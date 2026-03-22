/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stickyip provides sticky IP caching for proxy server connections.
// Within a health check cycle, the same resolved IP is reused to ensure
// connection stability when a proxy domain resolves to multiple IPs.
package stickyip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	// CacheTTL is how long to cache a successful proxy IP.
	// This should be at least the health check interval to ensure
	// all connections in a cycle use the same IP.
	CacheTTL = 5 * time.Minute
)

// ProxyIpCache manages sticky IP resolution for proxy server domains.
// It separately caches IPs that work for TCP and UDP since some proxies
// may have different availability per protocol.
type ProxyIpCache struct {
	sync.RWMutex
	cache map[string]*proxyIpEntry
}

type proxyIpEntry struct {
	// tcp4Addr is the IPv4:port that works for TCP connections.
	tcp4Addr string
	// tcp6Addr is the IPv6:port that works for TCP connections.
	tcp6Addr string
	// udp4Addr is the IPv4:port that works for UDP connections.
	udp4Addr string
	// udp6Addr is the IPv6:port that works for UDP connections.
	udp6Addr string
	// expiresAt is when this cache entry expires.
	expiresAt time.Time
	// checkCycle is the health check cycle number this entry belongs to.
	checkCycle uint64
}

// cacheKey generates a cache key from network (tcp/udp) and IP version (4/6).
func cacheKey(network, ipVersion string) string {
	return network + ipVersion
}

// NewProxyIpCache creates a new proxy IP cache.
func NewProxyIpCache() *ProxyIpCache {
	return &ProxyIpCache{
		cache: make(map[string]*proxyIpEntry),
	}
}

// Set stores a successful proxy IP address for a specific protocol and IP version with cycle tracking.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
// This ensures we only cache IPs that actually work for the specific protocol and address family.
func (c *ProxyIpCache) Set(originalAddr, actualAddr string, network string, ipVersion string, cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	now := time.Now()

	// Get or create entry
	entry, exists := c.cache[originalAddr]
	if !exists {
		entry = &proxyIpEntry{
			expiresAt:  now.Add(CacheTTL),
			checkCycle: cycle,
		}
		c.cache[originalAddr] = entry
	}

	// Update the appropriate address based on network type and IP version
	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		entry.tcp4Addr = actualAddr
	case "tcp6":
		entry.tcp6Addr = actualAddr
	case "udp4":
		entry.udp4Addr = actualAddr
	case "udp6":
		entry.udp6Addr = actualAddr
	}

	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"original_addr": originalAddr,
			"actual_addr":   actualAddr,
			"network":       network,
			"ip_version":    ipVersion,
			"cycle":         cycle,
		}).Debug("[StickyIP] Cached proxy IP")
	}
}

// GetWithCycleAndIpVersion returns the cached IP for the specified network and IP version if it belongs to the current check cycle.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (c *ProxyIpCache) GetWithCycleAndIpVersion(proxyAddr string, network string, ipVersion string, currentCycle uint64) string {
	if c == nil {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] Cache is nil")
		return proxyAddr
	}
	c.RLock()
	defer c.RUnlock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] No cache entry found")
		return proxyAddr
	}
	if time.Now().After(entry.expiresAt) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"expired_at": entry.expiresAt,
		}).Debug("[StickyIP] Cache entry expired")
		return proxyAddr
	}
	// Only use cached IP if it's from the current cycle
	if entry.checkCycle != currentCycle {
		logger.WithFields(logrus.Fields{
			"proxy_addr":    proxyAddr,
			"entry_cycle":   entry.checkCycle,
			"current_cycle": currentCycle,
		}).Debug("[StickyIP] Cycle mismatch - cache not from current cycle")
		return proxyAddr
	}

	// Return the protocol and IP version specific cached address
	var cachedAddr string
	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		cachedAddr = entry.tcp4Addr
	case "tcp6":
		cachedAddr = entry.tcp6Addr
	case "udp4":
		cachedAddr = entry.udp4Addr
	case "udp6":
		cachedAddr = entry.udp6Addr
	}

	if cachedAddr == "" {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] No cached IP for this network type and IP version")
		return proxyAddr
	}

	logger.WithFields(logrus.Fields{
		"proxy_addr":  proxyAddr,
		"cached_addr": cachedAddr,
		"network":     network,
		"ip_version":  ipVersion,
	}).Debug("[StickyIP] Cache hit - returning cached IP")
	return cachedAddr
}

// GetWithCycle returns the cached IP for the specified network (backward compatibility).
// Deprecated: Use GetWithCycleAndIpVersion for proper IP version separation.
func (c *ProxyIpCache) GetWithCycle(proxyAddr string, network string, currentCycle uint64) string {
	// Try IPv4 first, then IPv6 for backward compatibility
	if addr := c.GetWithCycleAndIpVersion(proxyAddr, network, "4", currentCycle); addr != proxyAddr {
		return addr
	}
	return c.GetWithCycleAndIpVersion(proxyAddr, network, "6", currentCycle)
}

// Invalidate removes all cached entries for a proxy address.
func (c *ProxyIpCache) Invalidate(proxyAddr string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.cache, proxyAddr)
}

// InvalidateProtocolAndIpVersion removes the cached entry for a specific protocol and IP version.
// This allows fine-grained invalidation when a specific protocol + address family combination fails.
func (c *ProxyIpCache) InvalidateProtocolAndIpVersion(proxyAddr, network, ipVersion string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	entry, exists := c.cache[proxyAddr]
	if !exists {
		return
	}

	key := cacheKey(network, ipVersion)
	switch key {
	case "tcp4":
		entry.tcp4Addr = ""
	case "tcp6":
		entry.tcp6Addr = ""
	case "udp4":
		entry.udp4Addr = ""
	case "udp6":
		entry.udp6Addr = ""
	}

	// If all addresses are empty now, remove the entry entirely
	if entry.tcp4Addr == "" && entry.tcp6Addr == "" && entry.udp4Addr == "" && entry.udp6Addr == "" {
		delete(c.cache, proxyAddr)
	} else {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Invalidated cache for protocol+IP version")
	}
}

// InvalidateProtocol removes the cached entries for a specific protocol (both IPv4 and IPv6).
// This is kept for backward compatibility but invalidates both IP versions.
func (c *ProxyIpCache) InvalidateProtocol(proxyAddr, network string) {
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "4")
	c.InvalidateProtocolAndIpVersion(proxyAddr, network, "6")
}

// InvalidateCycle removes all cache entries for a specific cycle.
func (c *ProxyIpCache) InvalidateCycle(cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	for addr, entry := range c.cache {
		if entry.checkCycle == cycle {
			delete(c.cache, addr)
		}
	}
}

// StickyIpDialer wraps a dialer to provide sticky IP caching for proxy servers.
type StickyIpDialer struct {
	dialer     netproxy.Dialer
	cache      *ProxyIpCache
	checkCycle uint64
	proxyAddr  string // Original proxy address (domain:port or IP:port)
	proxyHost  string
}

// NewStickyIpDialer creates a new sticky IP dialer wrapper.
func NewStickyIpDialer(dialer netproxy.Dialer, proxyAddr string, cache *ProxyIpCache) *StickyIpDialer {
	if cache == nil {
		cache = NewProxyIpCache()
	}
	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] NewStickyIpDialer created")
	}
	return &StickyIpDialer{
		dialer:     dialer,
		cache:      cache,
		checkCycle: 0,
		proxyAddr:  proxyAddr,
		proxyHost:  proxyHost,
	}
}

// IncrementCheckCycle advances the health check cycle.
func (d *StickyIpDialer) IncrementCheckCycle() {
	oldCycle := d.checkCycle
	d.checkCycle++
	logger.WithFields(logrus.Fields{
		"old_cycle":  oldCycle,
		"new_cycle":  d.checkCycle,
		"proxy_addr": d.proxyAddr,
	}).Debug("[StickyIP] Check cycle incremented")
	// Invalidate old cycle entries to force refresh
	d.cache.InvalidateCycle(d.checkCycle - 1)
}

// InvalidateProtocolCache invalidates the cached IP for a specific protocol.
// This is called when a connection fails (e.g., connection refused) to allow
// immediate retry with a different IP.
func (d *StickyIpDialer) InvalidateProtocolCache(proxyAddr, protocol string) {
	d.cache.InvalidateProtocol(proxyAddr, protocol)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
		}).Debug("[StickyIP] Protocol cache invalidated due to connection failure")
	}
}

// InvalidateProtocolAndIpVersionCache invalidates the cached IP for a specific protocol and IP version.
// This provides fine-grained cache invalidation when a specific combination fails.
func (d *StickyIpDialer) InvalidateProtocolAndIpVersionCache(proxyAddr, protocol, ipVersion string) {
	d.cache.InvalidateProtocolAndIpVersion(proxyAddr, protocol, ipVersion)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
			"ip_version": ipVersion,
		}).Debug("[StickyIP] Protocol+IP version cache invalidated due to connection failure")
	}
}

// GetCachedProxyAddr returns the cached IP for the proxy address and network type.
// network should be "tcp" or "udp".
func (d *StickyIpDialer) GetCachedProxyAddr(network string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycle(d.proxyAddr, network, d.checkCycle)
}

// GetCachedProxyAddrWithIpVersion returns the cached IP for the proxy address, network type and IP version.
// network should be "tcp" or "udp", ipVersion should be "4" or "6".
func (d *StickyIpDialer) GetCachedProxyAddrWithIpVersion(network, ipVersion string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycleAndIpVersion(d.proxyAddr, network, ipVersion, d.checkCycle)
}

// DialContext implements sticky IP caching by intercepting dial calls.
// It resolves all IPs for the target, tries the cached IP first, then falls back.
// For UDP, it verifies UDP connectivity before caching an IP.
func (d *StickyIpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	// Extract the base network type (tcp/udp) from magic network if present
	baseNetwork := d.getBaseNetwork(network)

	// Log every dial attempt for debugging
	logger.WithFields(logrus.Fields{
		"proxy_addr":   d.proxyAddr,
		"target":       addr,
		"network":      network,
		"base_network": baseNetwork,
		"is_proxy":     d.isProxyAddress(addr),
	}).Debug("[StickyIP] DialContext called")

	// Check if we should use a cached proxy IP for this connection
	if d.isProxyAddress(addr) {
		cachedAddr := d.GetCachedProxyAddr(baseNetwork)
		// Only use cached IP if it's different from proxy address (i.e., it's a resolved IP)
		// GetCachedProxyAddr returns proxyAddr when cache is empty/expired, so we need to check
		if cachedAddr != "" && cachedAddr != d.proxyAddr {
			// Try with cached IP first
			conn, err := d.dialer.DialContext(ctx, network, cachedAddr)
			if err == nil {
				// For UDP, verify the connection actually works by trying to read
				if baseNetwork == "udp" {
					if !d.verifyUDPConnectivity(ctx, conn.(netproxy.PacketConn)) {
						conn.Close()
						logCacheFailure(d.proxyAddr, cachedAddr, network, fmt.Errorf("UDP verification failed"))
						d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
						// Fall through to resolve and try other IPs
					} else {
						// UDP verification succeeded
						logCacheHit(d.proxyAddr, cachedAddr, network)
						return conn, nil
					}
				} else {
					// TCP - connection success is enough
					logCacheHit(d.proxyAddr, cachedAddr, network)
					return conn, nil
				}
			} else {
				// Log cache miss/failure
				logCacheFailure(d.proxyAddr, cachedAddr, network, err)
				// Cached IP failed, invalidate this protocol's cache
				d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
			}
		}
		// No cached IP, or cached IP failed - resolve and try all IPs
		logger.WithFields(logrus.Fields{
			"proxy_addr":  d.proxyAddr,
			"target":      addr,
			"network":     network,
			"cached_addr": cachedAddr,
		}).Debug("[StickyIP] No valid cached IP - resolving proxy domain")
		return d.dialWithIpResolution(ctx, network, addr, baseNetwork)
	}

	// Not the proxy address, just pass through
	logger.WithFields(logrus.Fields{
		"proxy_addr": d.proxyAddr,
		"target":     addr,
		"network":    network,
	}).Trace("[StickyIP] Pass-through (not proxy address)")
	return d.dialer.DialContext(ctx, network, addr)
}

// getBaseNetwork extracts the base network type (tcp/udp) from magic network.
func (d *StickyIpDialer) getBaseNetwork(network string) string {
	// Parse magic network to get base type
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		// Default to treating as-is
		return network
	}
	return magicNetwork.Network
}

// verifyUDPConnectivity checks if a UDP connection is actually working.
// For UDP, we do a basic sanity check by trying to read with a short deadline.
// Note: UDP connectivity can only be truly verified by sending/receiving actual data,
// so this is a best-effort check. The real validation happens during protocol handshake.
func (d *StickyIpDialer) verifyUDPConnectivity(ctx context.Context, conn netproxy.PacketConn) bool {
	// Set a very short read deadline
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	// Try to read - this will tell us if the socket is properly bound
	var buf [1]byte
	_, _, err := conn.ReadFrom(buf[:])

	if err != nil {
		// A timeout is expected and means the socket is working (just no data yet)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		// Check for immediate connection refused
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Err.Error() == "connection refused" {
				logger.WithField("error", err).Debug("[StickyIP] UDP connection refused detected")
				return false
			}
		}
		// Other errors at this stage are inconclusive for UDP
		// The socket might be fine, just no data available
		logger.WithField("error", err).Trace("[StickyIP] UDP verification read error (inconclusive)")
	}

	// If we got here without a definitive failure, consider the socket potentially working
	return true
}

// isProxyAddress checks if the given address matches the proxy address.
func (d *StickyIpDialer) isProxyAddress(addr string) bool {
	// Exact match
	if addr == d.proxyAddr {
		return true
	}
	// Check if host part matches
	addrHost, _, err := net.SplitHostPort(addr)
	if err == nil && d.proxyHost != "" {
		return d.proxyHost == addrHost
	}
	return false
}

// dialWithIpResolution resolves the address to IPs and tries each one.
// The first successful IP is cached for subsequent connections.
func (d *StickyIpDialer) dialWithIpResolution(ctx context.Context, network, addr, baseNetwork string) (netproxy.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not in host:port format, try directly
		logResolutionError(d.proxyAddr, "invalid address format", err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// If already an IP address, dial directly
	if ip := net.ParseIP(host); ip != nil {
		logDirectDial(d.proxyAddr, addr, network)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Resolve to get all IPs
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		// Resolution failed, try original address
		logResolutionError(d.proxyAddr, host, err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Log all resolved IPs
	logResolvedIPs(d.proxyAddr, ips, port, network)

	// Extract base network type for protocol-specific caching
	isUDP := baseNetwork == "udp"

	// Try each IP until one works
	var lastErr error
	for _, ipAddr := range ips {
		if ipAddr.IP == nil {
			continue
		}
		ipAddrStr := ipAddr.IP.String()
		targetAddr := net.JoinHostPort(ipAddrStr, port)

		logTryingIP(d.proxyAddr, targetAddr, network)
		conn, err := d.dialer.DialContext(ctx, network, targetAddr)
		if err == nil {
			// For UDP, verify the connection actually works
			if isUDP {
				packetConn, ok := conn.(netproxy.PacketConn)
				if !ok {
					conn.Close()
					lastErr = fmt.Errorf("not a packet connection")
					logIPFailure(d.proxyAddr, targetAddr, lastErr)
					continue
				}
				if !d.verifyUDPConnectivity(ctx, packetConn) {
					conn.Close()
					lastErr = fmt.Errorf("UDP connection verification failed")
					logIPFailure(d.proxyAddr, targetAddr, lastErr)
					continue
				}
			}

			// This IP works for this protocol, cache it
			// Determine IP version from the successful IP
			ipVersion := "4"
			if ipAddr.IP.To4() == nil {
				ipVersion = "6"
			}
			d.cache.Set(d.proxyAddr, targetAddr, baseNetwork, ipVersion, d.checkCycle)
			logIPSuccess(d.proxyAddr, targetAddr, baseNetwork, ipVersion, d.checkCycle)
			return conn, nil
		}
		lastErr = err
		logIPFailure(d.proxyAddr, targetAddr, err)
	}

	// All IPs failed, return an error
	logAllIPsFailed(d.proxyAddr, lastErr)
	return nil, &net.OpError{Op: "dial", Err: lastErr}
}

// Logging functions for debugging sticky IP caching

var logger = logrus.StandardLogger()

func logCacheHit(proxyAddr, cachedAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
		}).Debug("[StickyIP] Cache hit - using cached proxy IP")
	}
}

func logCacheFailure(proxyAddr, cachedAddr, network string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
			"error":      err.Error(),
		}).Warn("[StickyIP] Cached IP failed - invalidating and re-resolving")
	}
}

func logResolutionError(proxyAddr, host string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"host":       host,
			"error":      err.Error(),
		}).Warn("[StickyIP] DNS resolution failed")
	}
}

func logDirectDial(proxyAddr, addr, network string) {
	if logger.IsLevelEnabled(logrus.TraceLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     addr,
			"network":    network,
		}).Trace("[StickyIP] Direct dial (already an IP)")
	}
}

func logResolvedIPs(proxyAddr string, ips []net.IPAddr, port, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		ipList := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP != nil {
				ipList = append(ipList, ip.IP.String())
			}
		}
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"ips":        ipList,
			"port":       port,
			"network":    network,
			"count":      len(ipList),
		}).Debug("[StickyIP] Resolved proxy domain to IPs")
	}
}

func logTryingIP(proxyAddr, targetAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"network":    network,
		}).Debug("[StickyIP] Trying proxy IP")
	}
}

func logIPSuccess(proxyAddr, targetAddr, network, ipVersion string, cycle uint64) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr":  proxyAddr,
			"selected_ip": targetAddr,
			"network":     network,
			"ip_version":  ipVersion,
			"cycle":       cycle,
		}).Debug("[StickyIP] Successfully connected to proxy IP")
	}
}

func logIPFailure(proxyAddr, targetAddr string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"error":      err.Error(),
		}).Warn("[StickyIP] Failed to connect to proxy IP")
	}
}

func logAllIPsFailed(proxyAddr string, lastErr error) {
	if logger.IsLevelEnabled(logrus.ErrorLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"error":      lastErr.Error(),
		}).Error("[StickyIP] All proxy IPs failed - connection refused")
	}
}
