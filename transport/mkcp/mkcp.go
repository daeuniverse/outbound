// Package mkcp provides mKCP transport implementation for outbound connections.
// mKCP is a KCP (A Fast and Reliable ARQ Protocol) based transport.
//
// Usage:
//
//	dialer, _, err := mkcp.NewMkcp(option, nextDialer, "mkcp://host:port?mtu=1350&tti=50")
//	conn, err := dialer.DialContext(ctx, "udp", "target:port")
package mkcp

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"sync/atomic"

	"github.com/daeuniverse/outbound/common/buf"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

var globalConv = uint32(0)

func rollConv() uint16 {
	return uint16(atomic.AddUint32(&globalConv, 1))
}

// Mkcp is a mKCP dialer.
type Mkcp struct {
	dialer netproxy.Dialer
	addr   string
	config *Config
}

// NewMkcp creates a new mKCP dialer from the given link.
// Link format: mkcp://host:port?mtu=1350&tti=50&uplink=5&downlink=20&congestion=false&seed=xxx
func NewMkcp(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewMkcp: %w", err)
	}

	config := DefaultConfig()

	query := u.Query()

	// Parse MTU
	if mtuStr := query.Get("mtu"); mtuStr != "" {
		mtu, err := strconv.ParseUint(mtuStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid mtu: %w", err)
		}
		config.MTU = uint32(mtu)
	}

	// Parse TTI
	if ttiStr := query.Get("tti"); ttiStr != "" {
		tti, err := strconv.ParseUint(ttiStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid tti: %w", err)
		}
		config.TTI = uint32(tti)
	}

	// Parse Uplink Capacity
	if uplinkStr := query.Get("uplink"); uplinkStr != "" {
		uplink, err := strconv.ParseUint(uplinkStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid uplink: %w", err)
		}
		config.UplinkCapacity = uint32(uplink)
	}
	if uplinkStr := query.Get("uplinkCapacity"); uplinkStr != "" {
		uplink, err := strconv.ParseUint(uplinkStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid uplinkCapacity: %w", err)
		}
		config.UplinkCapacity = uint32(uplink)
	}

	// Parse Downlink Capacity
	if downlinkStr := query.Get("downlink"); downlinkStr != "" {
		downlink, err := strconv.ParseUint(downlinkStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid downlink: %w", err)
		}
		config.DownlinkCapacity = uint32(downlink)
	}
	if downlinkStr := query.Get("downlinkCapacity"); downlinkStr != "" {
		downlink, err := strconv.ParseUint(downlinkStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid downlinkCapacity: %w", err)
		}
		config.DownlinkCapacity = uint32(downlink)
	}

	// Parse Write Buffer Size
	if writeBufferStr := query.Get("writeBuffer"); writeBufferStr != "" {
		writeBuffer, err := strconv.ParseUint(writeBufferStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid writeBuffer: %w", err)
		}
		config.WriteBufferSize = uint32(writeBuffer)
	}

	// Parse Read Buffer Size
	if readBufferStr := query.Get("readBuffer"); readBufferStr != "" {
		readBuffer, err := strconv.ParseUint(readBufferStr, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid readBuffer: %w", err)
		}
		config.ReadBufferSize = uint32(readBuffer)
	}

	// Parse Congestion
	if congestionStr := query.Get("congestion"); congestionStr != "" {
		congestion, err := strconv.ParseBool(congestionStr)
		if err != nil {
			return nil, nil, fmt.Errorf("NewMkcp: invalid congestion: %w", err)
		}
		config.Congestion = congestion
	}

	// Parse Seed
	config.Seed = query.Get("seed")

	m := &Mkcp{
		dialer: nextDialer,
		addr:   u.Host,
		config: config,
	}

	return m, &dialer.Property{
		Name:     u.Fragment,
		Address:  u.Host,
		Protocol: "mkcp",
		Link:     link,
	}, nil
}

// DialContext establishes a mKCP connection.
func (m *Mkcp) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp", "udp":
		return m.dialKCP(ctx, network, addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (m *Mkcp) dialKCP(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	// mKCP uses UDP as the underlying transport
	udpNetwork := netproxy.MagicNetwork{
		Network: "udp",
	}.Encode()

	targetAddr := m.addr
	if targetAddr == "" {
		targetAddr = addr
	}

	rawConn, err := m.dialer.DialContext(ctx, udpNetwork, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("mkcp: failed to dial UDP to %s: %w", targetAddr, err)
	}

	security, err := m.config.GetSecurity()
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("mkcp: failed to create security: %w", err)
	}

	reader := &KCPPacketReader{
		Security: security,
	}

	writer := &KCPPacketWriter{
		Security: security,
		Writer:   &connWriter{rawConn},
	}

	conv := rollConv()

	// Get local and remote addresses if available
	localAddr := &FakeAddr{Addr: "0.0.0.0:0"}
	remoteAddr := &FakeAddr{Addr: targetAddr}

	session := NewConnection(ConnMetadata{
		LocalAddr:    localAddr,
		RemoteAddr:   remoteAddr,
		Conversation: conv,
	}, writer, &connCloser{rawConn}, m.config)

	go fetchInput(ctx, rawConn, reader, session)

	return &kcpConn{session}, nil
}

// connWriter wraps a netproxy.Conn for io.Writer interface.
type connWriter struct {
	conn netproxy.Conn
}

func (w *connWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

// connCloser wraps a netproxy.Conn for io.Closer interface.
type connCloser struct {
	conn netproxy.Conn
}

func (c *connCloser) Close() error {
	return c.conn.Close()
}

// kcpConn wraps a KCP Connection as netproxy.Conn.
type kcpConn struct {
	*Connection
}

// fetchInput reads incoming packets and feeds them to the connection.
func fetchInput(ctx context.Context, input netproxy.Conn, reader PacketReader, conn *Connection) {
	cache := make(chan *buf.Buffer, 1024)
	go func() {
		for {
			payload := buf.New()
			_, err := payload.ReadFrom(input)
			if err != nil {
				payload.Release()
				close(cache)
				return
			}
			select {
			case cache <- payload:
			default:
				payload.Release()
			}
		}
	}()

	for payload := range cache {
		segments := reader.Read(payload.Bytes())
		payload.Release()
		if len(segments) > 0 {
			conn.Input(segments)
		}
	}
}

// FakeAddr implements net.Addr for fake addresses.
type FakeAddr struct {
	Addr string
}

func (a *FakeAddr) Network() string {
	return "udp"
}

func (a *FakeAddr) String() string {
	return a.Addr
}

// DialKCP dials a new KCP connection with custom configuration.
func DialKCP(ctx context.Context, nextDialer netproxy.Dialer, addr string, config *Config) (netproxy.Conn, error) {
	if config == nil {
		config = DefaultConfig()
	}

	m := &Mkcp{
		dialer: nextDialer,
		addr:   addr,
		config: config,
	}

	return m.DialContext(ctx, "udp", addr)
}

// Dial is a convenience function for dialing with default config.
func Dial(ctx context.Context, nextDialer netproxy.Dialer, addr string) (netproxy.Conn, error) {
	return DialKCP(ctx, nextDialer, addr, nil)
}

// Conn is an alias for the KCP Connection type.
type Conn = Connection

// Read implements io.Reader for Conn (for compatibility).
func (c *kcpConn) Read(b []byte) (int, error) {
	return c.Connection.Read(b)
}

// Write implements io.Writer for Conn (for compatibility).
func (c *kcpConn) Write(b []byte) (int, error) {
	return c.Connection.Write(b)
}

// Close implements io.Closer for Conn.
func (c *kcpConn) Close() error {
	return c.Connection.Close()
}

// Reader wraps a netproxy.Conn as an io.Reader.
type connReader struct {
	conn netproxy.Conn
}

func (r *connReader) Read(b []byte) (int, error) {
	return r.conn.Read(b)
}

var _ io.Reader = (*connReader)(nil)
var _ io.Writer = (*connWriter)(nil)
var _ io.Closer = (*connCloser)(nil)
