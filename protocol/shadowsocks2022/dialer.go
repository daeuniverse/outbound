package shadowsocks2022

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("shadowsocks2022", NewDialer)
}

// Dialer implements netproxy.Dialer for SS2022
type Dialer struct {
	nextDialer   netproxy.Dialer
	proxyAddress string
	cipher       string
	config       *CipherConfig
	psk          []byte // user PSK (or only PSK in single-user mode)
	iPSK         []byte // identity PSK (nil in single-user mode)
}

// NewDialer creates a new SS2022 dialer
func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	config, err := GetCipherConfig(header.Cipher)
	if err != nil {
		return nil, err
	}

	// Parse PSK from password
	// Password format: base64(psk) or base64(ipsk):base64(upsk) for multi-user
	psk, iPSK, err := parsePSKFromPassword(header.Password, config.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PSK: %w", err)
	}

	// ChaCha20-Poly1305 does not support EIH (multi-user mode)
	if iPSK != nil && header.Cipher == "2022-blake3-chacha20-poly1305" {
		return nil, fmt.Errorf("chacha20-poly1305 does not support EIH (multi-user mode)")
	}

	return &Dialer{
		nextDialer:   nextDialer,
		proxyAddress: header.ProxyAddress,
		cipher:       header.Cipher,
		config:       config,
		psk:          psk,
		iPSK:         iPSK,
	}, nil
}

// parsePSKFromPassword parses PSK(s) from the password field
// Returns (psk, nil, nil) for single-user mode
// Returns (uPSK, iPSK, nil) for multi-user mode
func parsePSKFromPassword(password string, keyLen int) (psk, iPSK []byte, err error) {
	parts := strings.Split(password, ":")
	switch len(parts) {
	case 1:
		// Single PSK: base64(psk)
		psk, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid PSK encoding: %w", err)
		}
		if len(psk) != keyLen {
			return nil, nil, fmt.Errorf("PSK length mismatch: expected %d, got %d", keyLen, len(psk))
		}
		return psk, nil, nil
	case 2:
		// Multi-user: base64(ipsk):base64(upsk)
		iPSK, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid iPSK encoding: %w", err)
		}
		if len(iPSK) != keyLen {
			return nil, nil, fmt.Errorf("iPSK length mismatch: expected %d, got %d", keyLen, len(iPSK))
		}
		psk, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid uPSK encoding: %w", err)
		}
		if len(psk) != keyLen {
			return nil, nil, fmt.Errorf("uPSK length mismatch: expected %d, got %d", keyLen, len(psk))
		}
		return psk, iPSK, nil
	default:
		return nil, nil, fmt.Errorf("invalid password format: expected 1 or 2 parts, got %d", len(parts))
	}
}

// Dial creates a new TCP connection
func (d *Dialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext creates a new connection with context
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	metadata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	metadata.Cipher = d.cipher
	metadata.IsClient = true

	switch network {
	case "tcp":
		return d.dialTCP(ctx, metadata)
	case "udp":
		return d.dialUDP(ctx, metadata)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

// dialTCP creates a TCP connection
func (d *Dialer) dialTCP(ctx context.Context, metadata protocol.Metadata) (netproxy.Conn, error) {
	conn, err := d.nextDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy: %w", err)
	}

	tcpConn, err := NewTCPConn(conn, metadata, d.psk, d.iPSK, d.config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return tcpConn, nil
}

// dialUDP creates a UDP connection
func (d *Dialer) dialUDP(ctx context.Context, metadata protocol.Metadata) (netproxy.Conn, error) {
	conn, err := d.nextDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy: %w", err)
	}

	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("connection is not a PacketConn")
	}

	udpConn, err := NewUDPConn(packetConn, d.proxyAddress, metadata, d.psk, d.iPSK, d.config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return udpConn, nil
}
