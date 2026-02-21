package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

const maxPSKListLength = 8

// FakeNetPacketConn wraps a PacketConn to work with specific address
type FakeNetPacketConn struct {
	netproxy.PacketConn
	Addr string
}

func (c *FakeNetPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.Addr)
}

func (c *FakeNetPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, _, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	udpAddr, _ := net.ResolveUDPAddr("udp", c.Addr)
	return n, udpAddr, nil
}

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	parentDialer       netproxy.Dialer
	proxyAddress       string
	conf               *ciphers.CipherConf2022
	pskList            [][]byte
	uPSK               []byte
	sg                 shadowsocks.SaltGenerator
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks 2022 cipher: %s", header.Cipher)
	}
	if conf.NewCipher == nil || conf.NewBlockCipher == nil {
		return nil, fmt.Errorf("invalid shadowsocks 2022 cipher config: %s", header.Cipher)
	}
	keyStrList := strings.Split(header.Password, ":")
	if len(keyStrList) > maxPSKListLength {
		return nil, fmt.Errorf("too many PSKs: got %d, max %d", len(keyStrList), maxPSKListLength)
	}
	pskList := make([][]byte, len(keyStrList))
	for i, keyStr := range keyStrList {
		key, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen)
		if err != nil {
			return nil, err
		}
		pskList[i] = key
	}
	uPSK := pskList[len(pskList)-1]
	blockCipherEncrypt, err := conf.NewBlockCipher(pskList[0]) // iPSK0/uPSK
	if err != nil {
		return nil, err
	}
	blockCipherDecrypt, err := conf.NewBlockCipher(uPSK) // uPSK
	if err != nil {
		return nil, err
	}
	sg, err := shadowsocks.NewRandomSaltGenerator(conf.SaltLen)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		parentDialer:       parentDialer,
		proxyAddress:       header.ProxyAddress,
		conf:               conf,
		pskList:            pskList,
		uPSK:               uPSK,
		sg:                 sg,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	switch network {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewTCPConn(conn.(net.Conn), d.conf, d.pskList, d.uPSK, d.sg, addrInfo, nil), nil
	case "udp":
		conn, err := d.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &FakeNetPacketConn{
			PacketConn: conn,
			Addr:       addr,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (netproxy.PacketConn, error) {
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.parentDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn.(net.Conn), d.conf, d.blockCipherEncrypt, d.blockCipherDecrypt, d.pskList, d.uPSK, nil)
}
