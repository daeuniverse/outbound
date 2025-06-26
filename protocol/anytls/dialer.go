package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
	tlsConfig    *tls.Config

	sessionLock sync.Mutex
	session     *session
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
	}, nil
}

func (d *Dialer) DialTcp(ctx context.Context, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *Dialer) DialUdp(ctx context.Context, addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()

		s, err := d.getSession(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		streamAddr := fmt.Sprintf("%s:%d", mdata.Hostname, mdata.Port)
		return s.newStream(streamAddr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) getSession(ctx context.Context, tcpNetwork string) (*session, error) {
	d.sessionLock.Lock()
	defer d.sessionLock.Unlock()

	if d.session != nil && !d.session.Closed() {
		return d.session, nil
	}

	rawConn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn := rawConn.(net.Conn)

	tlsConn := tls.Client(conn, d.tlsConfig)

	buf := pool.Get(len(d.key) + 2)
	defer pool.Put(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	s := newSession(tlsConn)
	d.session = s
	go d.session.run()

	return d.session, nil
}
