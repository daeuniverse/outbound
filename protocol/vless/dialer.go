package trojanc

import (
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("vless.NewDialer: metadata: %v, password: %v", metadata, password)
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          id,
	}, nil
}

func (d *Dialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	return d.Dial("tcp", addr)
}

func (d *Dialer) DialUdp(addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) Dial(network string, addr string) (c netproxy.Conn, err error) {
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

		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		conn, err := d.nextDialer.Dial(tcpNetwork, d.proxyAddress)
		if err != nil {
			return nil, err
		}

		return NewConn(conn, vmess.Metadata{
			Metadata: mdata,
			Network:  magicNetwork.Network,
		}, d.key)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
