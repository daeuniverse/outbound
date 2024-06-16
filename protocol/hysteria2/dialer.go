package hysteria2

import (
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

func init() {
	protocol.Register("hysteria2", NewDialer)
}

type Dialer struct {
	client   client.Client
	metadata protocol.Metadata
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	serverAddr, err := net.ResolveUDPAddr("udp", header.ProxyAddress)
	if err != nil {
		return nil, err
	}

	config := &client.Config{
		ServerAddr: serverAddr,
		TLSConfig: client.TLSConfig{
			ServerName:            header.TlsConfig.ServerName,
			InsecureSkipVerify:    header.TlsConfig.InsecureSkipVerify,
			VerifyPeerCertificate: header.TlsConfig.VerifyPeerCertificate,
			RootCAs:               header.TlsConfig.RootCAs,
		},
		Auth: header.User,
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}

	client, err := client.NewReconnectableClient(
		func() (*client.Config, error) {
			return config, nil
		},
		func(c client.Client, hi *client.HandshakeInfo, i int) {
			// Do nothing
		},
		true,
	)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		client:   client,
		metadata: metadata,
	}, nil
}

func (d *Dialer) Dial(network, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		return d.client.TCP(address)
	case "udp":
		return d.client.UDP(address)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}
