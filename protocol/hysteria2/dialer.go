package hysteria2

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

func init() {
	protocol.Register("hysteria2", NewDialer)
}

type Dialer struct {
	client   client.Client
	metadata protocol.Metadata
}

type Feature1 struct {
	BandwidthConfig client.BandwidthConfig
	UDPHopInterval  time.Duration
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	host, port, hostPort := parseServerAddrString(header.ProxyAddress)

	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	config := &client.Config{
		TLSConfig: client.TLSConfig{
			ServerName:            header.TlsConfig.ServerName,
			InsecureSkipVerify:    header.TlsConfig.InsecureSkipVerify,
			VerifyPeerCertificate: header.TlsConfig.VerifyPeerCertificate,
			RootCAs:               header.TlsConfig.RootCAs,
		},
		Auth: header.User,
	}
	if header.SNI == "" {
		config.TLSConfig.ServerName = host
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}
	if feature := header.Feature1; feature != nil {
		config.BandwidthConfig = feature.(*Feature1).BandwidthConfig
		config.UDPHopInterval = feature.(*Feature1).UDPHopInterval
	}

	var err error
	if !isPortHoppingPort(port) {
		config.ServerAddr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		config.ServerAddr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return nil, err
	}

	if config.ServerAddr.Network() == "udphop" {
		config.ConnFactory = &client.UdpConnFactory{
			NewFunc: func(ctx context.Context) (net.PacketConn, error) {
				dialFunc := func(addr net.Addr) (net.PacketConn, error) {
					conn, err := nextDialer.DialContext(ctx, "udp", addr.String())
					if err != nil {
						return nil, err
					}
					return netproxy.NewFakeNetPacketConn(
						conn.(netproxy.PacketConn),
						net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
						addr,
					), nil
				}
				return udphop.NewUDPHopPacketConn(config.ServerAddr.(*udphop.UDPHopAddr), config.UDPHopInterval, dialFunc)
			},
		}
	} else {
		config.ConnFactory = &client.UdpConnFactory{
			NewFunc: func(ctx context.Context) (net.PacketConn, error) {
				conn, err := nextDialer.DialContext(ctx, "udp", config.ServerAddr.String())
				if err != nil {
					return nil, err
				}
				return netproxy.NewFakeNetPacketConn(
					conn.(netproxy.PacketConn),
					net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
					config.ServerAddr,
				), nil
			},
		}
	}

	client, err := client.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		client:   client,
		metadata: metadata,
	}, nil
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		return d.client.TCP(address, ctx)
	case "udp":
		return d.client.UDP(address, ctx)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}
