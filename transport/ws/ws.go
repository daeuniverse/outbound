package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/gorilla/websocket"
)

// Ws is a base Ws struct
type Ws struct {
	dialer          netproxy.Dialer
	wsAddr          string
	header          http.Header
	tlsClientConfig *tls.Config
	passthroughUdp  bool
}

// NewWs returns a Ws infra.
func NewWs(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewWs: %w", err)
	}

	t := &Ws{
		dialer: nextDialer,
	}

	query := u.Query()
	host := query.Get("host")
	if host == "" {
		host = u.Hostname()
	}
	t.header = http.Header{}
	t.header.Set("Host", host)

	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	wsUrl := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
	}
	t.wsAddr = wsUrl.String() + u.Path
	if u.Scheme == "wss" {
		allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
		}
		// TODO: utls
		t.tlsClientConfig = &tls.Config{
			ServerName:         query.Get("sni"),
			InsecureSkipVerify: allowInsecure || option.AllowInsecure,
		}
		if len(query.Get("alpn")) > 0 {
			t.tlsClientConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
		}
	}
	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  wsUrl.Host,
		Protocol: u.Scheme,
		Link:     link,
	}, nil
}

func (s *Ws) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		wsDialer := &websocket.Dialer{
			NetDial: func(_, addr string) (net.Conn, error) {
				c, err := s.dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  c,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: s.tlsClientConfig,
		}
		rc, _, err := wsDialer.DialContext(ctx, s.wsAddr, s.header)
		if err != nil {
			return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
		}
		return newConn(rc), err
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
