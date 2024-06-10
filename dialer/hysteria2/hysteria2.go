package hysteria2

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("hysteria2", NewHysteria2)
	dialer.FromLinkRegister("hy2", NewHysteria2)
}

type Hysteria2 struct {
	Name      string
	User      string
	Server    string
	Port      int
	Insecure  bool
	Sni       string
	PinSHA256 string
}

func NewHysteria2(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseHysteria2URL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Hysteria2) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	proxyAddress := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	header := protocol.Header{
		ProxyAddress: proxyAddress,
		TlsConfig: &tls.Config{
			ServerName:         s.Sni,
			InsecureSkipVerify: s.Insecure || option.AllowInsecure,
		},
		SNI:      s.Sni,
		User:     s.User,
		IsClient: true,
	}
	if s.PinSHA256 != "" {
		nHash := normalizeCertHash(s.PinSHA256)
		header.TlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	var err error
	if d, err = protocol.NewDialer("hysteria2", d, header); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  proxyAddress,
		Protocol: "hysteria2",
		Link:     s.ExportToURL(),
	}, nil
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

// ref: https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func ParseHysteria2URL(link string) (*Hysteria2, error) {
	// TODO: support salamander obfuscation
	t, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	q := t.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = t.Hostname()
	}
	return &Hysteria2{
		Name:      t.Fragment,
		User:      t.User.String(),
		Server:    t.Hostname(),
		Port:      port,
		Insecure:  q.Get("insecure") == "1",
		Sni:       sni,
		PinSHA256: q.Get("pinSHA256"),
	}, nil
}

func (s *Hysteria2) ExportToURL() string {
	t := url.URL{
		Scheme:   "hysteria2",
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		User:     url.User(s.User),
		Fragment: s.Name,
	}
	q := t.Query()
	if s.Insecure {
		q.Set("insecure", "1")
	}
	if s.Sni != "" {
		q.Set("sni", s.Sni)
	}
	if s.PinSHA256 != "" {
		q.Set("pinSHA256", s.PinSHA256)
	}
	t.RawQuery = q.Encode()
	return t.String()
}
