package hysteria2

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

func init() {
	dialer.FromLinkRegister("hysteria2", NewHysteria2)
	dialer.FromLinkRegister("hy2", NewHysteria2)
}

type Hysteria2 struct {
	Name      string
	User      string
	Password  string
	Server    string
	Port      int
	Insecure  bool
	Sni       string
	PinSHA256 string
	MaxTx     uint64
	MaxRx     uint64
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
		Password: s.Password,
		IsClient: true,
	}
	if header.SNI == "" {
		header.SNI = s.Server
	}
	if option.BandwidthMaxRx > 0 && option.BandwidthMaxTx > 0 {
		header.Feature1 = &client.BandwidthConfig{
			MaxRx: option.BandwidthMaxRx,
			MaxTx: option.BandwidthMaxTx,
		}
	}
	if s.PinSHA256 != "" {
		nHash := normalizeCertHash(s.PinSHA256)
		header.TlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certHashes := make([]string, 0, len(rawCerts))
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				certHashes = append(certHashes, hashHex)
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return fmt.Errorf("no matching certificate found, %s not in %v", nHash, certHashes)
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
	var insecure bool
	if insecureValue := q.Get("insecure"); insecureValue != "" {
		insecure, err = strconv.ParseBool(q.Get("insecure"))
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}
	var maxTx, maxRx uint64
	if q.Get("maxTx") != "" && q.Get("maxRx") != "" {
		maxTx, err = strconv.ParseUint(q.Get("maxTx"), 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
		maxRx, err = strconv.ParseUint(q.Get("maxRx"), 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}
	conf := &Hysteria2{
		Name:      t.Fragment,
		User:      t.User.Username(),
		Server:    t.Hostname(),
		Port:      port,
		Insecure:  insecure,
		Sni:       sni,
		PinSHA256: q.Get("pinSHA256"),
		MaxTx:     maxTx,
		MaxRx:     maxRx,
	}
	conf.Password, _ = t.User.Password()
	return conf, nil
}

func (s *Hysteria2) ExportToURL() string {
	t := url.URL{
		Scheme:   "hysteria2",
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		User:     url.User(s.User),
		Fragment: s.Name,
	}
	if s.Password != "" {
		t.User = url.UserPassword(s.User, s.Password)
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
	if s.MaxTx > 0 && s.MaxRx > 0 {
		q.Set("maxTx", strconv.FormatUint(s.MaxTx, 10))
		q.Set("maxRx", strconv.FormatUint(s.MaxRx, 10))
	}
	t.RawQuery = q.Encode()
	return t.String()
}
