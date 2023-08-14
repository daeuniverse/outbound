package tls

import "github.com/daeuniverse/dae-outbound/dialer"

func init() {
	dialer.FromLinkRegister("tls", NewTls)
	dialer.FromLinkRegister("utls", NewTls)
}
