package simpleobfs

import "github.com/daeuniverse/dae-outbound/dialer"

func init() {
	dialer.FromLinkRegister("simpleobfs", NewSimpleObfs)
}
