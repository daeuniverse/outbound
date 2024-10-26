package dialer

import "fmt"

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type ExtraOption struct {
	AllowInsecure     bool
	TlsImplementation string
	UtlsImitate       string
	BandwidthMaxTx    string
	BandwidthMaxRx    string
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}
