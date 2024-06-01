package congestion

import (
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/congestion/bbr"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/congestion/brutal"
	"github.com/daeuniverse/quic-go"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
