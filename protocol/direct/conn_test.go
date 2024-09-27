package direct

import (
	"context"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/juicity"
	"github.com/daeuniverse/quic-go"
	"github.com/stretchr/testify/require"
)

func TestFakeNetPacketConn(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		c, err := SymmetricDirect.DialContext(context.TODO(), "udp", "223.5.5.5:53")
		require.NoError(t, err)
		fc := netproxy.NewFakeNetPacketConn(c.(netproxy.PacketConn), nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.True(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
	t.Run("negative", func(t *testing.T) {
		c := (interface{})(&juicity.PacketConn{})
		fc := netproxy.NewFakeNetPacketConn(c.(netproxy.PacketConn), nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.False(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
}
