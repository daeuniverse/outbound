package netproxy

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"unicode"

	"github.com/daeuniverse/outbound/common"
)

const MagicNetworkType = 0

var (
	UnknownMagicNetworkEncodingError = fmt.Errorf("unknown magic network encoding")
)

type MagicNetwork struct {
	Network string
	Mark    uint32
	Mptcp   bool
}

func (mn MagicNetwork) Encode() string {
	if len([]byte(mn.Network)) > 255 {
		panic("network too long")
	}
	b := make([]byte, 2+len(mn.Network)+4+1)
	b[0] = MagicNetworkType
	b[1] = byte(len([]byte(mn.Network)))
	copy(b[2:], mn.Network)
	binary.BigEndian.PutUint32(b[2+len([]byte(mn.Network)):], uint32(mn.Mark))
	if mn.Mptcp {
		b[2+len([]byte(mn.Network))+4] = 1
	}
	return string(b)
}

func ParseMagicNetwork(network string) (mn *MagicNetwork, err error) {
	if len(network) == 0 {
		return &MagicNetwork{}, nil
	}
	if unicode.IsPrint([]rune(network)[0]) {
		return &MagicNetwork{
			Network: network,
			Mark:    0,
			Mptcp:   false,
		}, nil
	}
	b := []byte(network)
	if len(b) < 2 || b[0] != MagicNetworkType {
		return nil, UnknownMagicNetworkEncodingError
	}
	// flag(1B) network len (1B) network (variable length) mark(4B) mptcp(1B)
	networkLen := b[1]
	if len(b) < 2+int(networkLen)+4+1 {
		return nil, UnknownMagicNetworkEncodingError
	}
	network = network[2 : 2+int(networkLen)]
	mark := binary.BigEndian.Uint32(b[2+int(networkLen):])
	if bits.Len32(mark) >= common.IntSize {
		return nil, fmt.Errorf("mark is too big")
	}
	mptcp := b[2+int(networkLen)+4] == 1

	return &MagicNetwork{
		Network: network,
		Mark:    mark,
		Mptcp:   mptcp,
	}, nil
}
