package juicity

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/netip"
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
)

var packetTestMetadata = trojanc.Metadata{Metadata: protocol.Metadata{
	Type: protocol.MetadataTypeIPv4, Hostname: "127.0.0.1", Port: 53,
}}

func packetTestFrame(payload []byte) []byte {
	return SealUDP(packetTestMetadata, make([]byte, packetTestMetadata.Len()+2+len(payload)), payload)
}

func packetTestReader(r io.Reader) *PacketConn {
	return &PacketConn{Conn: NewConn(&testStream{reader: r}, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: true},
	}, nil)}
}

func TestPacketConnTruncationKeepsAlignment(t *testing.T) {
	for _, size := range []int{0, 2} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			wire := append(packetTestFrame([]byte("large")), packetTestFrame([]byte("ok"))...)
			conn := packetTestReader(bytes.NewReader(wire))
			n, addr, err := conn.ReadFrom(make([]byte, size))
			if n != size || addr != netip.MustParseAddrPort("127.0.0.1:53") || err != nil {
				t.Fatalf("oversized frame: got (%d, %v, %v)", n, addr, err)
			}
			payload := make([]byte, 2)
			n, addr, err = conn.ReadFrom(payload)
			if n != 2 || string(payload) != "ok" || addr != netip.MustParseAddrPort("127.0.0.1:53") || err != nil {
				t.Fatalf("next frame: got (%d, %q, %v, %v)", n, payload, addr, err)
			}
		})
	}
}

type packetErrorReader struct{ err error }

func (r packetErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestPacketConnDiscardError(t *testing.T) {
	for _, want := range []error{io.EOF, errors.New("stream reset")} {
		t.Run(want.Error(), func(t *testing.T) {
			wire := packetTestFrame([]byte("large"))
			reader := io.MultiReader(bytes.NewReader(wire[:len(wire)-2]), packetErrorReader{want})
			n, _, err := packetTestReader(reader).ReadFrom(make([]byte, 2))
			if n != 2 || !errors.Is(err, want) {
				t.Fatalf("discard: got (%d, %v), want (2, %v)", n, err, want)
			}
		})
	}
}

func TestPacketConnWriteLengthLimit(t *testing.T) {
	var wire bytes.Buffer
	conn := &PacketConn{Conn: NewConn(&testStream{writer: &wire}, &trojanc.Metadata{}, nil)}
	payload := bytes.Repeat([]byte{'x'}, math.MaxUint16+1)
	if n, err := conn.WriteTo(payload, "127.0.0.1:53"); n != 0 || err == nil || wire.Len() != 0 {
		t.Fatalf("oversized write: got (%d, %v), wrote %d bytes", n, err, wire.Len())
	}
	payload = payload[:math.MaxUint16]
	if n, err := conn.WriteTo(payload, "127.0.0.1:53"); n != len(payload) || err != nil {
		t.Fatalf("maximum write: got (%d, %v)", n, err)
	}
	got := make([]byte, len(payload))
	n, addr, err := packetTestReader(&wire).ReadFrom(got)
	if n != len(payload) || !bytes.Equal(got, payload) || addr != netip.MustParseAddrPort("127.0.0.1:53") || err != nil {
		t.Fatalf("maximum round trip: got (%d, %v, %v), payload equal: %v", n, addr, err, bytes.Equal(got, payload))
	}
}
