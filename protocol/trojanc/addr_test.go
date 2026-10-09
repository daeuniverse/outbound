package trojanc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func domainWire(host string) []byte {
	wire := make([]byte, 4+len(host))
	wire[0], wire[1] = 3, byte(len(host))
	copy(wire[2:], host)
	binary.BigEndian.PutUint16(wire[2+len(host):], 0xabcd)
	return wire
}

func TestMetadataUnpackDomain(t *testing.T) {
	for _, length := range []int{0, 1, 252, 253, 254, 255} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			host := strings.Repeat("a", length)
			wire := domainWire(host)
			reader := bytes.NewReader(append(wire, 0xee))
			var m Metadata
			n, err := m.Unpack(reader)
			if err != nil || n != len(wire) || m.Type != protocol.MetadataTypeDomain || m.Hostname != host || m.Port != 0xabcd || reader.Len() != 1 {
				t.Fatalf("Unpack: n=%d metadata=%+v remaining=%d err=%v", n, m, reader.Len(), err)
			}
			for _, cut := range []int{0, 1, 2, len(wire) - 1} {
				t.Run(fmt.Sprintf("truncated_%d", cut), func(t *testing.T) {
					var m Metadata
					n, err := m.Unpack(bytes.NewReader(wire[:cut]))
					want := io.ErrUnexpectedEOF
					if cut == 0 || cut == 2 {
						want = io.EOF
					}
					if n != 0 || !errors.Is(err, want) {
						t.Fatalf("Unpack truncated: n=%d err=%v, want %v", n, err, want)
					}
				})
			}
		})
	}
}

func TestMetadataPackToRoundTrip(t *testing.T) {
	for _, length := range []int{0, 1, 252, 253, 254, 255, 256, 257, 512} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			m := Metadata{Metadata: protocol.Metadata{
				Type: protocol.MetadataTypeDomain, Hostname: strings.Repeat("b", length), Port: 0xabcd,
			}}
			wantHost := m.Hostname[:min(length, 255)]
			wire := make([]byte, m.Len())
			n := m.PackTo(wire)
			if n != len(wire) || !bytes.Equal(wire, domainWire(wantHost)) {
				t.Fatalf("PackTo: n=%d wire=%x", n, wire)
			}
			var decoded Metadata
			n, err := decoded.Unpack(bytes.NewReader(wire))
			if err != nil || n != len(wire) || decoded.Type != m.Type || decoded.Hostname != wantHost || decoded.Port != m.Port {
				t.Fatalf("round trip: n=%d metadata=%+v err=%v", n, decoded, err)
			}
		})
	}
}
