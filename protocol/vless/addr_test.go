package vless

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func TestCompleteMetadataFromReaderDomain(t *testing.T) {
	for _, length := range []int{0, 1, 252, 253, 254, 255} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			host := strings.Repeat("a", length)
			wire := append([]byte{byte(length)}, host...)
			reader := bytes.NewReader(append(wire, 0xee))
			var m Metadata
			err := CompleteMetadataFromReader(&m, []byte{1, 0xab, 0xcd, 2}, reader)
			if err != nil || m.Type != protocol.MetadataTypeDomain || m.Hostname != host || m.Port != 0xabcd || m.Network != "tcp" || reader.Len() != 1 {
				t.Fatalf("decode: metadata=%+v remaining=%d err=%v", m, reader.Len(), err)
			}
			var truncated Metadata
			err = CompleteMetadataFromReader(&truncated, []byte{1, 0xab, 0xcd, 2}, bytes.NewReader(wire[:len(wire)-1]))
			want := io.ErrUnexpectedEOF
			if length <= 1 {
				want = io.EOF
			}
			if !errors.Is(err, want) {
				t.Fatalf("truncated: err=%v, want %v", err, want)
			}
		})
	}
}
