package tuic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReadAddressDomain(t *testing.T) {
	for _, length := range []int{0, 1, 252, 253, 254, 255} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			host := strings.Repeat("a", length)
			wire := make([]byte, 4+length)
			wire[0], wire[1] = AtypDomainName, byte(length)
			copy(wire[2:], host)
			binary.BigEndian.PutUint16(wire[2+length:], 0xabcd)
			reader := bytes.NewReader(append(wire, 0xee))
			addr, err := ReadAddress(reader)
			if err != nil {
				t.Fatal(err)
			}
			if addr.TYPE != AtypDomainName || !bytes.Equal(addr.ADDR, wire[1:2+length]) || addr.PORT != 0xabcd || reader.Len() != 1 {
				t.Fatalf("decode: address=%+v remaining=%d", addr, reader.Len())
			}
			_, err = ReadAddress(bytes.NewReader(wire[:len(wire)-1]))
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated: err=%v, want %v", err, io.ErrUnexpectedEOF)
			}
		})
	}
}
