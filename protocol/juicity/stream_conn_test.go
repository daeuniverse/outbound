package juicity

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/quic-go"
)

type testStream struct {
	quic.Stream
	reader io.Reader
	writer io.Writer
}

func (s *testStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *testStream) Write(p []byte) (int, error) { return s.writer.Write(p) }

func TestConnHeaderErrorPersists(t *testing.T) {
	input := bytes.NewReader([]byte{trojanc.NetworkToByte("tcp"), 0xff, 0, 'x'})
	conn := NewConn(&testStream{reader: input}, nil, nil)
	var headerErr error
	for i, p := range [][]byte{nil, make([]byte, 1), nil} {
		n, err := conn.Read(p)
		if n != 0 || err == nil {
			t.Fatalf("read %d: got (%d, %v), want header error", i, n, err)
		}
		if i == 0 {
			headerErr = err
		} else if !errors.Is(err, headerErr) {
			t.Fatalf("read %d: got %v, want %v", i, err, headerErr)
		}
		if input.Len() != 1 {
			t.Fatalf("read %d consumed payload after invalid header", i)
		}
	}
}
