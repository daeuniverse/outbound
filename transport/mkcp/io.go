package mkcp

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/daeuniverse/outbound/common/buf"
)

// PacketReader is the interface for reading KCP packets.
type PacketReader interface {
	Read([]byte) []Segment
}

// PacketWriter is the interface for writing KCP packets.
type PacketWriter interface {
	Overhead() int
	io.Writer
}

// KCPPacketReader reads and decrypts KCP packets.
type KCPPacketReader struct {
	Security cipher.AEAD
}

// Read parses and returns segments from the input buffer.
func (r *KCPPacketReader) Read(b []byte) []Segment {
	if r.Security != nil {
		nonceSize := r.Security.NonceSize()
		overhead := r.Security.Overhead()
		if len(b) <= nonceSize+overhead {
			return nil
		}
		out, err := r.Security.Open(b[nonceSize:nonceSize], b[:nonceSize], b[nonceSize:], nil)
		if err != nil {
			return nil
		}
		b = out
	}
	var result []Segment
	for len(b) > 0 {
		seg, x := ReadSegment(b)
		if seg == nil {
			break
		}
		result = append(result, seg)
		b = x
	}
	return result
}

// KCPPacketWriter encrypts and writes KCP packets.
type KCPPacketWriter struct {
	Security cipher.AEAD
	Writer   io.Writer
}

// Overhead returns the overhead of the packet writer.
func (w *KCPPacketWriter) Overhead() int {
	overhead := 0
	if w.Security != nil {
		overhead += w.Security.Overhead() + w.Security.NonceSize()
	}
	return overhead
}

// Write encrypts and writes data to the underlying writer.
func (w *KCPPacketWriter) Write(b []byte) (int, error) {
	bb := buf.New()
	defer bb.Release()

	if w.Security != nil {
		nonceSize := w.Security.NonceSize()
		nonce := bb.Extend(int32(nonceSize))
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return 0, err
		}

		encrypted := bb.Extend(int32(w.Security.Overhead() + len(b)))
		w.Security.Seal(encrypted[:0], nonce, b, nil)
	} else {
		bb.Write(b)
	}

	_, err := w.Writer.Write(bb.Bytes())
	return len(b), err
}
