package mkcp

import (
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common/buf"
)

// SegmentWriter is the interface for writing segments.
type SegmentWriter interface {
	Write(seg Segment) error
	Release()
}

// SimpleSegmentWriter implements SegmentWriter with basic functionality.
type SimpleSegmentWriter struct {
	sync.Mutex
	buffer *buf.Buffer
	writer io.Writer
	closed bool
}

// NewSegmentWriter creates a new SimpleSegmentWriter.
func NewSegmentWriter(writer io.Writer) SegmentWriter {
	return &SimpleSegmentWriter{
		writer: writer,
		buffer: buf.New(),
	}
}

// Write serializes and writes a segment.
func (w *SimpleSegmentWriter) Write(seg Segment) error {
	w.Lock()
	defer w.Unlock()
	if w.closed {
		return io.ErrClosedPipe
	}

	w.buffer.Clear()
	rawBytes := w.buffer.Extend(seg.ByteSize())
	seg.Serialize(rawBytes)
	_, err := w.writer.Write(w.buffer.Bytes())
	return err
}

// Release releases the segment writer resources.
func (w *SimpleSegmentWriter) Release() {
	w.Lock()
	defer w.Unlock()
	w.buffer.Release()
	w.closed = true
}

// RetryableWriter wraps a SegmentWriter with retry logic.
type RetryableWriter struct {
	writer SegmentWriter
}

// NewRetryableWriter creates a new RetryableWriter.
func NewRetryableWriter(writer SegmentWriter) SegmentWriter {
	return &RetryableWriter{
		writer: writer,
	}
}

// Write attempts to write a segment with retries.
func (w *RetryableWriter) Write(seg Segment) error {
	return retry(5, 100*time.Millisecond, func() error {
		return w.writer.Write(seg)
	})
}

// Release releases the underlying writer.
func (w *RetryableWriter) Release() {
	w.writer.Release()
}

// retry executes a function with retries.
func retry(attempts int, sleep time.Duration, f func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = f()
		if err == nil {
			return nil
		}
		time.Sleep(sleep)
	}
	return err
}
