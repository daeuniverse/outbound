package pool

import (
	"sync"

	"github.com/daeuniverse/outbound/pool/bytes"
)

var bufferPool = sync.Pool{New: func() any { return bytes.NewBuffer(nil) }}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}
