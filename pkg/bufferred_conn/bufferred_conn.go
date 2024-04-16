package bufferred_conn

import (
	"net"

	"github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{bufio.NewReader(c), c}
}

func NewBufferedConnSize(c net.Conn, n int) *BufferedConn {
	return &BufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) Close() error {
	b.r.Put()
	return b.Conn.Close()
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (c *BufferedConn) ReadByte() (byte, error) {
	return c.r.ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	return c.r.UnreadByte()
}
