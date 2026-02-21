// +build !linux

package netproxy

import (
	"io"
)

// ReadFrom implements io.ReaderFrom with standard copy for non-Linux systems
func ReadFrom(dst Conn, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}

// WriteTo implements io.WriterTo with standard copy for non-Linux systems
func WriteTo(src Conn, dst io.Writer) (int64, error) {
	return io.Copy(dst, src)
}
