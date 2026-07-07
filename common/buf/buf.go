/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

// Package buf provides a simple pooled byte buffer implementation.
package buf

import (
	"sync"
)

// Buffer is a simple byte buffer with pool support.
type Buffer struct {
	data []byte
}

// bufferPool is a pool of buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return &Buffer{
			data: make([]byte, 0, 2048),
		}
	},
}

// New creates a new buffer from the pool.
func New() *Buffer {
	return bufferPool.Get().(*Buffer)
}

// Release returns the buffer to the pool.
func (b *Buffer) Release() {
	if b == nil {
		return
	}
	b.data = b.data[:0]
	bufferPool.Put(b)
}

// Bytes returns the buffer content.
func (b *Buffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	return b.data
}

// Len returns the length of the buffer content.
func (b *Buffer) Len() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.data))
}

// Clear clears the buffer.
func (b *Buffer) Clear() {
	b.data = b.data[:0]
}

// Write appends data to the buffer.
func (b *Buffer) Write(data []byte) (int, error) {
	b.data = append(b.data, data...)
	return len(data), nil
}

// Extend extends the buffer by n bytes and returns the extended slice.
func (b *Buffer) Extend(n int32) []byte {
	start := len(b.data)
	b.data = append(b.data, make([]byte, n)...)
	return b.data[start:]
}

// ReadFrom reads data from an io.Reader into the buffer.
func (b *Buffer) ReadFrom(reader interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 2048)
	n, err := reader.Read(buf)
	if n > 0 {
		b.data = append(b.data, buf[:n]...)
	}
	return int64(n), err
}

// MultiBuffer is a slice of Buffers.
type MultiBuffer []*Buffer

// IsEmpty returns true if the multi-buffer is empty.
func (mb MultiBuffer) IsEmpty() bool {
	return len(mb) == 0
}

// ReleaseMulti releases all buffers in a multi-buffer.
func ReleaseMulti(mb MultiBuffer) {
	for _, b := range mb {
		b.Release()
	}
}

// SplitBytes splits the multi-buffer content into a byte slice.
func SplitBytes(mb MultiBuffer, b []byte) (MultiBuffer, int) {
	totalBytes := 0
	for len(mb) > 0 && len(b) > 0 {
		buf := mb[0]
		n := copy(b, buf.Bytes())
		totalBytes += n
		if n < int(buf.Len()) {
			// Partial read, keep remaining in buffer
			remaining := New()
			remaining.Write(buf.Bytes()[n:])
			buf.Release()
			mb[0] = remaining
			break
		}
		buf.Release()
		mb = mb[1:]
		b = b[n:]
	}
	return mb, totalBytes
}
