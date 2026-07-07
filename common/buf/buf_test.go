/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package buf

import (
	"bytes"
	"testing"
)

func TestBufferWriteAndRead(t *testing.T) {
	b := New()
	defer b.Release()

	data := []byte("hello world")
	n, err := b.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	if !bytes.Equal(b.Bytes(), data) {
		t.Errorf("data mismatch: expected %v, got %v", data, b.Bytes())
	}

	if b.Len() != int32(len(data)) {
		t.Errorf("expected length %d, got %d", len(data), b.Len())
	}
}

func TestBufferClear(t *testing.T) {
	b := New()
	defer b.Release()

	b.Write([]byte("test data"))
	b.Clear()

	if b.Len() != 0 {
		t.Errorf("expected length 0 after clear, got %d", b.Len())
	}
}

func TestBufferExtend(t *testing.T) {
	b := New()
	defer b.Release()

	ext := b.Extend(10)
	if len(ext) != 10 {
		t.Errorf("expected extended slice length 10, got %d", len(ext))
	}

	if b.Len() != 10 {
		t.Errorf("expected buffer length 10, got %d", b.Len())
	}
}

func TestBufferNilSafety(t *testing.T) {
	var b *Buffer

	if b.Bytes() != nil {
		t.Error("expected nil Bytes() for nil buffer")
	}

	if b.Len() != 0 {
		t.Error("expected 0 Len() for nil buffer")
	}

	// Release on nil should not panic
	b.Release()
}

func TestMultiBufferIsEmpty(t *testing.T) {
	var mb MultiBuffer
	if !mb.IsEmpty() {
		t.Error("expected empty MultiBuffer to be empty")
	}

	mb = append(mb, New())
	if mb.IsEmpty() {
		t.Error("expected non-empty MultiBuffer to not be empty")
	}

	ReleaseMulti(mb)
}

func TestSplitBytes(t *testing.T) {
	mb := make(MultiBuffer, 0, 2)

	b1 := New()
	b1.Write([]byte("hello "))
	mb = append(mb, b1)

	b2 := New()
	b2.Write([]byte("world"))
	mb = append(mb, b2)

	dst := make([]byte, 20)
	remaining, n := SplitBytes(mb, dst)

	if n != 11 {
		t.Errorf("expected 11 bytes read, got %d", n)
	}

	if string(dst[:n]) != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", string(dst[:n]))
	}

	if !remaining.IsEmpty() {
		t.Error("expected remaining to be empty")
	}
}

func TestSplitBytesPartial(t *testing.T) {
	mb := make(MultiBuffer, 0, 1)

	b := New()
	b.Write([]byte("hello world"))
	mb = append(mb, b)

	dst := make([]byte, 5)
	remaining, n := SplitBytes(mb, dst)

	if n != 5 {
		t.Errorf("expected 5 bytes read, got %d", n)
	}

	if string(dst[:n]) != "hello" {
		t.Errorf("expected 'hello', got '%s'", string(dst[:n]))
	}

	if remaining.IsEmpty() {
		t.Error("expected remaining to not be empty")
	}

	// Read the rest
	dst2 := make([]byte, 10)
	remaining, n2 := SplitBytes(remaining, dst2)

	if n2 != 6 {
		t.Errorf("expected 6 bytes read, got %d", n2)
	}

	if string(dst2[:n2]) != " world" {
		t.Errorf("expected ' world', got '%s'", string(dst2[:n2]))
	}

	ReleaseMulti(remaining)
}
