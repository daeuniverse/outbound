package tuic

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestReadFromNoDeadlock(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	readDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(readDone)
		_, _, _ = q.ReadFrom(make([]byte, 1024))
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		defer wg.Done()
		packets.Close()
	}()

	select {
	case <-readDone:
		t.Log("ReadFrom unblocked successfully - no deadlock")
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom deadlocked - Close() could not unblock it")
	}

	wg.Wait()
}

func TestReadFromReturnsNilAfterClose(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	packets.Close()

	_, _, err := q.ReadFrom(make([]byte, 1024))
	if err == nil {
		t.Error("expected error after close, got nil")
	}
}

func TestPacketsCloseUnblocksPopFrontBlock(t *testing.T) {
	p := NewPackets()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.PopFrontBlock()
	}()

	time.Sleep(50 * time.Millisecond)
	_ = p.Close()

	select {
	case <-done:
		t.Log("PopFrontBlock unblocked after Close")
	case <-time.After(1 * time.Second):
		t.Fatal("PopFrontBlock did not unblock after Close")
	}
}

func TestPacketsPushPop(t *testing.T) {
	p := NewPackets()

	go func() {
		time.Sleep(50 * time.Millisecond)
		p.PushBack(&Packet{
			PKT_ID:     1,
			FRAG_ID:    0,
			FRAG_TOTAL: 1,
			DATA:       []byte("test data"),
			ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 8080},
		})
	}()

	packet, closed := p.PopFrontBlock()
	if closed {
		t.Fatal("expected packet, got closed")
	}
	if packet == nil {
		t.Fatal("expected non-nil packet")
	}
	if string(packet.DATA) != "test data" {
		t.Errorf("expected 'test data', got '%s'", packet.DATA)
	}
	_ = p.Close()
}

func TestConcurrentPushClose(t *testing.T) {
	p := NewPackets()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.PushBack(&Packet{DATA: []byte("test")})
		}()
	}

	time.Sleep(10 * time.Millisecond)
	_ = p.Close()

	wg.Wait()
	_, closed := p.PopFrontBlock()
	if !closed {
		t.Error("expected closed after Close")
	}
}

func TestQuicStreamPacketConnWriteToAfterClose(t *testing.T) {
	q := &quicStreamPacketConn{}

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if _, err := q.WriteTo([]byte("test"), "127.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}
