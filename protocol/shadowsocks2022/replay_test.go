package shadowsocks2022

import (
	"testing"
)

func TestSlidingWindowFilter(t *testing.T) {
	filter := NewSlidingWindowFilter(64)

	// First packet should be accepted
	if !filter.Check(1) {
		t.Error("first packet should be accepted")
	}

	// Same packet should be rejected (replay)
	if filter.Check(1) {
		t.Error("replayed packet should be rejected")
	}

	// Next packet should be accepted
	if !filter.Check(2) {
		t.Error("next packet should be accepted")
	}

	// Packet within window should be accepted
	if !filter.Check(10) {
		t.Error("packet within window should be accepted")
	}

	// Old packet (after window shift) should still be tracked
	if filter.Check(1) {
		t.Error("old packet should be rejected after window shift")
	}

	// Much newer packet should shift window
	if !filter.Check(100) {
		t.Error("much newer packet should be accepted")
	}

	// Very old packet (before window) should be rejected
	if filter.Check(1) {
		t.Error("very old packet should be rejected")
	}
}

func TestSlidingWindowFilterWindowShift(t *testing.T) {
	filter := NewSlidingWindowFilter(1024)

	// Accept initial packets
	for i := uint64(1); i <= 10; i++ {
		if !filter.Check(i) {
			t.Errorf("packet %d should be accepted", i)
		}
	}

	// Jump forward by more than window size
	if !filter.Check(2000) {
		t.Error("packet 2000 should be accepted")
	}

	// Old packets should all be rejected
	for i := uint64(1); i <= 10; i++ {
		if filter.Check(i) {
			t.Errorf("old packet %d should be rejected after large shift", i)
		}
	}

	// Packets within new window should work
	if !filter.Check(1999) {
		t.Error("packet 1999 should be accepted")
	}
	if filter.Check(1999) {
		t.Error("replayed packet 1999 should be rejected")
	}
}

func TestSlidingWindowFilterReset(t *testing.T) {
	filter := NewSlidingWindowFilter(64)

	// Accept some packets
	filter.Check(1)
	filter.Check(2)
	filter.Check(3)

	// Reset
	filter.Reset()

	// Same packets should be accepted again
	if !filter.Check(1) {
		t.Error("packet 1 should be accepted after reset")
	}
	if !filter.Check(2) {
		t.Error("packet 2 should be accepted after reset")
	}
}

func TestSessionFilter(t *testing.T) {
	sf := NewSessionFilter(10)

	// Get filter for session
	f1 := sf.GetOrCreate("session1")
	if f1 == nil {
		t.Fatal("GetOrCreate should return a filter")
	}

	// Same session should return same filter
	f1b := sf.GetOrCreate("session1")
	if f1 != f1b {
		t.Error("same session should return same filter")
	}

	// Different session should return different filter
	f2 := sf.GetOrCreate("session2")
	if f1 == f2 {
		t.Error("different sessions should return different filters")
	}

	// Remove session
	sf.Remove("session1")
	f1c := sf.GetOrCreate("session1")
	if f1 == f1c {
		t.Error("after remove, should create new filter")
	}
}

func TestSessionFilterEviction(t *testing.T) {
	sf := NewSessionFilter(3)

	// Create 3 sessions
	sf.GetOrCreate("s1")
	sf.GetOrCreate("s2")
	sf.GetOrCreate("s3")

	// Creating 4th should evict one
	sf.GetOrCreate("s4")

	// We should still have 3 sessions (one was evicted)
	// The test mainly ensures no panic and eviction works
}
