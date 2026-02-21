package shadowsocks_2022

import (
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

func TestValidateTimestamp(t *testing.T) {
	now := time.Now()
	if err := validateTimestamp(now, now); err != nil {
		t.Fatalf("now should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance-time.Millisecond), now); err != nil {
		t.Fatalf("near-future timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance+time.Millisecond), now); err != nil {
		t.Fatalf("near-past timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance+time.Millisecond), now); err != protocol.ErrReplayAttack {
		t.Fatalf("too-far future timestamp should fail with replay, got: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Millisecond), now); err != protocol.ErrReplayAttack {
		t.Fatalf("too-old timestamp should fail with replay, got: %v", err)
	}
}

func TestUdpConn_NextPacketID_ConcurrentUnique(t *testing.T) {
	u := &UdpConn{}
	const n = 2000

	ids := make(chan uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- u.nextPacketID()
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[uint64]struct{}, n)
	var minID uint64 = ^uint64(0)
	var maxID uint64
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate packetID: %d", id)
		}
		seen[id] = struct{}{}
		if id < minID {
			minID = id
		}
		if id > maxID {
			maxID = id
		}
	}

	if len(seen) != n {
		t.Fatalf("unexpected unique count: got %d, want %d", len(seen), n)
	}
	if minID != 1 {
		t.Fatalf("unexpected min packetID: got %d, want 1", minID)
	}
	if maxID != n {
		t.Fatalf("unexpected max packetID: got %d, want %d", maxID, n)
	}
}

func TestUdpConn_ReplayWindow_PerSessionAndExpiry(t *testing.T) {
	u := &UdpConn{}
	now := time.Now()

	var sid1 [8]byte
	copy(sid1[:], []byte{1, 1, 1, 1, 1, 1, 1, 1})
	var sid2 [8]byte
	copy(sid2[:], []byte{2, 2, 2, 2, 2, 2, 2, 2})

	if !u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 packet 1 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 duplicate packet 1 should fail")
	}
	if !u.checkAndUpdateReplay(sid1, 2, now) {
		t.Fatalf("sid1 packet 2 should pass")
	}
	if !u.checkAndUpdateReplay(sid2, 1, now) {
		t.Fatalf("sid2 packet 1 should pass independently")
	}

	if !u.checkAndUpdateReplay(sid1, 5000, now) {
		t.Fatalf("sid1 packet 5000 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 old packet should fail after large jump")
	}

	future := now.Add(ciphers.SaltStorageDuration + time.Second)
	if !u.checkAndUpdateReplay(sid1, 1, future) {
		t.Fatalf("sid1 should reset after expiry and accept packet 1")
	}
}
