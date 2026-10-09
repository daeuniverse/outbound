package juicity

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestClientRingConcurrentCapability(t *testing.T) {
	var update func(int64)
	created := 0
	ring := newClientRing(func(callback func(int64)) *clientImpl {
		created++
		update = callback
		return &clientImpl{ClientOption: &ClientOption{Ctx: context.Background()}}
	}, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ring.DialContext(ctx, nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := range 20000 {
			update(int64(100 + i%10))
		}
	}()
	for _, auth := range []bool{false, true} {
		go func(auth bool) {
			defer wg.Done()
			<-start
			for range 2000 {
				var err error
				if auth {
					_, _, err = ring.DialAuth(ctx, nil, nil, nil)
				} else {
					_, err = ring.DialContext(ctx, nil, nil, nil)
				}
				if !errors.Is(err, context.Canceled) {
					t.Errorf("dial auth=%v: got %v, want context cancellation", auth, err)
					return
				}
			}
		}(auth)
	}
	close(start)
	wg.Wait()
	if created != 1 {
		t.Fatalf("created %d clients despite available capacity", created)
	}
}
