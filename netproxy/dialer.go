package netproxy

import (
	"context"
)

// A Dialer is a means to establish a connection.
// Custom dialers should also implement ContextDialer.
type Dialer interface {
	Dial(network string, addr string) (c Conn, err error)
}

type ContextDialer interface {
	Dial(network string, addr string) (c Conn, err error)
	DialContext(ctx context.Context, network, addr string) (c Conn, err error)
}

type ContextDialerConverter struct {
	Dialer
}

func DialContext(ctx context.Context, network, addr string, dial func(network, addr string) (Conn, error)) (Conn, error) {
	var done = make(chan struct{})
	var c Conn
	var err error
	go func() {
		c, err = dial(network, addr)
		select {
		case <-ctx.Done():
			if err == nil {
				_ = c.Close()
			}
		default:
			close(done)
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return c, err
	}
}

func (d *ContextDialerConverter) DialContext(ctx context.Context, network, addr string) (c Conn, err error) {
	return DialContext(ctx, network, addr, d.Dialer.Dial)
}
