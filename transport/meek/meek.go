package meek

import (
	"context"
	"io"
)

type Session interface {
	io.ReadWriteCloser
}

type Request struct {
	Data          []byte
	ConnectionTag []byte
}

type Tripper interface {
	RoundTrip(ctx context.Context, req Request) (resp Response, err error)
}

// StreamingTripper extends Tripper with streaming response support.
type StreamingTripper interface {
	Tripper
	// RoundTripStreaming sends a request and streams the response to the writer.
	// It returns after the response is fully received.
	RoundTripStreaming(ctx context.Context, req Request, respWriter io.Writer) error
}

type Response struct {
	Data []byte
}
