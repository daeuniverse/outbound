package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/mkcp"
)

var mekyaGlobalConv = uint32(0)

func rollMekyaConv() uint16 {
	return uint16(atomic.AddUint32(&mekyaGlobalConv, 1))
}

// MekyaConfig holds Mekya-specific configuration.
type MekyaConfig struct {
	// PollingIntervalInitial is the initial polling interval in milliseconds.
	PollingIntervalInitial int
	// MaxRequestSize is the maximum size of a single HTTP request body.
	MaxRequestSize int
	// MaxWriteDelay is the maximum delay to wait for more packets before sending.
	MaxWriteDelay int
}

// DefaultMekyaConfig returns the default Mekya configuration.
func DefaultMekyaConfig() *MekyaConfig {
	return &MekyaConfig{
		PollingIntervalInitial: 100,
		MaxRequestSize:         65536,
		MaxWriteDelay:          10,
	}
}

// MekyaDialer is a Mekya dialer that uses mKCP over HTTP.
type MekyaDialer struct {
	*Dialer
	kcpConfig   *mkcp.Config
	mekyaConfig *MekyaConfig
}

// NewMekyaDialer creates a new Mekya dialer.
func NewMekyaDialer(meekDialer *Dialer, kcpConfig *mkcp.Config) *MekyaDialer {
	return &MekyaDialer{
		Dialer:      meekDialer,
		kcpConfig:   kcpConfig,
		mekyaConfig: DefaultMekyaConfig(),
	}
}

// DialContext creates a new Mekya connection.
func (m *MekyaDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	sessionCtx, cancel := context.WithCancel(ctx)

	// Create HTTP packet transport with concurrent support
	packetConn := newHTTPPacketConn(sessionCtx, &httpTripperClient{
		nextDialer: m.nextDialer,
		addr:       addr,
		url:        m.url,
		tlsConfig:  m.tlsConfig,
	}, m.mekyaConfig)

	security, err := m.kcpConfig.GetSecurity()
	if err != nil {
		cancel()
		return nil, err
	}

	reader := &mkcp.KCPPacketReader{
		Security: security,
	}

	writer := &mkcp.KCPPacketWriter{
		Security: security,
		Writer:   packetConn,
	}

	conv := rollMekyaConv()

	localAddr := &mkcp.FakeAddr{Addr: "0.0.0.0:0"}
	remoteAddr := &mkcp.FakeAddr{Addr: addr}

	session := mkcp.NewConnection(mkcp.ConnMetadata{
		LocalAddr:    localAddr,
		RemoteAddr:   remoteAddr,
		Conversation: conv,
	}, writer, packetConn, m.kcpConfig)

	// Start the background polling/sending loop
	go packetConn.keepRunning(reader, session)

	return &mekyaConn{
		Connection: session,
		cancel:     cancel,
	}, nil
}

// mekyaConn wraps a KCP Connection as netproxy.Conn.
type mekyaConn struct {
	*mkcp.Connection
	cancel context.CancelFunc
}

func (c *mekyaConn) Close() error {
	c.cancel()
	return c.Connection.Close()
}

// httpPacketConn wraps HTTP round-trips as a packet-based connection for mKCP.
// It supports concurrent HTTP requests and background polling.
type httpPacketConn struct {
	ctx       context.Context
	tripper   Tripper
	sessionID []byte
	config    *MekyaConfig

	// Write channel for outgoing packets
	writerChan chan []byte

	closed    int32
	closeOnce sync.Once
}

func newHTTPPacketConn(ctx context.Context, tripper Tripper, config *MekyaConfig) *httpPacketConn {
	sessionID := make([]byte, 16)
	io.ReadFull(rand.Reader, sessionID)

	return &httpPacketConn{
		ctx:        ctx,
		tripper:    tripper,
		sessionID:  sessionID,
		config:     config,
		writerChan: make(chan []byte, 256),
	}
}

// keepRunning is the main loop that handles sending and receiving packets.
// It batches outgoing packets and sends them via HTTP, receiving responses asynchronously.
func (c *httpPacketConn) keepRunning(reader mkcp.PacketReader, conn *mkcp.Connection) {
	currentPollingInterval := c.config.PollingIntervalInitial

	for c.ctx.Err() == nil {
		currentPollingInterval = c.runOnce(currentPollingInterval, reader, conn)
	}
}

func (c *httpPacketConn) runOnce(currentPollingInterval int, reader mkcp.PacketReader, conn *mkcp.Connection) int {
	requestBody := bytes.NewBuffer(nil)
	waitTimer := time.NewTimer(time.Duration(currentPollingInterval) * time.Millisecond)
	var seenPacket bool

copyFromChan:
	for {
		select {
		case <-c.ctx.Done():
			waitTimer.Stop()
			return currentPollingInterval
		case <-waitTimer.C:
			break copyFromChan
		case packet := <-c.writerChan:
			if !seenPacket {
				seenPacket = true
				waitTimer.Stop()
				waitTimer.Reset(time.Duration(c.config.MaxWriteDelay) * time.Millisecond)
			}
			// Check if adding this packet would exceed max request size
			overhead := 2 // length prefix
			if requestBody.Len()+overhead+len(packet) > c.config.MaxRequestSize {
				// Put it back for next round (or send immediately in a separate request)
				go func(p []byte) {
					select {
					case c.writerChan <- p:
					case <-c.ctx.Done():
					}
				}(packet)
				break copyFromChan
			}
			// Write packet with length prefix
			binary.Write(requestBody, binary.BigEndian, uint16(len(packet)))
			requestBody.Write(packet)
		}
	}
	waitTimer.Stop()

	// Send HTTP request asynchronously - this enables concurrent HTTP connections
	go func(data []byte) {
		// Try streaming response if supported
		if streamingTripper, ok := c.tripper.(StreamingTripper); ok {
			c.doStreamingRoundTrip(streamingTripper, data, reader, conn)
		} else {
			c.doNormalRoundTrip(data, reader, conn)
		}
	}(requestBody.Bytes())

	// Adjust polling interval based on activity
	if seenPacket {
		// Data was sent, reset to minimum interval
		return c.config.MaxWriteDelay
	}
	// No data, increase polling interval (exponential backoff)
	newInterval := currentPollingInterval * 2
	if newInterval > 1000 { // Cap at 1 second
		newInterval = 1000
	}
	return newInterval
}

// doStreamingRoundTrip sends a request and processes the response as it streams in.
// This reduces latency by processing packets as they arrive.
func (c *httpPacketConn) doStreamingRoundTrip(tripper StreamingTripper, data []byte, reader mkcp.PacketReader, conn *mkcp.Connection) {
	pipeReader, pipeWriter := io.Pipe()

	// Start a goroutine to parse packets from the streaming response
	go func() {
		defer pipeReader.Close()
		c.parseAndInputPacketsFromReader(pipeReader, reader, conn)
	}()

	// Stream the response into the pipe
	err := tripper.RoundTripStreaming(c.ctx, Request{
		Data:          data,
		ConnectionTag: c.sessionID,
	}, pipeWriter)
	pipeWriter.Close()

	if err != nil && c.ctx.Err() == nil {
		// Log error but continue
		return
	}
}

// doNormalRoundTrip sends a request and waits for the complete response.
func (c *httpPacketConn) doNormalRoundTrip(data []byte, reader mkcp.PacketReader, conn *mkcp.Connection) {
	resp, err := c.tripper.RoundTrip(c.ctx, Request{
		Data:          data,
		ConnectionTag: c.sessionID,
	})
	if err != nil {
		if c.ctx.Err() != nil {
			return
		}
		// Log error but continue
		return
	}

	// Parse response packets and input to KCP
	if len(resp.Data) > 0 {
		c.parseAndInputPackets(resp.Data, reader, conn)
	}
}

// parseAndInputPacketsFromReader parses packets from an io.Reader (for streaming).
func (c *httpPacketConn) parseAndInputPacketsFromReader(r io.Reader, reader mkcp.PacketReader, conn *mkcp.Connection) {
	for {
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(r, packet); err != nil {
			return
		}

		// Parse KCP segments and input to connection
		segments := reader.Read(packet)
		if len(segments) > 0 {
			conn.Input(segments)
		}
	}
}

// parseAndInputPackets parses response data and feeds packets to KCP connection.
func (c *httpPacketConn) parseAndInputPackets(data []byte, reader mkcp.PacketReader, conn *mkcp.Connection) {
	r := bytes.NewReader(data)
	for r.Len() >= 2 {
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return
		}
		if r.Len() < int(length) {
			return
		}
		packet := make([]byte, length)
		if _, err := io.ReadFull(r, packet); err != nil {
			return
		}

		// Parse KCP segments and input to connection
		segments := reader.Read(packet)
		if len(segments) > 0 {
			conn.Input(segments)
		}
	}
}

// Write queues a packet for sending. This is non-blocking.
func (c *httpPacketConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	packet := make([]byte, len(b))
	copy(packet, b)

	select {
	case c.writerChan <- packet:
		return len(b), nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

// Read is not used for Mekya - reads come from the KCP connection.
func (c *httpPacketConn) Read(b []byte) (int, error) {
	// This should not be called directly for Mekya
	// Reads are handled through KCP connection
	<-c.ctx.Done()
	return 0, c.ctx.Err()
}

// Close closes the packet connection.
func (c *httpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
	})
	return nil
}
