package mkcp

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/common/buf"
)

var (
	// ErrIOTimeout is returned when read/write timeout occurs.
	ErrIOTimeout = &errIOTimeout{}
	// ErrClosedConnection is returned when connection is closed.
	ErrClosedConnection = &errClosedConnection{}
)

type errIOTimeout struct{}

func (e *errIOTimeout) Error() string   { return "Read/Write timeout" }
func (e *errIOTimeout) Timeout() bool   { return true }
func (e *errIOTimeout) Temporary() bool { return true }

type errClosedConnection struct{}

func (e *errClosedConnection) Error() string { return "Connection closed" }

// State of the connection
type State int32

// Is returns true if current State is one of the candidates.
func (s State) Is(states ...State) bool {
	for _, state := range states {
		if s == state {
			return true
		}
	}
	return false
}

const (
	StateActive          State = 0 // Connection is active
	StateReadyToClose    State = 1 // Connection is closed locally
	StatePeerClosed      State = 2 // Connection is closed on remote
	StateTerminating     State = 3 // Connection is ready to be destroyed locally
	StatePeerTerminating State = 4 // Connection is ready to be destroyed on remote
	StateTerminated      State = 5 // Connection is destroyed.
)

func nowMillisec() int64 {
	now := time.Now()
	return now.Unix()*1000 + int64(now.Nanosecond()/1000000)
}

// RoundTripInfo tracks round-trip time information.
type RoundTripInfo struct {
	sync.RWMutex
	variation        uint32
	srtt             uint32
	rto              uint32
	minRtt           uint32
	updatedTimestamp uint32
}

// UpdatePeerRTO updates the peer RTO.
func (info *RoundTripInfo) UpdatePeerRTO(rto uint32, current uint32) {
	info.Lock()
	defer info.Unlock()

	if current-info.updatedTimestamp < 3000 {
		return
	}

	info.updatedTimestamp = current
	info.rto = rto
}

// Update updates the RTT information.
func (info *RoundTripInfo) Update(rtt uint32, current uint32) {
	if rtt > 0x7FFFFFFF {
		return
	}
	info.Lock()
	defer info.Unlock()

	// https://tools.ietf.org/html/rfc6298
	if info.srtt == 0 {
		info.srtt = rtt
		info.variation = rtt / 2
	} else {
		delta := rtt - info.srtt
		if info.srtt > rtt {
			delta = info.srtt - rtt
		}
		info.variation = (3*info.variation + delta) / 4
		info.srtt = (7*info.srtt + rtt) / 8
		if info.srtt < info.minRtt {
			info.srtt = info.minRtt
		}
	}
	var rto uint32
	if info.minRtt < 4*info.variation {
		rto = info.srtt + 4*info.variation
	} else {
		rto = info.srtt + info.variation
	}

	if rto > 10000 {
		rto = 10000
	}
	info.rto = rto * 5 / 4
	info.updatedTimestamp = current
}

// Timeout returns the current RTO.
func (info *RoundTripInfo) Timeout() uint32 {
	info.RLock()
	defer info.RUnlock()

	return info.rto
}

// SmoothedTime returns the smoothed RTT.
func (info *RoundTripInfo) SmoothedTime() uint32 {
	info.RLock()
	defer info.RUnlock()

	return info.srtt
}

// Notifier is a simple signal notifier.
type Notifier struct {
	ch chan struct{}
}

// NewNotifier creates a new Notifier.
func NewNotifier() *Notifier {
	return &Notifier{
		ch: make(chan struct{}, 1),
	}
}

// Signal sends a signal.
func (n *Notifier) Signal() {
	select {
	case n.ch <- struct{}{}:
	default:
	}
}

// Wait returns a channel that receives signals.
func (n *Notifier) Wait() <-chan struct{} {
	return n.ch
}

// Updater manages periodic updates.
type Updater struct {
	interval        int64
	shouldContinue  func() bool
	shouldTerminate func() bool
	updateFunc      func()
	notifier        chan struct{}
}

// NewUpdater creates a new Updater.
func NewUpdater(interval uint32, shouldContinue func() bool, shouldTerminate func() bool, updateFunc func()) *Updater {
	u := &Updater{
		interval:        int64(time.Duration(interval) * time.Millisecond),
		shouldContinue:  shouldContinue,
		shouldTerminate: shouldTerminate,
		updateFunc:      updateFunc,
		notifier:        make(chan struct{}, 1),
	}
	return u
}

// WakeUp starts the updater if not already running.
func (u *Updater) WakeUp() {
	select {
	case u.notifier <- struct{}{}:
		go u.run()
	default:
	}
}

func (u *Updater) run() {
	defer func() {
		<-u.notifier
	}()

	if u.shouldTerminate() {
		return
	}
	ticker := time.NewTicker(u.Interval())
	for u.shouldContinue() {
		u.updateFunc()
		<-ticker.C
	}
	ticker.Stop()
}

// Interval returns the update interval.
func (u *Updater) Interval() time.Duration {
	return time.Duration(atomic.LoadInt64(&u.interval))
}

// SetInterval sets the update interval.
func (u *Updater) SetInterval(d time.Duration) {
	atomic.StoreInt64(&u.interval, int64(d))
}

// ConnMetadata contains connection metadata.
type ConnMetadata struct {
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	Conversation uint16
}

// Connection is a KCP connection over UDP.
type Connection struct {
	meta       ConnMetadata
	closer     io.Closer
	rd         time.Time
	wd         time.Time // write deadline
	since      int64
	dataInput  *Notifier
	dataOutput *Notifier
	Config     *Config

	state            State
	stateBeginTime   uint32
	lastIncomingTime uint32
	lastPingTime     uint32

	mss       uint32
	roundTrip *RoundTripInfo

	receivingWorker *ReceivingWorker
	sendingWorker   *SendingWorker

	output SegmentWriter

	dataUpdater *Updater
	pingUpdater *Updater
}

// NewConnection creates a new KCP connection.
func NewConnection(meta ConnMetadata, writer PacketWriter, closer io.Closer, config *Config) *Connection {
	conn := &Connection{
		meta:       meta,
		closer:     closer,
		since:      nowMillisec(),
		dataInput:  NewNotifier(),
		dataOutput: NewNotifier(),
		Config:     config,
		output:     NewRetryableWriter(NewSegmentWriter(writer)),
		mss:        config.GetMTUValue() - uint32(writer.Overhead()) - DataSegmentOverhead,
		roundTrip: &RoundTripInfo{
			rto:    100,
			minRtt: config.GetTTIValue(),
		},
	}

	conn.receivingWorker = NewReceivingWorker(conn)
	conn.sendingWorker = NewSendingWorker(conn)

	isTerminating := func() bool {
		return conn.State().Is(StateTerminating, StateTerminated)
	}
	isTerminated := func() bool {
		return conn.State() == StateTerminated
	}
	conn.dataUpdater = NewUpdater(
		config.GetTTIValue(),
		func() bool {
			return !isTerminating() && (conn.sendingWorker.UpdateNecessary() || conn.receivingWorker.UpdateNecessary())
		},
		isTerminating,
		conn.updateTask)
	conn.pingUpdater = NewUpdater(
		5000, // 5 seconds
		func() bool { return !isTerminated() },
		isTerminated,
		conn.updateTask)
	conn.pingUpdater.WakeUp()

	return conn
}

// Elapsed returns the elapsed time since connection creation.
func (c *Connection) Elapsed() uint32 {
	return uint32(nowMillisec() - c.since)
}

// ReadMultiBuffer reads data as MultiBuffer.
func (c *Connection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if c == nil {
		return nil, io.EOF
	}

	for {
		if c.State().Is(StateReadyToClose, StateTerminating, StateTerminated) {
			return nil, io.EOF
		}
		mb := c.receivingWorker.ReadMultiBuffer()
		if !mb.IsEmpty() {
			c.dataUpdater.WakeUp()
			return mb, nil
		}

		if c.State() == StatePeerTerminating {
			return nil, io.EOF
		}

		if err := c.waitForDataInput(); err != nil {
			return nil, err
		}
	}
}

func (c *Connection) waitForDataInput() error {
	for i := 0; i < 16; i++ {
		select {
		case <-c.dataInput.Wait():
			return nil
		default:
			runtime.Gosched()
		}
	}

	duration := time.Second * 16
	if !c.rd.IsZero() {
		duration = time.Until(c.rd)
		if duration < 0 {
			return ErrIOTimeout
		}
	}

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-c.dataInput.Wait():
	case <-timeout.C:
		if !c.rd.IsZero() && c.rd.Before(time.Now()) {
			return ErrIOTimeout
		}
	}

	return nil
}

// Read implements the Conn Read method.
func (c *Connection) Read(b []byte) (int, error) {
	if c == nil {
		return 0, io.EOF
	}

	for {
		if c.State().Is(StateReadyToClose, StateTerminating, StateTerminated) {
			return 0, io.EOF
		}
		nBytes := c.receivingWorker.Read(b)
		if nBytes > 0 {
			c.dataUpdater.WakeUp()
			return nBytes, nil
		}

		if err := c.waitForDataInput(); err != nil {
			return 0, err
		}
	}
}

func (c *Connection) waitForDataOutput() error {
	for i := 0; i < 16; i++ {
		select {
		case <-c.dataOutput.Wait():
			return nil
		default:
			runtime.Gosched()
		}
	}

	duration := time.Second * 16
	if !c.wd.IsZero() {
		duration = time.Until(c.wd)
		if duration < 0 {
			return ErrIOTimeout
		}
	}

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-c.dataOutput.Wait():
	case <-timeout.C:
		if !c.wd.IsZero() && c.wd.Before(time.Now()) {
			return ErrIOTimeout
		}
	}

	return nil
}

// Write implements io.Writer.
func (c *Connection) Write(b []byte) (int, error) {
	reader := bytes.NewReader(b)
	if err := c.writeMultiBufferInternal(reader); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Connection) writeMultiBufferInternal(reader io.Reader) error {
	updatePending := false
	defer func() {
		if updatePending {
			c.dataUpdater.WakeUp()
		}
	}()

	var b *buf.Buffer
	defer func() {
		if b != nil {
			b.Release()
		}
	}()

	for {
		for {
			if c == nil || c.State() != StateActive {
				return io.ErrClosedPipe
			}

			if b == nil {
				b = buf.New()
				_, err := b.ReadFrom(io.LimitReader(reader, int64(c.mss)))
				if err != nil || b.Len() == 0 {
					return nil
				}
			}

			if !c.sendingWorker.Push(b) {
				break
			}
			updatePending = true
			b = nil
		}

		if updatePending {
			c.dataUpdater.WakeUp()
			updatePending = false
		}

		if err := c.waitForDataOutput(); err != nil {
			return err
		}
	}
}

// SetState sets the connection state.
func (c *Connection) SetState(state State) {
	current := c.Elapsed()
	atomic.StoreInt32((*int32)(&c.state), int32(state))
	atomic.StoreUint32(&c.stateBeginTime, current)

	switch state {
	case StateReadyToClose:
		c.receivingWorker.CloseRead()
	case StatePeerClosed:
		c.sendingWorker.CloseWrite()
	case StateTerminating:
		c.receivingWorker.CloseRead()
		c.sendingWorker.CloseWrite()
		c.pingUpdater.SetInterval(time.Second)
	case StatePeerTerminating:
		c.sendingWorker.CloseWrite()
		c.pingUpdater.SetInterval(time.Second)
	case StateTerminated:
		c.receivingWorker.CloseRead()
		c.sendingWorker.CloseWrite()
		c.pingUpdater.SetInterval(time.Second)
		c.dataUpdater.WakeUp()
		c.pingUpdater.WakeUp()
		go c.Terminate()
	}
}

// Close closes the connection.
func (c *Connection) Close() error {
	if c == nil {
		return ErrClosedConnection
	}

	c.dataInput.Signal()
	c.dataOutput.Signal()

	switch c.State() {
	case StateReadyToClose, StateTerminating, StateTerminated:
		return ErrClosedConnection
	case StateActive:
		c.SetState(StateReadyToClose)
	case StatePeerClosed:
		c.SetState(StateTerminating)
	case StatePeerTerminating:
		c.SetState(StateTerminated)
	}

	return nil
}

// LocalAddr returns the local network address.
func (c *Connection) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.meta.LocalAddr
}

// RemoteAddr returns the remote network address.
func (c *Connection) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.meta.RemoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *Connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Connection) SetReadDeadline(t time.Time) error {
	if c == nil || c.State() != StateActive {
		return ErrClosedConnection
	}
	c.rd = t
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *Connection) SetWriteDeadline(t time.Time) error {
	if c == nil || c.State() != StateActive {
		return ErrClosedConnection
	}
	c.wd = t
	return nil
}

func (c *Connection) updateTask() {
	c.flush()
}

// Terminate terminates the connection.
func (c *Connection) Terminate() {
	if c == nil {
		return
	}

	c.dataInput.Signal()
	c.dataOutput.Signal()

	c.closer.Close()
	c.sendingWorker.Release()
	c.receivingWorker.Release()
	c.output.Release()
}

// HandleOption handles segment options.
func (c *Connection) HandleOption(opt SegmentOption) {
	if (opt & SegmentOptionClose) == SegmentOptionClose {
		c.OnPeerClosed()
	}
}

// OnPeerClosed handles peer close event.
func (c *Connection) OnPeerClosed() {
	switch c.State() {
	case StateReadyToClose:
		c.SetState(StateTerminating)
	case StateActive:
		c.SetState(StatePeerClosed)
	}
}

// Input processes incoming segments.
func (c *Connection) Input(segments []Segment) {
	current := c.Elapsed()
	atomic.StoreUint32(&c.lastIncomingTime, current)

	for _, seg := range segments {
		if seg.Conversation() != c.meta.Conversation {
			break
		}

		switch seg := seg.(type) {
		case *DataSegment:
			c.HandleOption(seg.Option)
			c.receivingWorker.ProcessSegment(seg)
			if c.receivingWorker.IsDataAvailable() {
				c.dataInput.Signal()
			}
			c.dataUpdater.WakeUp()
		case *AckSegment:
			c.HandleOption(seg.Option)
			c.sendingWorker.ProcessSegment(current, seg, c.roundTrip.Timeout())
			c.dataOutput.Signal()
			c.dataUpdater.WakeUp()
		case *CmdOnlySegment:
			c.HandleOption(seg.Option)
			if seg.Command() == CommandTerminate {
				switch c.State() {
				case StateActive, StatePeerClosed:
					c.SetState(StatePeerTerminating)
				case StateReadyToClose:
					c.SetState(StateTerminating)
				case StateTerminating:
					c.SetState(StateTerminated)
				}
			}
			if seg.Option == SegmentOptionClose || seg.Command() == CommandTerminate {
				c.dataInput.Signal()
				c.dataOutput.Signal()
			}
			c.sendingWorker.ProcessReceivingNext(seg.ReceivingNext)
			c.receivingWorker.ProcessSendingNext(seg.SendingNext)
			c.roundTrip.UpdatePeerRTO(seg.PeerRTO, current)
			seg.Release()
		default:
		}
	}
}

func (c *Connection) flush() {
	current := c.Elapsed()

	if c.State() == StateTerminated {
		return
	}
	if c.State() == StateActive && current-atomic.LoadUint32(&c.lastIncomingTime) >= 30000 {
		c.Close()
	}
	if c.State() == StateReadyToClose && c.sendingWorker.IsEmpty() {
		c.SetState(StateTerminating)
	}

	if c.State() == StateTerminating {
		c.Ping(current, CommandTerminate)

		if current-atomic.LoadUint32(&c.stateBeginTime) > 8000 {
			c.SetState(StateTerminated)
		}
		return
	}
	if c.State() == StatePeerTerminating && current-atomic.LoadUint32(&c.stateBeginTime) > 4000 {
		c.SetState(StateTerminating)
	}

	if c.State() == StateReadyToClose && current-atomic.LoadUint32(&c.stateBeginTime) > 15000 {
		c.SetState(StateTerminating)
	}

	// flush acknowledges
	c.receivingWorker.Flush(current)
	c.sendingWorker.Flush(current)

	if current-atomic.LoadUint32(&c.lastPingTime) >= 3000 {
		c.Ping(current, CommandPing)
	}
}

// State returns the current connection state.
func (c *Connection) State() State {
	return State(atomic.LoadInt32((*int32)(&c.state)))
}

// Ping sends a ping segment.
func (c *Connection) Ping(current uint32, cmd Command) {
	seg := NewCmdOnlySegment()
	seg.Conv = c.meta.Conversation
	seg.Cmd = cmd
	seg.ReceivingNext = c.receivingWorker.NextNumber()
	seg.SendingNext = c.sendingWorker.FirstUnacknowledged()
	seg.PeerRTO = c.roundTrip.Timeout()
	if c.State() == StateReadyToClose {
		seg.Option = SegmentOptionClose
	}
	c.output.Write(seg)
	atomic.StoreUint32(&c.lastPingTime, current)
	seg.Release()
}
