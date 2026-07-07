package mkcp

import (
	"sync"

	"github.com/daeuniverse/outbound/common/buf"
)

// ReceivingWindow manages received segments by their sequence numbers.
type ReceivingWindow struct {
	cache map[uint32]*DataSegment
}

// NewReceivingWindow creates a new ReceivingWindow.
func NewReceivingWindow() *ReceivingWindow {
	return &ReceivingWindow{
		cache: make(map[uint32]*DataSegment),
	}
}

// Set stores a segment with the given ID.
func (w *ReceivingWindow) Set(id uint32, value *DataSegment) bool {
	_, f := w.cache[id]
	if f {
		return false
	}
	w.cache[id] = value
	return true
}

// Has checks if a segment with the given ID exists.
func (w *ReceivingWindow) Has(id uint32) bool {
	_, f := w.cache[id]
	return f
}

// Remove removes and returns the segment with the given ID.
func (w *ReceivingWindow) Remove(id uint32) *DataSegment {
	v, f := w.cache[id]
	if !f {
		return nil
	}
	delete(w.cache, id)
	return v
}

// AckList manages acknowledgments to be sent.
type AckList struct {
	writer     SegmentWriter
	timestamps []uint32
	numbers    []uint32
	nextFlush  []uint32

	flushCandidates []uint32
	dirty           bool
}

// NewAckList creates a new AckList.
func NewAckList(writer SegmentWriter) *AckList {
	return &AckList{
		writer:          writer,
		timestamps:      make([]uint32, 0, 128),
		numbers:         make([]uint32, 0, 128),
		nextFlush:       make([]uint32, 0, 128),
		flushCandidates: make([]uint32, 0, 128),
	}
}

// Add adds an acknowledgment to the list.
func (l *AckList) Add(number uint32, timestamp uint32) {
	l.timestamps = append(l.timestamps, timestamp)
	l.numbers = append(l.numbers, number)
	l.nextFlush = append(l.nextFlush, 0)
	l.dirty = true
}

// Clear removes all acknowledgments with numbers less than una.
func (l *AckList) Clear(una uint32) {
	count := 0
	for i := 0; i < len(l.numbers); i++ {
		if l.numbers[i] < una {
			continue
		}
		if i != count {
			l.numbers[count] = l.numbers[i]
			l.timestamps[count] = l.timestamps[i]
			l.nextFlush[count] = l.nextFlush[i]
		}
		count++
	}
	if count < len(l.numbers) {
		l.numbers = l.numbers[:count]
		l.timestamps = l.timestamps[:count]
		l.nextFlush = l.nextFlush[:count]
		l.dirty = true
	}
}

// Flush sends pending acknowledgments.
func (l *AckList) Flush(current uint32, rto uint32) {
	l.flushCandidates = l.flushCandidates[:0]

	seg := NewAckSegment()
	for i := 0; i < len(l.numbers); i++ {
		if l.nextFlush[i] > current {
			if len(l.flushCandidates) < cap(l.flushCandidates) {
				l.flushCandidates = append(l.flushCandidates, l.numbers[i])
			}
			continue
		}
		seg.PutNumber(l.numbers[i])
		seg.PutTimestamp(l.timestamps[i])
		timeout := rto / 2
		if timeout < 20 {
			timeout = 20
		}
		l.nextFlush[i] = current + timeout

		if seg.IsFull() {
			l.writer.Write(seg)
			seg.Release()
			seg = NewAckSegment()
			l.dirty = false
		}
	}

	if l.dirty || !seg.IsEmpty() {
		for _, number := range l.flushCandidates {
			if seg.IsFull() {
				break
			}
			seg.PutNumber(number)
		}
		l.writer.Write(seg)
		l.dirty = false
	}

	seg.Release()
}

// ReceivingWorker handles receiving data segments.
type ReceivingWorker struct {
	sync.RWMutex
	conn       *Connection
	leftOver   buf.MultiBuffer
	window     *ReceivingWindow
	acklist    *AckList
	nextNumber uint32
	windowSize uint32
}

// NewReceivingWorker creates a new ReceivingWorker.
func NewReceivingWorker(kcp *Connection) *ReceivingWorker {
	worker := &ReceivingWorker{
		conn:       kcp,
		window:     NewReceivingWindow(),
		windowSize: kcp.Config.GetReceivingInFlightSize(),
	}
	worker.acklist = NewAckList(worker)
	return worker
}

// Release releases the receiving worker resources.
func (w *ReceivingWorker) Release() {
	w.Lock()
	buf.ReleaseMulti(w.leftOver)
	w.leftOver = nil
	w.Unlock()
}

// ProcessSendingNext processes the sending next number.
func (w *ReceivingWorker) ProcessSendingNext(number uint32) {
	w.Lock()
	defer w.Unlock()

	w.acklist.Clear(number)
}

// ProcessSegment processes a received data segment.
func (w *ReceivingWorker) ProcessSegment(seg *DataSegment) {
	w.Lock()
	defer w.Unlock()

	number := seg.Number
	idx := number - w.nextNumber
	if idx >= w.windowSize {
		return
	}
	w.acklist.Clear(seg.SendingNext)
	w.acklist.Add(number, seg.Timestamp)

	if !w.window.Set(seg.Number, seg) {
		seg.Release()
	}
}

// ReadMultiBuffer reads available data as a MultiBuffer.
func (w *ReceivingWorker) ReadMultiBuffer() buf.MultiBuffer {
	if w.leftOver != nil {
		mb := w.leftOver
		w.leftOver = nil
		return mb
	}

	mb := make(buf.MultiBuffer, 0, 32)

	w.Lock()
	defer w.Unlock()
	for {
		seg := w.window.Remove(w.nextNumber)
		if seg == nil {
			break
		}
		w.nextNumber++
		mb = append(mb, seg.Detach())
		seg.Release()
	}

	return mb
}

// Read reads data into the provided byte slice.
func (w *ReceivingWorker) Read(b []byte) int {
	mb := w.ReadMultiBuffer()
	if mb.IsEmpty() {
		return 0
	}
	mb, nBytes := buf.SplitBytes(mb, b)
	if !mb.IsEmpty() {
		w.leftOver = mb
	}
	return nBytes
}

// IsDataAvailable checks if data is available for reading.
func (w *ReceivingWorker) IsDataAvailable() bool {
	w.RLock()
	defer w.RUnlock()
	return w.window.Has(w.nextNumber)
}

// NextNumber returns the next expected sequence number.
func (w *ReceivingWorker) NextNumber() uint32 {
	w.RLock()
	defer w.RUnlock()

	return w.nextNumber
}

// Flush sends pending acknowledgments.
func (w *ReceivingWorker) Flush(current uint32) {
	w.Lock()
	defer w.Unlock()

	w.acklist.Flush(current, w.conn.roundTrip.Timeout())
}

// Write sends an ACK segment.
func (w *ReceivingWorker) Write(seg Segment) error {
	ackSeg := seg.(*AckSegment)
	ackSeg.Conv = w.conn.meta.Conversation
	ackSeg.ReceivingNext = w.nextNumber
	ackSeg.ReceivingWindow = w.nextNumber + w.windowSize
	ackSeg.Option = 0
	if w.conn.State() == StateReadyToClose {
		ackSeg.Option = SegmentOptionClose
	}
	return w.conn.output.Write(ackSeg)
}

// CloseRead closes reading.
func (*ReceivingWorker) CloseRead() {
}

// UpdateNecessary returns true if an update is needed.
func (w *ReceivingWorker) UpdateNecessary() bool {
	w.RLock()
	defer w.RUnlock()

	return len(w.acklist.numbers) > 0
}
