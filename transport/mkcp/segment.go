package mkcp

import (
	"encoding/binary"

	"github.com/daeuniverse/outbound/common/buf"
)

// Command is a KCP command that indicates the purpose of a Segment.
type Command byte

const (
	// CommandACK indicates an AckSegment.
	CommandACK Command = 0
	// CommandData indicates a DataSegment.
	CommandData Command = 1
	// CommandTerminate indicates that peer terminates the connection.
	CommandTerminate Command = 2
	// CommandPing indicates a ping.
	CommandPing Command = 3
)

// SegmentOption represents options for a segment.
type SegmentOption byte

const (
	// SegmentOptionClose indicates the connection should be closed.
	SegmentOptionClose SegmentOption = 1
)

// Segment is the interface for KCP protocol segments.
type Segment interface {
	Release()
	Conversation() uint16
	Command() Command
	ByteSize() int32
	Serialize([]byte)
	parse(conv uint16, cmd Command, opt SegmentOption, buf []byte) (bool, []byte)
}

const (
	// DataSegmentOverhead is the overhead of a data segment header.
	DataSegmentOverhead = 18
)

// DataSegment represents a data segment in KCP protocol.
type DataSegment struct {
	Conv        uint16
	Option      SegmentOption
	Timestamp   uint32
	Number      uint32
	SendingNext uint32

	payload  *buf.Buffer
	timeout  uint32
	transmit uint32
}

// NewDataSegment creates a new DataSegment.
func NewDataSegment() *DataSegment {
	return new(DataSegment)
}

func (s *DataSegment) parse(conv uint16, cmd Command, opt SegmentOption, buf []byte) (bool, []byte) {
	s.Conv = conv
	s.Option = opt
	if len(buf) < 15 {
		return false, nil
	}
	s.Timestamp = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.Number = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.SendingNext = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	dataLen := int(binary.BigEndian.Uint16(buf))
	buf = buf[2:]

	if len(buf) < dataLen {
		return false, nil
	}
	s.Data().Clear()
	s.Data().Write(buf[:dataLen])
	buf = buf[dataLen:]

	return true, buf
}

// Conversation returns the conversation ID.
func (s *DataSegment) Conversation() uint16 {
	return s.Conv
}

// Command returns the segment command.
func (*DataSegment) Command() Command {
	return CommandData
}

// Detach detaches and returns the payload buffer.
func (s *DataSegment) Detach() *buf.Buffer {
	r := s.payload
	s.payload = nil
	return r
}

// Data returns the payload buffer, creating one if needed.
func (s *DataSegment) Data() *buf.Buffer {
	if s.payload == nil {
		s.payload = buf.New()
	}
	return s.payload
}

// Serialize writes the segment to a byte slice.
func (s *DataSegment) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, s.Conv)
	b[2] = byte(CommandData)
	b[3] = byte(s.Option)
	binary.BigEndian.PutUint32(b[4:], s.Timestamp)
	binary.BigEndian.PutUint32(b[8:], s.Number)
	binary.BigEndian.PutUint32(b[12:], s.SendingNext)
	binary.BigEndian.PutUint16(b[16:], uint16(s.payload.Len()))
	copy(b[18:], s.payload.Bytes())
}

// ByteSize returns the size of the segment in bytes.
func (s *DataSegment) ByteSize() int32 {
	return 2 + 1 + 1 + 4 + 4 + 4 + 2 + s.payload.Len()
}

// Release releases the segment resources.
func (s *DataSegment) Release() {
	if s.payload != nil {
		s.payload.Release()
		s.payload = nil
	}
}

// AckSegment represents an acknowledgment segment in KCP protocol.
type AckSegment struct {
	Conv            uint16
	Option          SegmentOption
	ReceivingWindow uint32
	ReceivingNext   uint32
	Timestamp       uint32
	NumberList      []uint32
}

const ackNumberLimit = 128

// NewAckSegment creates a new AckSegment.
func NewAckSegment() *AckSegment {
	return new(AckSegment)
}

func (s *AckSegment) parse(conv uint16, cmd Command, opt SegmentOption, buf []byte) (bool, []byte) {
	s.Conv = conv
	s.Option = opt
	if len(buf) < 13 {
		return false, nil
	}

	s.ReceivingWindow = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.ReceivingNext = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.Timestamp = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	count := int(buf[0])
	buf = buf[1:]

	if len(buf) < count*4 {
		return false, nil
	}
	for i := 0; i < count; i++ {
		s.PutNumber(binary.BigEndian.Uint32(buf))
		buf = buf[4:]
	}

	return true, buf
}

// Conversation returns the conversation ID.
func (s *AckSegment) Conversation() uint16 {
	return s.Conv
}

// Command returns the segment command.
func (*AckSegment) Command() Command {
	return CommandACK
}

// PutTimestamp updates the timestamp if newer.
func (s *AckSegment) PutTimestamp(timestamp uint32) {
	if timestamp-s.Timestamp < 0x7FFFFFFF {
		s.Timestamp = timestamp
	}
}

// PutNumber adds a number to the acknowledgment list.
func (s *AckSegment) PutNumber(number uint32) {
	s.NumberList = append(s.NumberList, number)
}

// IsFull returns true if the acknowledgment list is full.
func (s *AckSegment) IsFull() bool {
	return len(s.NumberList) == ackNumberLimit
}

// IsEmpty returns true if the acknowledgment list is empty.
func (s *AckSegment) IsEmpty() bool {
	return len(s.NumberList) == 0
}

// ByteSize returns the size of the segment in bytes.
func (s *AckSegment) ByteSize() int32 {
	return 2 + 1 + 1 + 4 + 4 + 4 + 1 + int32(len(s.NumberList)*4)
}

// Serialize writes the segment to a byte slice.
func (s *AckSegment) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, s.Conv)
	b[2] = byte(CommandACK)
	b[3] = byte(s.Option)
	binary.BigEndian.PutUint32(b[4:], s.ReceivingWindow)
	binary.BigEndian.PutUint32(b[8:], s.ReceivingNext)
	binary.BigEndian.PutUint32(b[12:], s.Timestamp)
	b[16] = byte(len(s.NumberList))
	n := 17
	for _, number := range s.NumberList {
		binary.BigEndian.PutUint32(b[n:], number)
		n += 4
	}
}

// Release releases the segment resources.
func (s *AckSegment) Release() {}

// CmdOnlySegment represents a command-only segment (ping, terminate).
type CmdOnlySegment struct {
	Conv          uint16
	Cmd           Command
	Option        SegmentOption
	SendingNext   uint32
	ReceivingNext uint32
	PeerRTO       uint32
}

// NewCmdOnlySegment creates a new CmdOnlySegment.
func NewCmdOnlySegment() *CmdOnlySegment {
	return new(CmdOnlySegment)
}

func (s *CmdOnlySegment) parse(conv uint16, cmd Command, opt SegmentOption, buf []byte) (bool, []byte) {
	s.Conv = conv
	s.Cmd = cmd
	s.Option = opt

	if len(buf) < 12 {
		return false, nil
	}

	s.SendingNext = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.ReceivingNext = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	s.PeerRTO = binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	return true, buf
}

// Conversation returns the conversation ID.
func (s *CmdOnlySegment) Conversation() uint16 {
	return s.Conv
}

// Command returns the segment command.
func (s *CmdOnlySegment) Command() Command {
	return s.Cmd
}

// ByteSize returns the size of the segment in bytes.
func (*CmdOnlySegment) ByteSize() int32 {
	return 2 + 1 + 1 + 4 + 4 + 4
}

// Serialize writes the segment to a byte slice.
func (s *CmdOnlySegment) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, s.Conv)
	b[2] = byte(s.Cmd)
	b[3] = byte(s.Option)
	binary.BigEndian.PutUint32(b[4:], s.SendingNext)
	binary.BigEndian.PutUint32(b[8:], s.ReceivingNext)
	binary.BigEndian.PutUint32(b[12:], s.PeerRTO)
}

// Release releases the segment resources.
func (*CmdOnlySegment) Release() {}

// ReadSegment reads a segment from the buffer.
func ReadSegment(buf []byte) (Segment, []byte) {
	if len(buf) < 4 {
		return nil, nil
	}

	conv := binary.BigEndian.Uint16(buf)
	buf = buf[2:]

	cmd := Command(buf[0])
	opt := SegmentOption(buf[1])
	buf = buf[2:]

	var seg Segment
	switch cmd {
	case CommandData:
		seg = NewDataSegment()
	case CommandACK:
		seg = NewAckSegment()
	default:
		seg = NewCmdOnlySegment()
	}

	valid, extra := seg.parse(conv, cmd, opt, buf)
	if !valid {
		return nil, nil
	}
	return seg, extra
}
