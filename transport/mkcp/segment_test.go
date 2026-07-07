package mkcp

import (
	"bytes"
	"testing"
)

func TestDataSegmentSerialize(t *testing.T) {
	seg := NewDataSegment()
	seg.Conv = 12345
	seg.Option = 0
	seg.Timestamp = 1000
	seg.Number = 1
	seg.SendingNext = 0

	data := []byte("hello world")
	seg.Data().Write(data)

	buf := make([]byte, seg.ByteSize())
	seg.Serialize(buf)

	// Parse it back
	parsedSeg, remaining := ReadSegment(buf)
	if parsedSeg == nil {
		t.Fatal("failed to parse segment")
	}
	if remaining == nil {
		// OK - consumed entire buffer
	}

	dataSeg, ok := parsedSeg.(*DataSegment)
	if !ok {
		t.Fatalf("expected DataSegment, got %T", parsedSeg)
	}

	if dataSeg.Conv != 12345 {
		t.Errorf("expected Conv 12345, got %d", dataSeg.Conv)
	}

	if dataSeg.Timestamp != 1000 {
		t.Errorf("expected Timestamp 1000, got %d", dataSeg.Timestamp)
	}

	if dataSeg.Number != 1 {
		t.Errorf("expected Number 1, got %d", dataSeg.Number)
	}

	if !bytes.Equal(dataSeg.Data().Bytes(), data) {
		t.Errorf("data mismatch: expected %v, got %v", data, dataSeg.Data().Bytes())
	}

	seg.Release()
	dataSeg.Release()
}

func TestAckSegmentSerialize(t *testing.T) {
	seg := NewAckSegment()
	seg.Conv = 54321
	seg.ReceivingWindow = 100
	seg.ReceivingNext = 5
	seg.Timestamp = 2000
	seg.PutNumber(1)
	seg.PutNumber(2)
	seg.PutNumber(3)

	buf := make([]byte, seg.ByteSize())
	seg.Serialize(buf)

	// Parse it back
	parsedSeg, remaining := ReadSegment(buf)
	if parsedSeg == nil {
		t.Fatal("failed to parse segment")
	}
	if remaining == nil {
		// OK
	}

	ackSeg, ok := parsedSeg.(*AckSegment)
	if !ok {
		t.Fatalf("expected AckSegment, got %T", parsedSeg)
	}

	if ackSeg.Conv != 54321 {
		t.Errorf("expected Conv 54321, got %d", ackSeg.Conv)
	}

	if ackSeg.ReceivingWindow != 100 {
		t.Errorf("expected ReceivingWindow 100, got %d", ackSeg.ReceivingWindow)
	}

	if ackSeg.ReceivingNext != 5 {
		t.Errorf("expected ReceivingNext 5, got %d", ackSeg.ReceivingNext)
	}

	if len(ackSeg.NumberList) != 3 {
		t.Errorf("expected 3 numbers, got %d", len(ackSeg.NumberList))
	}

	seg.Release()
	ackSeg.Release()
}

func TestCmdOnlySegmentSerialize(t *testing.T) {
	seg := NewCmdOnlySegment()
	seg.Conv = 11111
	seg.Cmd = CommandPing
	seg.Option = SegmentOptionClose
	seg.SendingNext = 10
	seg.ReceivingNext = 20
	seg.PeerRTO = 100

	buf := make([]byte, seg.ByteSize())
	seg.Serialize(buf)

	// Parse it back
	parsedSeg, _ := ReadSegment(buf)
	if parsedSeg == nil {
		t.Fatal("failed to parse segment")
	}

	cmdSeg, ok := parsedSeg.(*CmdOnlySegment)
	if !ok {
		t.Fatalf("expected CmdOnlySegment, got %T", parsedSeg)
	}

	if cmdSeg.Conv != 11111 {
		t.Errorf("expected Conv 11111, got %d", cmdSeg.Conv)
	}

	if cmdSeg.Cmd != CommandPing {
		t.Errorf("expected CommandPing, got %d", cmdSeg.Cmd)
	}

	if cmdSeg.Option != SegmentOptionClose {
		t.Errorf("expected SegmentOptionClose, got %d", cmdSeg.Option)
	}

	seg.Release()
	cmdSeg.Release()
}
