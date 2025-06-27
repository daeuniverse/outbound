package anytls

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn netproxy.Conn

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	seq    uint64
	sid    atomic.Uint32
	closed atomic.Bool
}

func newSession(conn netproxy.Conn, seq uint64) *session {
	return &session{
		conn:    conn,
		streams: map[uint32]*stream{},
		seq:     seq,
	}
}

func (s *session) newStream(addr string) (*stream, error) {
	s.sid.Add(1)
	sid := s.sid.Load()

	frame := newFrame(cmdSettings, sid)
	frame.data = settingsBytes
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}

	frame = newFrame(cmdSYN, sid)
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	frame = newFrame(cmdPSH, sid)
	frame.data = tgtAddr
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}

	stream := newStream(s, sid)
	s.streamLock.Lock()
	s.streams[sid] = stream
	s.streamLock.Unlock()

	return stream, nil
}

func (s *session) newPacketStream(addr, packetAddr string) (*packetStream, error) {
	stream, err := s.newStream(addr)
	if err != nil {
		return nil, err
	}
	return &packetStream{
		stream: stream,
		addr:   packetAddr,
	}, nil
}

func (s *session) removeStream(sid uint32) {
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
}

func (s *session) run(streamClosed chan uint64, sessionClosed chan struct{}) error {
	defer func() {
		sessionClosed <- struct{}{}
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
		}
	}()
	defer s.Close()

	var header rawHeader
	for {
		if s.Closed() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		switch header.Cmd() {
		case cmdWaste:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				if _, err := stream.pw.Write(buf); err != nil {
					pool.Put(buf)
					return err
				}
			}
			pool.Put(buf)
		case cmdPSH:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				if _, err := stream.pw.Write(buf); err != nil {
					pool.Put(buf)
					return err
				}
			}
			pool.Put(buf)
		case cmdAlert:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.Put(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				stream.remoteClose()
				streamClosed <- s.seq
			}
		default:
			return fmt.Errorf("invalid cmd: %d", header.Cmd())
		}
	}
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.streamLock.Lock()
		defer s.streamLock.Unlock()
		for i := range s.streams {
			delete(s.streams, i)
		}
		s.streams = make(map[uint32]*stream)
		return s.conn.Close()
	}
	return nil
}

func (s *session) Closed() bool {
	return s.closed.Load()
}
