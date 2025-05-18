package anytls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

const ( // cmds
	cmdWaste               = iota // Paddings
	cmdSYN                        // stream open
	cmdPSH                        // data push
	cmdFIN                        // stream close, a.k.a EOF mark
	cmdSettings                   // Settings (Client send to Server)
	cmdAlert                      // Alert
	cmdUpdatePaddingScheme        // update padding scheme
	// Since version 2
	cmdSYNACK         // Server reports to the client that the stream has been opened
	cmdHeartRequest   // Keep alive command
	cmdHeartResponse  // Keep alive command
	cmdServerSettings // Settings (Server send to client)
)

const (
	headerOverHeadSize = 1 + 4 + 2
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}

func writeFrame(conn io.Writer, frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := pool.Get(dataLen + headerOverHeadSize)
	defer pool.Put(buffer)

	buffer[0] = frame.cmd
	binary.BigEndian.PutUint32(buffer[1:], frame.sid)
	binary.BigEndian.PutUint16(buffer[5:], uint16(dataLen))
	copy(buffer[7:], frame.data)
	_, err := conn.Write(buffer)
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

var _ netproxy.Conn = (*anytlsConn)(nil)

type anytlsConn struct {
	netproxy.Conn
	metadata   protocol.Metadata
	writeMutex sync.Mutex
	readMutex  sync.Mutex

	readBuf bytes.Buffer

	sid uint32
}

func (d *Dialer) newAnytlsConn(conn netproxy.Conn, metadata protocol.Metadata) (netproxy.Conn, error) {
	password := d.key
	b := make([]byte, len(password)+2)
	copy(b, password)
	binary.BigEndian.PutUint16(b[len(password):], uint16(0))
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	frame := newFrame(cmdSettings, d.sid.Load())
	frame.data = settingsBytes
	if _, err := writeFrame(conn, frame); err != nil {
		return nil, err
	}
	d.sid.Add(1)

	frame = newFrame(cmdSYN, d.sid.Load())
	if _, err := writeFrame(conn, frame); err != nil {
		return nil, err
	}

	tgtAddr, err := socks.ParseAddr(metadata.Hostname + ":" + strconv.Itoa(int(metadata.Port)))
	if err != nil {
		return nil, err
	}
	frame = newFrame(cmdPSH, d.sid.Load())
	frame.data = tgtAddr
	if _, err := writeFrame(conn, frame); err != nil {
		return nil, err
	}

	return &anytlsConn{Conn: conn, metadata: metadata, sid: d.sid.Load()}, nil
}

func (c *anytlsConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	frame := newFrame(cmdPSH, c.sid)
	frame.data = b
	return writeFrame(c.Conn, frame)
}

func (c *anytlsConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	var header rawHeader
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	switch header.Cmd() {
	case cmdWaste:
		buf := pool.Get(int(header.Length()))
		defer pool.Put(buf)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		return 0, nil
	case cmdPSH:
		buf := pool.Get(int(header.Length()))
		defer pool.Put(buf)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		c.readBuf.Write(buf)
		return c.readBuf.Read(b)
	case cmdAlert:
		buf := pool.Get(int(header.Length()))
		defer pool.Put(buf)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		slog.Error("[Alert from server]", "msg", string(buf))
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid cmd: %d", header.Cmd())
	}
}
