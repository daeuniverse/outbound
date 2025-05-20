package anytls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
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

var (
	_ netproxy.Conn       = (*anytlsConn)(nil)
	_ netproxy.PacketConn = (*anytlsConn)(nil)
)

type anytlsConn struct {
	netproxy.Conn
	metadata   protocol.Metadata
	writeMutex sync.Mutex
	readMutex  sync.Mutex

	readBuf bytes.Buffer
	addr    netip.AddrPort

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
	case cmdFIN:
		return 0, c.Conn.Close()
	default:
		return 0, fmt.Errorf("invalid cmd: %d", header.Cmd())
	}
}

func (c *anytlsConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	data := pool.Get(2 + len(p))
	defer pool.Put(data)
	n, err := c.Read(data)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	copy(p, data[2:n])
	return n, c.addr, nil
}

func (c *anytlsConn) WriteTo(p []byte, addr string) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return 0, err
	}
	data := pool.Get(1 + len(tgtAddr) + 2 + len(p))
	defer pool.Put(data)
	data[0] = 1
	copy(data[1:], tgtAddr)
	binary.BigEndian.PutUint16(data[1+len(tgtAddr):], uint16(len(p)))
	copy(data[1+len(tgtAddr)+2:], p)

	frame := newFrame(cmdPSH, c.sid)
	frame.data = data
	if _, err := writeFrame(c.Conn, frame); err != nil {
		return 0, err
	}
	c.addr = netip.MustParseAddrPort(addr)
	return len(p), nil
}
