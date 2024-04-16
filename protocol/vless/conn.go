// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package trojanc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

var (
	FailAuthErr = fmt.Errorf("incorrect UUID")
)

type Conn struct {
	netproxy.Conn
	metadata            vmess.Metadata
	cmdKey              []byte
	cachedProxyAddrIpIP netip.AddrPort

	writeMutex sync.Mutex
	onceWrite  bool
	onceRead   sync.Once
}

func NewConn(conn netproxy.Conn, metadata vmess.Metadata, cmdKey []byte) (c *Conn, err error) {

	// DO NOT use pool here because Close() cannot interrupt the reading or writing, which will modify the value of the pool buffer.
	key := make([]byte, len(cmdKey))
	copy(key, cmdKey)
	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
	}
	if metadata.Network == "udp" {
		proxyAddrIp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
		if err != nil {
			return nil, err
		}
		c.cachedProxyAddrIpIP = proxyAddrIp.AddrPort()
	}
	if metadata.Network == "tcp" && metadata.IsClient {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first
			if _, err = c.Write(nil); err != nil {
				return
			}
		})
	}
	return c, nil
}

func (c *Conn) reqHeaderFromPool(payload []byte) (buf []byte) {
	addrLen := c.metadata.AddrLen()
	buf = pool.Get(1 + 16 + 1 + 1 + 2 + 1 + addrLen + len(payload))
	buf[0] = 0 // version
	copy(buf[1:], c.cmdKey)
	buf[17] = 0                                           // length of addons
	buf[18] = vmess.NetworkToByte(c.metadata.Network)     // inst
	binary.BigEndian.PutUint16(buf[19:], c.metadata.Port) // port
	buf[21] = vmess.MetadataTypeToByte(c.metadata.Type)   // addr type
	c.metadata.PutAddr(buf[22:])
	copy(buf[22+addrLen:], payload)
	return buf
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if !c.onceWrite {
		if c.metadata.IsClient {
			buf := c.reqHeaderFromPool(b)
			defer pool.Put(buf)
			if _, err = c.Conn.Write(buf); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		if c.metadata.IsClient {
			if err = c.ReadRespHeader(); err != nil {
				return
			}
		} else {
			if err = c.ReadReqHeader(); err != nil {
				return
			}
		}
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) ReadReqHeader() (err error) {
	buf := pool.Get(18)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if !bytes.Equal(c.cmdKey[:], buf[1:17]) {
		return FailAuthErr
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[17])); err != nil { // ignore addons
		return err
	}
	buf = pool.Get(4)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if err = CompleteMetadataFromReader(&c.metadata, buf, c.Conn); err != nil {
		return err
	}
	return nil
}

func (c *Conn) ReadRespHeader() (err error) {
	buf := pool.Get(2)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[1])); err != nil {
		return err
	}
	return nil
}
