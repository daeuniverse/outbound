package shadowsocks

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	disk_bloom "github.com/mzz2017/disk-bloom"
)

type UdpConn struct {
	netproxy.PacketConn

	proxyAddress string

	metadata   protocol.Metadata
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	bloom      *disk_bloom.FilterGroup
	sg         SaltGenerator

	tgtAddr string
}

func NewUdpConn(conn netproxy.PacketConn, proxyAddress string, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	sg, err := GetSaltGenerator(masterKey, conf.SaltLen)
	if err != nil {
		return nil, err
	}
	c := &UdpConn{
		PacketConn:   conn,
		proxyAddress: proxyAddress,
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    key,
		bloom:        bloom,
		sg:           sg,
		tgtAddr:      net.JoinHostPort(metadata.Hostname, strconv.Itoa(int(metadata.Port))),
	}
	return c, nil
}

func (c *UdpConn) Close() error {
	return c.PacketConn.Close()
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	if err != nil {
		return 0, err
	}
	return c.WriteTo(b, c.tgtAddr)
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	metadata := Metadata{
		Metadata: c.metadata,
	}
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type
	prefix, err := metadata.BytesFromPool()
	if err != nil {
		return 0, err
	}
	defer pool.Put(prefix)
	chunk := pool.Get(len(prefix) + len(b))
	defer pool.Put(chunk)
	copy(chunk, prefix)
	copy(chunk[len(prefix):], b)
	salt := c.sg.Get()
	toWrite, err := EncryptUDPFromPool(&Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}, chunk, salt, ciphers.ShadowsocksReusedInfo)
	pool.Put(salt)
	if err != nil {
		return 0, err
	}
	defer pool.Put(toWrite)
	if c.bloom != nil {
		c.bloom.ExistOrAdd(toWrite[:c.cipherConf.SaltLen])
	}
	return c.PacketConn.WriteTo(toWrite, c.proxyAddress)
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	enc := pool.Get(len(b) + c.cipherConf.SaltLen)
	defer pool.Put(enc)
	n, addr, err = c.PacketConn.ReadFrom(enc)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n, err = DecryptUDP(b, &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}, enc[:n], ciphers.ShadowsocksReusedInfo)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(enc[:c.cipherConf.SaltLen]); exist {
			err = protocol.ErrReplayAttack
			return
		}
	}
	// parse sAddr from metadata
	sizeMetadata, err := BytesSizeForMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	mdata, err := NewMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	var typ protocol.MetadataType
	switch typ {
	case protocol.MetadataTypeIPv4, protocol.MetadataTypeIPv6:
		ip, err := netip.ParseAddr(mdata.Hostname)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrPortFrom(ip, mdata.Port)
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", typ)
	}
	copy(b, b[sizeMetadata:])
	n -= sizeMetadata
	return n, addr, nil
}
