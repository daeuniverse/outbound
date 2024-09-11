// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
package vision

import (
	"bytes"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewConn(conn netproxy.Conn, userUUID []byte) (*Conn, error) {
	c := &Conn{
		overlayConn:                conn,
		userUUID:                   userUUID,
		packetsToFilter:            6,
		needHandshake:              true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	c.writer = &writeWrapper{
		vision: c,
	}
	c.reader = &readWrapper{
		vision: c,
	}
	var t reflect.Type
	var p unsafe.Pointer
	if iconn, ok := conn.(interface{ IntrinsicConn() netproxy.Conn }); ok {
		ic := iconn.IntrinsicConn()
		if tlsConn, ok := ic.(*gotls.Conn); ok {
			c.Conn = tlsConn.NetConn()
			c.tlsConn = tlsConn
			t = reflect.TypeOf(tlsConn).Elem()
			p = unsafe.Pointer(tlsConn)
		} else if utlsConn, ok := ic.(*utls.UConn); ok {
			c.Conn = utlsConn.NetConn()
			c.tlsConn = utlsConn
			t = reflect.TypeOf(utlsConn.Conn).Elem()
			p = unsafe.Pointer(utlsConn.Conn)
		} else if realityConn, ok := ic.(*tls.RealityUConn); ok {
			// logrus.Infoln("realityConn")
			c.Conn = realityConn.NetConn()
			c.tlsConn = realityConn.UConn
			t = reflect.TypeOf(realityConn.Conn).Elem()
			p = unsafe.Pointer(realityConn.Conn)
		} else {
			return nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", ic)
		}
	} else {
		return nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", conn)
	}
	i, _ := t.FieldByName("input")
	r, _ := t.FieldByName("rawInput")
	c.input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
	c.rawInput = (*bytes.Buffer)(unsafe.Add(p, r.Offset))
	return c, nil
}
