package tls

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

func parseRange(str string) (min, max int64, err error) {
	stringArr := strings.Split(str, "-")
	if len(stringArr) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	min, err = strconv.ParseInt(stringArr[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseInt(stringArr[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return min, max, nil
}

type FragmentConn struct {
	rawConn     netproxy.Conn
	maxLength   int64
	minLength   int64
	maxInterval int64
	minInterval int64
}

func NewFragmentConn(rawConn netproxy.Conn, minLength, maxLength, minInterval, maxInterval int64) *FragmentConn {
	return &FragmentConn{
		rawConn:     rawConn,
		maxLength:   maxLength,
		minLength:   minLength,
		maxInterval: maxInterval,
		minInterval: minInterval,
	}
}

func (f *FragmentConn) Read(b []byte) (n int, err error) {
	return f.rawConn.Read(b)
}

func (f *FragmentConn) Write(b []byte) (n int, err error) {
	if len(b) <= 5 || b[0] != 22 {
		return f.rawConn.Write(b)
	}
	recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
	if len(b) < recordLen {
		return f.rawConn.Write(b)
	}
	data := b[5:recordLen]
	buf := make([]byte, 1024)
	var hello []byte
	for from := 0; ; {
		to := common.Min(len(data), from+int(randBetween(f.minLength, f.maxLength)))
		copy(buf[:3], b)
		copy(buf[5:], data[from:to])
		l := to - from
		from = to
		buf[3] = byte(l >> 8)
		buf[4] = byte(l)
		if f.maxInterval == 0 {
			hello = append(hello, buf[:5+l]...)
		} else {
			if _, err := f.rawConn.Write(buf[:5+l]); err != nil {
				return 0, err
			}
			time.Sleep(time.Duration(randBetween(f.minInterval, f.maxInterval)) * time.Millisecond)
		}
		if from == len(data) {
			break
		}
	}
	if len(hello) > 0 {
		if _, err := f.rawConn.Write(hello); err != nil {
			return 0, err
		}
	}
	if len(b) > recordLen {
		if _, err := f.rawConn.Write(b[recordLen:]); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (f *FragmentConn) Close() error {
	return f.rawConn.Close()
}

func (f *FragmentConn) SetDeadline(t time.Time) error {
	return f.rawConn.SetDeadline(t)
}

func (f *FragmentConn) SetReadDeadline(t time.Time) error {
	return f.rawConn.SetReadDeadline(t)
}

func (f *FragmentConn) SetWriteDeadline(t time.Time) error {
	return f.rawConn.SetWriteDeadline(t)
}
