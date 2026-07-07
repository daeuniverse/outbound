// Package mkcp provides mKCP transport implementation.
// mKCP is a KCP (A Fast and Reliable ARQ Protocol) based transport.
//
// Acknowledgement:
//   - skywind3000@github for inventing the KCP protocol
//   - xtaci@github for translating to Golang
//   - v2fly/v2ray-core for the reference implementation
package mkcp

import (
	"crypto/cipher"
)

// Config contains mKCP configuration parameters.
type Config struct {
	// MTU is the Maximum Transmission Unit. Default is 1350.
	MTU uint32
	// TTI is Transmission Time Interval in milliseconds. Default is 50.
	TTI uint32
	// UplinkCapacity is the uplink capacity in MB/s. Default is 5.
	UplinkCapacity uint32
	// DownlinkCapacity is the downlink capacity in MB/s. Default is 20.
	DownlinkCapacity uint32
	// WriteBufferSize is the write buffer size in bytes. Default is 2MB.
	WriteBufferSize uint32
	// ReadBufferSize is the read buffer size in bytes. Default is 2MB.
	ReadBufferSize uint32
	// Congestion enables congestion control. Default is false.
	Congestion bool
	// Seed is the encryption seed. If empty, uses SimpleAuthenticator.
	Seed string
}

// DefaultConfig returns a default mKCP configuration.
func DefaultConfig() *Config {
	return &Config{
		MTU:              1350,
		TTI:              50,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		WriteBufferSize:  2 * 1024 * 1024,
		ReadBufferSize:   2 * 1024 * 1024,
		Congestion:       false,
		Seed:             "",
	}
}

// GetMTUValue returns the value of MTU settings.
func (c *Config) GetMTUValue() uint32 {
	if c == nil || c.MTU == 0 {
		return 1350
	}
	return c.MTU
}

// GetTTIValue returns the value of TTI settings.
func (c *Config) GetTTIValue() uint32 {
	if c == nil || c.TTI == 0 {
		return 50
	}
	return c.TTI
}

// GetUplinkCapacityValue returns the value of UplinkCapacity settings.
func (c *Config) GetUplinkCapacityValue() uint32 {
	if c == nil || c.UplinkCapacity == 0 {
		return 5
	}
	return c.UplinkCapacity
}

// GetDownlinkCapacityValue returns the value of DownlinkCapacity settings.
func (c *Config) GetDownlinkCapacityValue() uint32 {
	if c == nil || c.DownlinkCapacity == 0 {
		return 20
	}
	return c.DownlinkCapacity
}

// GetWriteBufferSize returns the size of WriteBuffer in bytes.
func (c *Config) GetWriteBufferSize() uint32 {
	if c == nil || c.WriteBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.WriteBufferSize
}

// GetReadBufferSize returns the size of ReadBuffer in bytes.
func (c *Config) GetReadBufferSize() uint32 {
	if c == nil || c.ReadBufferSize == 0 {
		return 2 * 1024 * 1024
	}
	return c.ReadBufferSize
}

// GetSecurity returns the security AEAD cipher.
func (c *Config) GetSecurity() (cipher.AEAD, error) {
	if c != nil && c.Seed != "" {
		return NewAEADAESGCMBasedOnSeed(c.Seed), nil
	}
	return NewSimpleAuthenticator(), nil
}

// GetSendingInFlightSize calculates the sending in-flight window size.
func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.GetUplinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

// GetSendingBufferSize calculates the sending buffer size in segments.
func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

// GetReceivingInFlightSize calculates the receiving in-flight window size.
func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.GetDownlinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

// GetReceivingBufferSize calculates the receiving buffer size in segments.
func (c *Config) GetReceivingBufferSize() uint32 {
	return c.GetReadBufferSize() / c.GetMTUValue()
}
