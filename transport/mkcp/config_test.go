package mkcp

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.GetMTUValue() != 1350 {
		t.Errorf("expected MTU 1350, got %d", config.GetMTUValue())
	}

	if config.GetTTIValue() != 50 {
		t.Errorf("expected TTI 50, got %d", config.GetTTIValue())
	}

	if config.GetUplinkCapacityValue() != 5 {
		t.Errorf("expected UplinkCapacity 5, got %d", config.GetUplinkCapacityValue())
	}

	if config.GetDownlinkCapacityValue() != 20 {
		t.Errorf("expected DownlinkCapacity 20, got %d", config.GetDownlinkCapacityValue())
	}

	if config.GetWriteBufferSize() != 2*1024*1024 {
		t.Errorf("expected WriteBufferSize 2MB, got %d", config.GetWriteBufferSize())
	}

	if config.GetReadBufferSize() != 2*1024*1024 {
		t.Errorf("expected ReadBufferSize 2MB, got %d", config.GetReadBufferSize())
	}
}

func TestConfigWithCustomValues(t *testing.T) {
	config := &Config{
		MTU:              1400,
		TTI:              20,
		UplinkCapacity:   10,
		DownlinkCapacity: 50,
		WriteBufferSize:  4 * 1024 * 1024,
		ReadBufferSize:   4 * 1024 * 1024,
		Congestion:       true,
		Seed:             "test-seed",
	}

	if config.GetMTUValue() != 1400 {
		t.Errorf("expected MTU 1400, got %d", config.GetMTUValue())
	}

	if config.GetTTIValue() != 20 {
		t.Errorf("expected TTI 20, got %d", config.GetTTIValue())
	}

	if config.GetUplinkCapacityValue() != 10 {
		t.Errorf("expected UplinkCapacity 10, got %d", config.GetUplinkCapacityValue())
	}

	if config.GetDownlinkCapacityValue() != 50 {
		t.Errorf("expected DownlinkCapacity 50, got %d", config.GetDownlinkCapacityValue())
	}
}

func TestGetSendingInFlightSize(t *testing.T) {
	config := DefaultConfig()
	size := config.GetSendingInFlightSize()
	if size < 8 {
		t.Errorf("expected at least 8, got %d", size)
	}
}

func TestGetReceivingInFlightSize(t *testing.T) {
	config := DefaultConfig()
	size := config.GetReceivingInFlightSize()
	if size < 8 {
		t.Errorf("expected at least 8, got %d", size)
	}
}
