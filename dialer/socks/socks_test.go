/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package socks

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/softwind/protocol/direct"
	dnsmessage "github.com/miekg/dns"
)

func TestSocks5(t *testing.T) {
	c, err := ParseSocksURL("socks5://192.168.31.6:1081")
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := c.Dialer(&dialer.ExtraOption{
		AllowInsecure:     false,
		TlsImplementation: "",
		UtlsImitate:       "",
	}, direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := netutils.ResolveNetip(ctx, d, netip.MustParseAddrPort("8.8.8.8:53"), "apple.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(addrs)
}
