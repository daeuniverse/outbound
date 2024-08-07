/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package iout

import (
	"io"

	"github.com/daeuniverse/outbound/pool"
)

func MultiWrite(dst io.Writer, bs ...[]byte) (int64, error) {
	var n int
	for _, b := range bs {
		n += len(b)
	}
	buf := pool.Get(n)[:0]
	defer buf.Put()
	for _, b := range bs {
		buf = append(buf, b...)
	}
	n, err := dst.Write(buf)
	return int64(n), err
}
