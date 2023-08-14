/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/daeuniverse/softwind/netproxy"
)

func Deduplicate(list []string) []string {
	if list == nil {
		return nil
	}
	res := make([]string, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		res = append(res, v)
	}
	return res
}

func Base64UrlDecode(s string) (string, error) {
	s = strings.TrimSpace(s)
	saver := s
	if len(s)%4 > 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return saver, err
	}
	return string(raw), nil
}

func Base64StdDecode(s string) (string, error) {
	s = strings.TrimSpace(s)
	saver := s
	if len(s)%4 > 0 {
		s += strings.Repeat("=", 4-len(s)%4)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return saver, err
	}
	return string(raw), nil
}

func SetValue(values *url.Values, key string, value string) {
	if value == "" {
		return
	}
	values.Set(key, value)
}

func GetTagFromLinkLikePlaintext(link string) (tag string, afterTag string) {
	iColon := strings.Index(link, ":")
	if iColon == -1 {
		return "", link
	}
	// If first colon is like "://" in "scheme://linkbody", no tag is present.
	if strings.HasPrefix(link[iColon:], "://") {
		return "", link
	}
	// Else tag is the part before colon.
	return link[:iColon], link[iColon+1:]
}

func BoolToString(b bool) string {
	if b {
		return "1"
	} else {
		return "0"
	}
}

func MagicNetwork(network string, mark uint32) string {
	if mark == 0 {
		return network
	} else {
		return netproxy.MagicNetwork{
			Network: network,
			Mark:    mark,
		}.Encode()
	}
}

func GenerateCertChainHash(rawCerts [][]byte) (chainHash []byte) {
	for _, cert := range rawCerts {
		certHash := sha256.Sum256(cert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			newHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = newHash[:]
		}
	}
	return chainHash
}
