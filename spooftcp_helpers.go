package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
)

// classifyHost determines the hostname for a connection: SNI for TLS, Host
// header for plain HTTP, "" otherwise. The peeked bytes stay buffered for
// replay.
func classifyHost(c net.Conn) (host string, tr *tlsReader, err error) {
	tr = newTLSReader(c)
	h, ok, lerr := tr.sni()
	if lerr == nil && ok {
		return strings.TrimSuffix(h, "."), tr, nil
	}
	if lerr == nil && !ok {
		return "", tr, nil // valid TLS without SNI
	}
	if lerr == errNotTLS {
		h := peekHTTPHost(tr)
		return h, tr, nil
	}
	return "", tr, lerr
}

// peekHTTPHost scans the buffered bytes for a Host header.
func peekHTTPHost(tr *tlsReader) string {
	s := string(tr.buffered())
	i := strings.Index(strings.ToLower(s), "\r\nhost:")
	if i < 0 {
		i = strings.Index(strings.ToLower(s), "\nhost:")
		if i < 0 {
			return ""
		}
	}
	rest := s[i+6:]
	j := strings.IndexAny(rest, "\r\n")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// dnsHeader helpers: read/patch the flag word of a raw DNS message.
func binaryFlags(msg []byte) uint16 {
	if len(msg) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(msg[2:4])
}

// ioEOF keeps the io import used by relay-style helpers.
var _ = io.EOF
