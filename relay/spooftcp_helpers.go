package relay

import (
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
