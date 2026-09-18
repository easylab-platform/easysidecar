package relay

import (
	"net"

	"github.com/easylab-platform/easysidecar/rule"
)

// firstMatch returns the first match pattern of a decision for logging
// ("" when the default action applied).
func firstMatch(dec rule.Decision) string {
	if dec.Rule == nil || len(dec.Rule.Match) == 0 {
		return ""
	}
	return dec.Rule.Match[0]
}

// resetConn aborts a connection with RST instead of a graceful FIN.
func resetConn(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}
