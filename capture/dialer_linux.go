//go:build linux

package capture

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Mark is the fwmark stamped on the sidecar's own outbound sockets in capture
// mode. The init container's nat chain RETURNs traffic carrying it, so the
// sidecar's upstream dials are not redirected back into itself.
const Mark = 0x1e1

// MarkedDialer returns a Dialer that stamps SO_MARK on every socket before
// connect, exempting the sidecar's egress from the capture redirect.
func MarkedDialer(mark int) *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}); err != nil {
				return err
			}
			return serr
		},
	}
}
