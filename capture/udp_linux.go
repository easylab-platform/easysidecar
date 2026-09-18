//go:build linux

package capture

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// This file implements transparent interception of UDP datagrams that were
// DNAT'd to the sidecar. Unlike TCP, the original destination of a datagram is
// not a socket property: it arrives in an IP_RECVORIGDSTADDR control message.
// We therefore:
//
//   - set IP_RECVORIGDSTADDR (and the v6 equivalent) on the listener socket, and
//   - parse the destination out of the control message of every ReadMsgUDP.

// EnableOrigDst asks the kernel to deliver the pre-NAT destination of each
// datagram as a control message on the socket.
func EnableOrigDst(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if cerr := raw.Control(func(fd uintptr) {
		opErr = enableOrigDstFD(fd)
	}); cerr != nil {
		return cerr
	}
	return opErr
}

func enableOrigDstFD(fd uintptr) error {
	one := 1
	if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, one); err == nil {
		return nil
	}
	// Dual-stack sockets need the v6 option; a v4-only socket may reject it.
	if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, one); err == nil {
		return nil
	}
	return fmt.Errorf("IP_RECVORIGDSTADDR unsupported")
}

// ParseOrigDst extracts the destination address from a datagram's control
// messages (as returned by ReadMsgUDP). ok is false when no
// original-destination message was present, in which case the caller should
// fall back to the socket's local address.
func ParseOrigDst(oob []byte) (ip net.IP, port int, ok bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0, false
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR:
			ip, port, err = parseSockaddr(m.Data)
			return ip, port, err == nil
		case m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR:
			ip, port, err = parseSockaddr(m.Data)
			return ip, port, err == nil
		}
	}
	return nil, 0, false
}

// OrigDstOOBSize is the control-buffer size for ReadMsgUDP: two cmsgs
// (orig-dst + pktinfo) fit comfortably.
const OrigDstOOBSize = 128

// SetMark stamps SO_MARK on a socket so every datagram it sends carries the
// mark. The nat chain RETURNs marked traffic, which keeps the sidecar's own
// UDP (DNS replies, forwarded queries, relayed replies) out of the capture
// redirect. mark == 0 is a no-op.
func SetMark(c *net.UDPConn, mark int) error {
	if mark == 0 {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if cerr := raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
	}); cerr != nil {
		return cerr
	}
	return opErr
}
