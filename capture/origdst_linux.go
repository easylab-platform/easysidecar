//go:build linux

// Package capture implements privileged transparent interception: the
// iptables rules an init container installs (REDIRECT all TCP to the sidecar)
// and the SO_ORIGINAL_DST lookup that recovers the destination a redirected
// connection was really addressed to.
package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soOriginalDst is the getsockopt option (value 80 for both IP and IPv6) that
// returns the pre-NAT destination of a REDIRECTed socket.
const soOriginalDst = 80

// OriginalDst recovers the destination address a redirected TCP connection was
// originally sent to. It is only meaningful for sockets accepted on a
// REDIRECTed port; on a normal socket it returns the local address.
func OriginalDst(c *net.TCPConn) (ip net.IP, port int, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var (
		gotIP   net.IP
		gotPort int
		opErr   error
	)
	cerr := raw.Control(func(fd uintptr) {
		gotIP, gotPort, opErr = originalDstFD(fd)
	})
	if cerr != nil {
		return nil, 0, cerr
	}
	return gotIP, gotPort, opErr
}

// originalDstFD is the raw getsockopt dance, separated so tests can drive the
// sockaddr parser without a live NAT socket.
func originalDstFD(fd uintptr) (net.IP, int, error) {
	// Try IPv4 first (SOL_IP), then IPv6 (SOL_IPV6): a dual-stack listener
	// accepted an IPv6 socket needs the latter.
	if ip, port, err := originalDstLevel(fd, unix.SOL_IP); err == nil {
		return ip, port, nil
	}
	return originalDstLevel(fd, unix.SOL_IPV6)
}

func originalDstLevel(fd uintptr, level int) (net.IP, int, error) {
	var buf [128]byte
	l := uint32(len(buf))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(level), soOriginalDst,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return nil, 0, errno
	}
	return parseSockaddr(buf[:l])
}

// parseSockaddr decodes a struct sockaddr_in / sockaddr_in6 as returned by
// SO_ORIGINAL_DST. The family field is host-endian; the port and addresses are
// network order.
func parseSockaddr(b []byte) (net.IP, int, error) {
	if len(b) < 8 {
		return nil, 0, fmt.Errorf("short sockaddr (%d bytes)", len(b))
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	port := int(binary.BigEndian.Uint16(b[2:4]))
	switch family {
	case unix.AF_INET:
		return net.IPv4(b[4], b[5], b[6], b[7]), port, nil
	case unix.AF_INET6:
		if len(b) < 24 {
			return nil, 0, fmt.Errorf("short sockaddr_in6 (%d bytes)", len(b))
		}
		ip := make(net.IP, 16)
		copy(ip, b[8:24])
		return ip, port, nil
	default:
		return nil, 0, fmt.Errorf("unexpected address family %d", family)
	}
}
