//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// getsockoptOriginalDst recovers the pre-REDIRECT destination for a socket
// redirected by iptables nat (IPv4) or ip6tables (IPv6).
func getsockoptOriginalDst(fd uintptr) (string, error) {
	// Try IPv4 first.
	var addr4 syscall.RawSockaddrInet4
	salen := uint32(unsafe.Sizeof(addr4))
	err := getsockopt(fd, syscall.SOL_IP, solOriginalDst, unsafe.Pointer(&addr4), &salen)
	if err == nil {
		ip := net.IP(addr4.Addr[:])
		port := uint16(addr4.Port>>8) | uint16(addr4.Port<<8)
		return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
	}
	// IPv6.
	var addr6 syscall.RawSockaddrInet6
	salen6 := uint32(unsafe.Sizeof(addr6))
	err = getsockopt(fd, syscall.SOL_IPV6, solOriginalDst, unsafe.Pointer(&addr6), &salen6)
	if err != nil {
		return "", fmt.Errorf("SO_ORIGINAL_DST: %w", err)
	}
	ip := net.IP(addr6.Addr[:])
	port := uint16(addr6.Port>>8) | uint16(addr6.Port<<8)
	return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
}
