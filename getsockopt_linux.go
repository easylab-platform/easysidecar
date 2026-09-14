//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

// getsockopt is the raw syscall wrapper (net package doesn't expose SOL_IP).
func getsockopt(fd uintptr, level, opt int, val unsafe.Pointer, vallen *uint32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(opt),
		uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
