//go:build !linux

package main

import "fmt"

// getsockoptOriginalDst is Linux-only (netfilter REDIRECT); other platforms
// are unsupported for transparent mode (tests use explicit CONNECT instead).
func getsockoptOriginalDst(fd uintptr) (string, error) {
	return "", fmt.Errorf("transparent mode requires linux")
}
