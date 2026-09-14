package main

import (
	"fmt"
	"net"
	"strings"
)

// inAnyCIDR reports whether ip (dotted quad or empty) falls inside any of
// the comma-supplied CIDRs. An empty ip list or unparseable entries are
// treated as no-match (fail open to the rule engine, which still classifies
// by hostname).
func inAnyCIDR(ip string, cidrs []string) bool {
	if ip == "" || len(cidrs) == 0 {
		return false
	}
	parsed := net.ParseIP(strings.Split(ip, "%")[0]) // strip IPv6 zone
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if ipnet.Contains(parsed) {
			return true
		}
	}
	return false
}

// hostPort splits "host:port" (or "[v6]:port") into its parts.
func hostPort(addr string) (string, string, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("split %q: %w", addr, err)
	}
	return h, p, nil
}
