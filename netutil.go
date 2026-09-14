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

// firstNonLoopbackIPv4 returns the Pod's primary IPv4 address.
func firstNonLoopbackIPv4() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() {
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("no non-loopback IPv4 address")
}
