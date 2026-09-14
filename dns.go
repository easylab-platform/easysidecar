package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// This file implements the DNS hijack face: the init rules REDIRECT
// outbound UDP/53 here. easyproxy answers blocked domains with NXDOMAIN (so
// clients fail fast instead of connecting into a RST) and forwards
// everything else to the Pod's original resolver (127.0.0.1:53 would loop —
// the upstream is taken from /etc/resolv.conf minus loopback entries).

// ServeDNS serves the UDP/53 listener until failure.
func ServeDNS(addr string, d *Decider, logger *ConnLogger) error {
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns listen %s: %w", addr, err)
	}
	logger.Log(ConnLogEntry{Action: "info", Dst: "listening dns " + addr})
	buf := make([]byte, 1500)
	upstream := dnsUpstreams()
	for {
		n, client, err := ln.ReadFrom(buf)
		if err != nil {
			return err
		}
		q, ok := parseDNSQuery(buf[:n])
		if !ok {
			continue
		}
		dec := d.Decide(q, "")
		if dec.Action == ActionBlock {
			resp := buildNXDOMAIN(buf[:n])
			_, _ = ln.WriteTo(resp, client)
			logger.Log(ConnLogEntry{Host: q, Action: "block-dns", Rule: firstMatch(dec)})
			continue
		}
		go forwardDNS(ln, client, buf[:n], upstream, logger)
	}
}

// dnsUpstreams returns the non-loopback nameservers from /etc/resolv.conf.
func dnsUpstreams() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8:53"}
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "nameserver "); ok {
			ns := strings.TrimSpace(rest)
			if ns != "" && !strings.HasPrefix(ns, "127.") && ns != "::1" {
				if !strings.Contains(ns, ":") {
					ns += ":53"
				}
				out = append(out, ns)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"8.8.8.8:53"}
	}
	return out
}

// forwardDNS relays one query to the first upstream that answers.
func forwardDNS(ln net.PacketConn, client net.Addr, query []byte, upstreams []string, logger *ConnLogger) {
	for _, up := range upstreams {
		conn, err := net.Dial("udp", up)
		if err != nil {
			continue
		}
		func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(query); err != nil {
				return
			}
			resp := make([]byte, 1500)
			n, err := conn.Read(resp)
			if err != nil {
				return
			}
			if _, err := ln.WriteTo(resp[:n], client); err == nil {
				logger.Log(ConnLogEntry{Action: "dns", Dst: up})
			}
		}()
		return
	}
}

// parseDNSQuery extracts the first QNAME of a DNS message ("" when the
// message is not a query).
func parseDNSQuery(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 != 0 { // QR=1: a response, not a query
		return "", false
	}
	p := 12
	var labels []string
	for {
		if p >= len(msg) {
			return "", false
		}
		l := int(msg[p])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer in a query: unsupported
			return "", false
		}
		if p+1+l > len(msg) {
			return "", false
		}
		labels = append(labels, string(msg[p+1:p+1+l]))
		p += 1 + l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// buildNXDOMAIN rewrites the query's flags into a response with RCODE=3
// (NXDOMAIN) and no answers.
func buildNXDOMAIN(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000            // QR=1
	flags |= 0x0003            // RCODE=3 NXDOMAIN
	flags &^= 0x0400 &^ 0x0100 // clear reserved bits, keep RD
	binary.BigEndian.PutUint16(resp[2:4], flags)
	// Zero out the answer/authority/additional counts (offsets 6..12).
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}
