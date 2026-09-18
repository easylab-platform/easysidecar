package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/easylab-platform/easysidecar/capture"
	"github.com/easylab-platform/easysidecar/logging"
	"github.com/easylab-platform/easysidecar/rule"
)

// This file implements the dns-spoof interception mode: no iptables, no tun,
// no NET_ADMIN. The sidecar is the Pod's resolver (dnsConfig nameserver) and
// answers for the workloads it protects:
//
//	block   -> NXDOMAIN (the client never connects)
//	rewrite -> the sidecar's own Pod IP (so the client connects to the
//	           sidecar's :443/:80, which authenticates with MITM and relays
//	           to the rule target)
//	direct  -> the real upstream answer, forwarded from the cluster resolver
//
// Only A/AAAA queries for rewrite-matched names are spoofed; everything else
// is forwarded verbatim (including cluster-internal names), so search domains
// and ndots behavior stay correct.

// SpoofDNS serves the resolver for spoof mode.
type SpoofDNS struct {
	Addr        string
	SelfIP      string
	UpstreamDNS []string
	Decider     *rule.Decider
	Logger      *logging.ConnLogger
	// Mark, when non-zero, is stamped on the resolver's sockets so the capture
	// redirect exempts its replies and upstream forwards (no self-loop).
	Mark int
	// ForwardDirect disables the mitm_default "spoof every name to SelfIP"
	// branch, so direct names resolve to their real IPs. Capture mode sets it:
	// the netfilter redirect intercepts the real destination, so answering a
	// Pod IP would route the connection over loopback instead (and lose the
	// real destination).
	ForwardDirect bool
}

// ServeDNS listens on UDP and TCP :53 (DNS over UDP plus TCP fallback for
// truncated/large answers).
func (s *SpoofDNS) Serve() error {
	udp, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("spoof dns (udp) %s: %w", s.Addr, err)
	}
	if uc, ok := udp.(*net.UDPConn); ok {
		_ = capture.SetMark(uc, s.Mark)
	}
	s.Logger.Log(logging.ConnLogEntry{Action: "info", Dst: "listening spoof-dns udp " + s.Addr})
	go s.serveUDP(udp)

	tcp, err := net.Listen("tcp", s.Addr)
	if err != nil {
		// Some clusters only route UDP 53; TCP is best-effort.
		return nil
	}
	s.Logger.Log(logging.ConnLogEntry{Action: "info", Dst: "listening spoof-dns tcp " + s.Addr})
	for {
		c, err := tcp.Accept()
		if err != nil {
			return err
		}
		go s.serveTCP(c)
	}
}

func (s *SpoofDNS) serveUDP(ln net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, client, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := s.handle(buf[:n])
		if resp == nil {
			continue
		}
		_, _ = ln.WriteTo(resp, client)
	}
}

func (s *SpoofDNS) serveTCP(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hdr [2]byte
		if _, err := readFull(c, hdr[:]); err != nil {
			return
		}
		qlen := int(binary.BigEndian.Uint16(hdr[:]))
		if qlen <= 0 || qlen > 4096 {
			return
		}
		q := make([]byte, qlen)
		if _, err := readFull(c, q); err != nil {
			return
		}
		resp := s.handle(q)
		if resp == nil {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := c.Write(out[:]); err != nil {
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

// handle classifies one query and returns the response bytes (nil = drop).
func (s *SpoofDNS) handle(query []byte) []byte {
	name, qtype, ok := parseDNSQuestion(query)
	if !ok {
		return s.forward(query)
	}
	dec := s.Decider.Decide(name, "")
	switch dec.Action {
	case rule.ActionBlock:
		s.Logger.Log(logging.ConnLogEntry{Host: name, Action: "block-dns", Rule: firstMatch(dec)})
		return BuildNXDOMAIN(query)
	case rule.ActionRewrite:
		if qtype == dnsTypeA {
			s.Logger.Log(logging.ConnLogEntry{Host: name, Action: "spoof-dns", Rule: firstMatch(dec), Dst: s.SelfIP})
			return buildARecord(query, s.SelfIP, dnsTypeA)
		}
		if qtype == dnsTypeAAAA || qtype == dnsTypeHTTPS || qtype == dnsTypeSVCB {
			// NODATA: no IPv6 answer (self-ip is IPv4) and no HTTPS/SVCB
			// record, which cuts the client's QUIC/HTTP3 discovery path —
			// spoof mode has no UDP listener to catch h3.
			s.Logger.Log(logging.ConnLogEntry{Host: name, Action: "spoof-nodata", Rule: firstMatch(dec)})
			return buildNODATA(query)
		}
		return s.forward(query)
	case rule.ActionDirect:
		if !s.ForwardDirect && s.Decider.ShouldDecrypt(dec) {
			if qtype == dnsTypeA {
				return buildARecord(query, s.SelfIP, dnsTypeA)
			}
			if qtype == dnsTypeAAAA || qtype == dnsTypeHTTPS || qtype == dnsTypeSVCB {
				return buildNODATA(query)
			}
		}
		s.Logger.Log(logging.ConnLogEntry{Host: name, Action: "dns-forward"})
		return s.forward(query)
	}
	s.Logger.Log(logging.ConnLogEntry{Host: name, Action: "dns-forward"})
	return s.forward(query)
}

// forward relays the query to the configured upstream resolver(s).
func (s *SpoofDNS) forward(query []byte) []byte {
	for _, up := range s.UpstreamDNS {
		var conn net.Conn
		var err error
		if s.Mark != 0 {
			conn, err = capture.MarkedDialer(s.Mark).Dial("udp", up)
		} else {
			conn, err = net.Dial("udp", up)
		}
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			_ = conn.Close()
			continue
		}
		resp := make([]byte, 4096)
		n, err := conn.Read(resp)
		_ = conn.Close()
		if err != nil {
			continue
		}
		return resp[:n]
	}
	return nil
}

// DNS constants + generic record encoding.
const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsTypeSVCB  = 64
	dnsTypeHTTPS = 65
)

// parseDNSQuestion returns the QNAME and QTYPE of the first question.
func parseDNSQuestion(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(msg[2:4])&0x8000 != 0 {
		return "", 0, false // a response
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd == 0 {
		return "", 0, false
	}
	p := 12
	var labels []string
	for {
		if p >= len(msg) {
			return "", 0, false
		}
		l := int(msg[p])
		if l == 0 {
			p++
			break
		}
		if l&0xC0 != 0 || p+1+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[p+1:p+1+l]))
		p += 1 + l
	}
	if p+4 > len(msg) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(msg[p : p+2])
	return strings.ToLower(strings.Join(labels, ".")), qtype, true
}

// questionEnd returns the offset just past the first question. buildARecord
// copies the question verbatim so the response stays well-formed.
func questionEnd(msg []byte) (int, bool) {
	p := 12
	for {
		if p >= len(msg) {
			return 0, false
		}
		l := int(msg[p])
		if l == 0 {
			p++
			break
		}
		if l&0xC0 != 0 || p+1+l > len(msg) {
			return 0, false
		}
		p += 1 + l
	}
	if p+4 > len(msg) {
		return 0, false
	}
	return p + 4, true
}

// buildARecord answers a query with a single A (or AAAA) record pointing at
// ip. The question section is echoed verbatim; a class-IN, TTL=30 answer is
// appended. Header flags: QR=1, AA=1, RD copied, RA=1.
func buildARecord(query []byte, ip string, qtype uint16) []byte {
	qe, ok := questionEnd(query)
	if !ok {
		return BuildNXDOMAIN(query)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return BuildNXDOMAIN(query)
	}
	if qtype != dnsTypeA {
		return BuildNXDOMAIN(query)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return BuildNXDOMAIN(query)
	}
	rdata := v4

	resp := make([]byte, 0, qe+16+len(rdata))
	resp = append(resp, query[:qe]...)
	// Header: copy the query's ID + question, set flags + counts.
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= 0x8000 // QR
	flags |= 0x0400 // AA (authoritative for the spoofed name)
	flags |= 0x0080 // RA
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	// Answer: name pointer to 0x0c (the question name).
	resp = append(resp, 0xc0, 0x0c)
	var typeLen [8]byte
	binary.BigEndian.PutUint16(typeLen[0:2], qtype) // TYPE
	binary.BigEndian.PutUint16(typeLen[2:4], 1)     // CLASS IN
	binary.BigEndian.PutUint32(typeLen[4:8], 30)    // TTL 30s
	resp = append(resp, typeLen[:]...)
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(rdata)))
	resp = append(resp, rdlen[:]...)
	resp = append(resp, rdata...)
	return resp
}

// buildNODATA answers a query with NOERROR and zero records (the name
// exists conceptually but has no data of that type — e.g. AAAA for an
// IPv4-only answer, or HTTPS/SVCB to suppress HTTP/3 discovery).
func buildNODATA(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= 0x8000 // QR=1
	flags |= 0x0080 // RA=1
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	return resp
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// firstMatch returns the first match pattern of a decision for logging
// ("" when the default action applied).
func firstMatch(dec rule.Decision) string {
	if dec.Rule == nil || len(dec.Rule.Match) == 0 {
		return ""
	}
	return dec.Rule.Match[0]
}

// BuildNXDOMAIN rewrites a query into a response with RCODE=3 and no records.
func BuildNXDOMAIN(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= 0x8000 // QR=1
	flags |= 0x0003 // RCODE=3 NXDOMAIN
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	return resp
}
