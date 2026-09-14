package main

import (
	"net"
	"testing"
)

func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	var b []byte
	b = append(b, 0x12, 0x34) // ID
	b = append(b, 0x01, 0x00) // RD
	b = append(b, 0x00, 0x01) // QDCOUNT
	b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range splitLabels(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00) // root
	b = append(b, byte(qtype>>8), byte(qtype))
	b = append(b, 0x00, 0x01) // class IN
	return b
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestParseDNSQuestion(t *testing.T) {
	q := buildQuery(t, "registry.npmjs.org", dnsTypeA)
	name, qtype, ok := parseDNSQuestion(q)
	if !ok || name != "registry.npmjs.org" || qtype != dnsTypeA {
		t.Fatalf("got %q %d %v", name, qtype, ok)
	}
}

func TestBuildARecord(t *testing.T) {
	q := buildQuery(t, "registry.npmjs.org", dnsTypeA)
	resp := buildARecord(q, "10.1.2.3", dnsTypeA)
	if len(resp) < len(q)+16 {
		t.Fatalf("response too short: %d", len(resp))
	}
	// ANCOUNT must be 1.
	if resp[6] != 0 || resp[7] != 1 {
		t.Fatalf("ANCOUNT = %d", int(resp[6])<<8|int(resp[7]))
	}
	// The last 4 bytes are the A record.
	ip := net.IP(resp[len(resp)-4:])
	if ip.String() != "10.1.2.3" {
		t.Fatalf("answer IP = %s", ip)
	}
}

func TestSpoofDNSClassify(t *testing.T) {
	rs, err := LoadRules(writeRules(t, `
rules:
  - match: ["*.npmjs.org"]
    action: rewrite
    target: "gw:8080"
  - match: ["blocked.example"]
    action: block
default: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecider(rs, false, nil)
	// A forwarder that returns a canned "real" answer for direct queries.
	fwd := func(query []byte) []byte { return query } // echo (test only)
	s := &SpoofDNS{SelfIP: "10.0.0.9", Decider: d, Logger: NewConnLogger(), UpstreamDNS: nil}

	// rewrite -> spoofed A at SelfIP.
	resp := s.handle(buildQuery(t, "registry.npmjs.org", dnsTypeA))
	if resp == nil {
		t.Fatal("rewrite query got no response")
	}
	if ip := net.IP(resp[len(resp)-4:]); ip.String() != "10.0.0.9" {
		t.Fatalf("spoofed IP = %s", ip)
	}

	// block -> NXDOMAIN (RCODE 3).
	resp2 := s.handle(buildQuery(t, "blocked.example", dnsTypeA))
	if resp2 == nil {
		t.Fatal("block query got no response")
	}
	if rcode := resp2[3] & 0x0f; rcode != 3 {
		t.Fatalf("RCODE = %d, want 3", rcode)
	}

	// direct with no upstream -> dropped (nil).
	if resp3 := s.handle(buildQuery(t, "example.com", dnsTypeA)); resp3 != nil {
		t.Fatalf("direct with no upstream should drop, got %d bytes", len(resp3))
	}
	_ = fwd
}

func TestWithPort(t *testing.T) {
	cases := map[string]string{
		"10.96.0.10":    "10.96.0.10:53",
		"10.96.0.10:53": "10.96.0.10:53",
		"":              "8.8.8.8:53",
	}
	for in, want := range cases {
		if got := withPort(in, "53"); got != want {
			t.Errorf("withPort(%q) = %q want %q", in, got, want)
		}
	}
}

// TestSpoofNODATA verifies AAAA and HTTPS/SVCB queries for handled names get
// NODATA (NOERROR, zero answers) so clients never attempt QUIC/HTTP3 or a
// bogus IPv6 address.
func TestSpoofNODATA(t *testing.T) {
	rs, err := LoadRules(writeRules(t, `
rules:
  - match: ["*.npmjs.org"]
    action: rewrite
    target: "gw:8080"
default: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	s := &SpoofDNS{SelfIP: "10.0.0.9", Decider: NewDecider(rs, false, nil), Logger: NewConnLogger(), UpstreamDNS: nil}

	for _, qt := range []uint16{dnsTypeAAAA, dnsTypeHTTPS, dnsTypeSVCB} {
		resp := s.handle(buildQuery(t, "registry.npmjs.org", qt))
		if resp == nil {
			t.Fatalf("qtype %d: no response", qt)
		}
		if rcode := resp[3] & 0x0f; rcode != 0 {
			t.Fatalf("qtype %d: RCODE = %d, want 0 (NODATA)", qt, rcode)
		}
		if ancount := int(resp[6])<<8 | int(resp[7]); ancount != 0 {
			t.Fatalf("qtype %d: ANCOUNT = %d, want 0", qt, ancount)
		}
	}
}

// TestSpoofDirectNODATA verifies mitm_default direct names also get NODATA
// for AAAA/HTTPS (so the client sticks to the A record pointed at the
// sidecar).
func TestSpoofDirectNODATA(t *testing.T) {
	rs, err := LoadRules(writeRules(t, "rules: []\ndefault: direct\nmitm_default: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := &SpoofDNS{SelfIP: "10.0.0.9", Decider: NewDecider(rs, true, nil), Logger: NewConnLogger()}
	resp := s.handle(buildQuery(t, "example.com", dnsTypeAAAA))
	if resp == nil {
		t.Fatal("no response")
	}
	if rcode := resp[3] & 0x0f; rcode != 0 {
		t.Fatalf("RCODE = %d", rcode)
	}
	if ancount := int(resp[6])<<8 | int(resp[7]); ancount != 0 {
		t.Fatalf("ANCOUNT = %d, want 0", ancount)
	}
}
