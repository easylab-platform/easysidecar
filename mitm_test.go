package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRewriteHostPreserved verifies the rewrite relay forwards the ORIGINAL
// Host header to the pull-through adapter (npm needs the upstream hostname).
func TestRewriteHostPreserved(t *testing.T) {
	var gotHost string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(target.Close)

	caPEM, keyPEM, err := mintTestCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writePEMFile(t, dir, caPEM, keyPEM)
	mitm, err := LoadMITM(dir+"/ca.crt", dir+"/ca.key")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = serveSpoofTLS(ln, NewDecider(mustRules(t, target), false, nil), mitm, NewConnLogger()) }()

	c := spoofTLS(t, ln.Addr().String(), "registry.npmjs.org", caPEM)
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET /pkgs/npm/react HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("response = %q", buf[:n])
	}
	if gotHost != "registry.npmjs.org" {
		t.Fatalf("target saw Host %q, want the original upstream hostname", gotHost)
	}
}

// mustRules builds a one-rewrite rule set targeting the test server.
func mustRules(t *testing.T, target *httptest.Server) *RuleSet {
	t.Helper()
	p := writeRules(t, `
rules:
  - match: ["registry.npmjs.org"]
    action: rewrite
    target: "`+stripScheme(target.URL)+`"
default: direct
`)
	rs, err := LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func writePEMFile(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(dir+"/ca.crt", certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ca.key", keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}
