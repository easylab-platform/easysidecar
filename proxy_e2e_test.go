package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// e2e: a rule-driven proxy over the explicit CONNECT face (portable; the
// transparent face needs iptables and is covered by kind integration).

type e2eFixture struct {
	caPEM   []byte
	origSrv *httptest.Server // "docker.io" stand-in
	npmSrv  *httptest.Server // rewrite target stand-in
}

func newE2E(t *testing.T) (*e2eFixture, string) {
	t.Helper()

	orig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ORIGIN-"+r.Host)
	}))
	t.Cleanup(orig.Close)
	rewrite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "REWRITTEN-"+r.Host+r.URL.Path)
	}))
	t.Cleanup(rewrite.Close)

	yaml := `
rules:
  - match: ["*.npmjs.org"]
    action: rewrite
    target: "` + stripScheme(rewrite.URL) + `"
  - match: ["blocked.example"]
    action: block
  - match: ["direct.test"]
    action: direct
default: direct
`
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}

	// CA for MITM.
	caPEM, keyPEM, err := mintTestCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	mitm, err := LoadMITM(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	dec := NewDecider(rs, false, nil)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyLn.Addr().String()
	serveErr := make(chan error, 1)
	go func() { serveErr <- ServeConnect(proxyLn, dec, mitm, NewConnLogger()) }()
	t.Cleanup(func() { _ = proxyLn.Close() })
	go func() {
		if e := <-serveErr; e != nil && !strings.Contains(e.Error(), "use of closed network connection") {
			t.Errorf("ServeConnect exited: %v", e)
		}
	}()

	return &e2eFixture{origSrv: orig, npmSrv: rewrite, caPEM: caPEM}, proxyAddr
}

func stripScheme(u string) string {
	for _, p := range []string{"http://", "https://"} {
		if rest, ok := cutStrPrefix(u, p); ok {
			return rest
		}
	}
	return u
}

func cutStrPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return s, false
}

// dialVia issues CONNECT through the proxy and returns the tunneled conn.
func dialVia(t *testing.T, proxyAddr, host string, caPEM []byte) net.Conn {
	t.Helper()
	up, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	if _, err := up.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(up)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}
	if caPEM == nil {
		return up
	}
	// TLS through the tunnel, trusting the easyproxy CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA PEM")
	}
	tlsC := tls.Client(up, &tls.Config{ServerName: hostOnly(host), RootCAs: pool})
	if err := tlsC.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsC
}

func hostOnly(h string) string {
	if i := indexByteStr(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

func indexByteStr(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func TestE2EBlock(t *testing.T) {
	_, addr := newE2E(t)
	up, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	_, _ = up.Write([]byte("CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n"))
	br := bufio.NewReader(up)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		// The transparent face RSTs; explicit face RSTs too (resetConn).
		return
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("blocked host must not establish")
	}
}

func TestE2EDirect(t *testing.T) {
	f, addr := newE2E(t)
	// CONNECT to direct.test:80; the proxy dials the authority — but
	// direct.test doesn't resolve in the test env. Instead connect directly
	// to the origin server's host:port while declaring Host: direct.test so
	// classification sees the rule.
	originHostPort := stripScheme(f.origSrv.URL)
	c := dialVia(t, addr, originHostPort, nil)
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: direct.test\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ORIGIN-direct.test" {
		t.Fatalf("body = %q", body)
	}
}

func TestE2ERewriteMITM(t *testing.T) {
	f, addr := newE2E(t)
	c := dialVia(t, addr, "registry.npmjs.org:443", f.caPEM)
	defer func() { _ = c.Close() }()
	// HTTPS GET through the MITM'd tunnel toward the rewrite target.
	if _, err := c.Write([]byte("GET /pkg HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	// The rewrite target answered (not the origin).
	if len(body) == 0 || string(body)[:9] != "REWRITTEN" {
		t.Fatalf("body = %q (expected rewrite target)", body)
	}
	// And the original Host reached the target adapter.
	if string(body) != "REWRITTEN-registry.npmjs.org/pkg" {
		t.Fatalf("body = %q", body)
	}
}
