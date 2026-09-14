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

// e2e for the spoof TLS face: the listener IS the TLS server. The client
// connects with SNI, easyproxy classifies (rewrite → MITM to the rule
// target, direct → passthrough, block → RST) and the client trusts the
// easyproxy CA (mirroring the injected SSL_CERT_FILE / NODE_EXTRA_CA_CERTS).

type e2eFixture struct {
	caPEM   []byte
	origSrv *httptest.Server // direct-action stand-in
	npmSrv  *httptest.Server // rewrite-target stand-in
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
	go func() { serveErr <- serveSpoofTLS(proxyLn, dec, mitm, NewConnLogger()) }()
	t.Cleanup(func() { _ = proxyLn.Close() })
	go func() {
		if e := <-serveErr; e != nil && !strings.Contains(e.Error(), "use of closed network connection") {
			t.Errorf("spoof TLS face exited: %v", e)
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

// spoofTLS connects to the spoof listener and performs the client TLS
// handshake with SNI=host, trusting the easyproxy CA (the injected
// SSL_CERT_FILE equivalent).
func spoofTLS(t *testing.T, proxyAddr, host string, caPEM []byte) net.Conn {
	t.Helper()
	up, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA PEM")
	}
	tlsC := tls.Client(up, &tls.Config{ServerName: host, RootCAs: pool})
	if err := tlsC.Handshake(); err != nil {
		t.Fatalf("TLS handshake with %s: %v", host, err)
	}
	return tlsC
}

func TestSpoofE2EBlock(t *testing.T) {
	_, addr := newE2E(t)
	up, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = up.Close() }()
	// ClientHello with SNI=blocked.example → the sidecar RSTs during/after
	// classification; the handshake or the first write/read fails.
	tlsC := tls.Client(up, &tls.Config{ServerName: "blocked.example"})
	_ = tlsC.SetDeadline(time.Now().Add(5 * time.Second))
	err = tlsC.Handshake()
	if err != nil {
		return // reset during handshake: the expected block behavior
	}
	_, werr := tlsC.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n"))
	buf := make([]byte, 32)
	_, rerr := tlsC.Read(buf)
	if werr == nil && rerr == nil {
		t.Fatal("blocked host must not serve content")
	}
}

func TestSpoofE2ERewriteMITM(t *testing.T) {
	f, addr := newE2E(t)
	c := spoofTLS(t, addr, "registry.npmjs.org", f.caPEM)
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET /pkg HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "REWRITTEN-registry.npmjs.org/pkg" {
		t.Fatalf("body = %q", body)
	}
}
