package relay

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easylab-platform/easysidecar/rule"
)

func TestIsH2CPreface(t *testing.T) {
	full := []byte(h2cPreface)
	if !isH2CPreface(full) {
		t.Fatal("full preface must match")
	}
	if !isH2CPreface(full[:8]) {
		t.Fatal("partial preface must match")
	}
	if isH2CPreface([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("HTTP/1.1 must not match")
	}
	if isH2CPreface(nil) {
		t.Fatal("empty must not match")
	}
	if isH2CPreface([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\rX")) {
		t.Fatal("wrong final byte must not match")
	}
}

// TestTransparentProxyRoundTrip proves a plain HTTP request is proxied to the
// original destination and logged with method/path/status.
func TestTransparentProxyRoundTrip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Path))
	}))
	defer backend.Close()
	_, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}

	var gotMethod, gotPath string
	var gotStatus int
	rp := buildTransparentProxy("127.0.0.1", port, "http", nil, "", func(r *http.Request, status int) {
		gotMethod, gotPath, gotStatus = r.Method, r.URL.Path, status
	})
	front := httptest.NewServer(rp)
	defer front.Close()

	resp, err := http.Get(front.URL + "/abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello /abc" {
		t.Fatalf("body = %q", body)
	}
	if gotMethod != "GET" || gotPath != "/abc" || gotStatus != 200 {
		t.Fatalf("log = %s %s %d", gotMethod, gotPath, gotStatus)
	}
}

// mustRulesTarget builds a one-rewrite rule set targeting the test server.
func mustRulesTarget(t *testing.T, targetURL, host string) *rule.RuleSet {
	t.Helper()
	p := writeRules(t, `
rules:
  - match: ["`+host+`"]
    action: rewrite
    target: "`+stripScheme(targetURL)+`"
    add_prefix: "/artifacts/npm"
default: direct
`)
	rs, err := rule.LoadRules(p)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// TestWebFaceRewriteMapsPath verifies the shared web face rewrites a request
// that matches a rule (using the Host header) to the rule target.
func TestWebFaceRewriteMapsPath(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("rewritten " + r.URL.Path))
	}))
	defer target.Close()

	rs := mustRulesTarget(t, target.URL, "registry.npmjs.org")
	face := &webFace{
		scheme: "http", origHost: "127.0.0.1", origPort: 80,
		decider: rule.NewDecider(rs, false),
	}
	front := httptest.NewServer(face.handler())
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/left-pad", nil)
	req.Host = "registry.npmjs.org"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "rewritten /artifacts/npm/left-pad" {
		t.Fatalf("body = %q", body)
	}
}
