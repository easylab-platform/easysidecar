package relay

import (
	"net"
	"strings"
	"testing"

	"github.com/easylab-platform/easysidecar/rule"
)

func TestRewriteTarget(t *testing.T) {
	r := &rule.Rule{AddPrefix: "/artifacts/npm"}
	cases := []struct{ in, want string }{
		{"/react", "/artifacts/npm/react"},
		{"/react?write=true", "/artifacts/npm/react?write=true"},
		{"http://registry.npmjs.org/react", "http://registry.npmjs.org/artifacts/npm/react"},
		{"http://registry.npmjs.org", "http://registry.npmjs.org"},
	}
	for _, c := range cases {
		if got := rewriteTarget(c.in, r.MapPath); got != c.want {
			t.Errorf("rewriteTarget(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestHeaderReaderRewrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go func() {
		_, _ = c2.Write([]byte("PUT /crate/foo HTTP/1.1\r\nHost: index.crates.io\r\nContent-Length: 4\r\n\r\nBODY"))
	}()
	br := newHeaderReader(c1)
	host, err := br.readHost()
	if err != nil {
		t.Fatal(err)
	}
	if host != "index.crates.io" {
		t.Fatalf("host = %q", host)
	}
	out := string(br.rewrite((&rule.Rule{AddPrefix: "/artifacts/cargo"}).MapPath))
	if !strings.Contains(out, "PUT /artifacts/cargo/crate/foo HTTP/1.1\r\n") {
		t.Fatalf("request line not mapped: %q", out)
	}
	if !strings.Contains(out, "Host: index.crates.io\r\n") {
		t.Fatalf("Host header changed: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\nBODY") {
		t.Fatalf("body lost: %q", out)
	}
}

func TestHeaderReaderRewriteNoopUnchanged(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	raw := "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
	go func() { _, _ = c2.Write([]byte(raw)) }()
	br := newHeaderReader(c1)
	if _, err := br.readHost(); err != nil {
		t.Fatal(err)
	}
	if got := string(br.rewrite(nil)); got != raw {
		t.Fatalf("nil fn rewrite = %q want %q", got, raw)
	}
}
