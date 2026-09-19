package rule

import (
	"strings"
	"testing"

	"github.com/easylab-platform/artifact/targets"
)

func TestDefaultRulesYAMLParses(t *testing.T) {
	yaml := DefaultRulesYAML("gateway.easylab.svc:8080")
	p := writeRules(t, yaml)
	rs, err := LoadRules(p)
	if err != nil {
		t.Fatalf("default rules must parse: %v", err)
	}
	if rs.Default != ActionDirect {
		t.Fatalf("default = %q", rs.Default)
	}
	if rs.MitmDefault {
		t.Fatal("mitm_default must be false by default")
	}
	// Every non-direct policy entry becomes a rewrite rule.
	wantRewrite := 0
	for _, e := range targets.EgressPolicy() {
		if !e.Direct {
			wantRewrite++
		}
	}
	rewrites := 0
	for _, r := range rs.Rules {
		if r.Action == ActionRewrite {
			rewrites++
			if r.Target != "gateway.easylab.svc:8080" {
				t.Fatalf("target = %q", r.Target)
			}
		}
	}
	if rewrites != wantRewrite {
		t.Fatalf("rewrite rules = %d, want %d", rewrites, wantRewrite)
	}
}

func TestDefaultRulesCoverEcosystems(t *testing.T) {
	cases := map[string]bool{
		"registry-1.docker.io":   true,
		"registry.npmjs.org":     true,
		"pypi.org":               true,
		"files.pythonhosted.org": true,
		"proxy.golang.org":       true,
		"crates.io":              true,
		"repo.maven.apache.org":  true,
		"api.nuget.org":          true,
		"rubygems.org":           true,
		"dl-cdn.alpinelinux.org": true,
		"deb.debian.org":         true,
		"archive.ubuntu.com":     true,
		"cdn-lfs.huggingface.co": true,
		"conda.anaconda.org":     true,
		"cache.nixos.org":        true,
		// An arbitrary public host is covered by the catch-all (cached via
		// netcache); cluster-local names are not.
		"example.com":            true,
		"kubernetes.default.svc": false,
		"easylab":                false,
	}
	for host, want := range cases {
		if got := HasUpstreamDomain(host); got != want {
			t.Errorf("HasUpstreamDomain(%q) = %v want %v", host, got, want)
		}
	}
}

func TestDefaultRulesYAMLShape(t *testing.T) {
	y := DefaultRulesYAML("gw:80")
	// All container registries share one OCI target, so a single rule carries
	// docker hub's aliases plus the registries a client addresses by name.
	for _, h := range []string{"registry-1.docker.io", "docker.io", "index.docker.io", "ghcr.io", "quay.io"} {
		if !strings.Contains(y, `"`+h+`"`) {
			t.Fatalf("OCI registry %q missing from rule set:\n%s", h, y)
		}
	}
	// Targets are bare host:port (routing is by preserved Host). add_prefix may
	// carry /artifacts/..., but the target line must not.
	for _, line := range strings.Split(y, "\n") {
		if strings.Contains(line, "target:") && strings.Contains(line, "/artifacts/") {
			t.Fatalf("target must be bare host:port, got %q", line)
		}
	}
	// A path-shaped mirror emits strip/add.
	if !strings.Contains(y, `strip_prefix: "/dl/android/maven2"`) ||
		!strings.Contains(y, `add_prefix: "/artifacts/maven"`) {
		t.Fatalf("google maven strip/add missing:\n%s", y)
	}
	// A mirror serving two prefixes emits the plural form.
	if !strings.Contains(y, `strip_prefixes: ["/milestone", "/release"]`) {
		t.Fatalf("spring multi-strip missing:\n%s", y)
	}
}
