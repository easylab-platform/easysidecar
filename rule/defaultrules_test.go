package rule

import (
	"strings"
	"testing"
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
	// Every ecosystem entry became a rewrite rule.
	rewrites := 0
	for _, r := range rs.Rules {
		if r.Action == ActionRewrite {
			rewrites++
			if r.Target != "gateway.easylab.svc:8080" {
				t.Fatalf("target = %q", r.Target)
			}
		}
	}
	if rewrites != len(defaultUpstreams) {
		t.Fatalf("rewrite rules = %d, want %d", rewrites, len(defaultUpstreams))
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
		"example.com":            false, // not an upstream: direct
	}
	for host, want := range cases {
		if got := HasUpstreamDomain(host); got != want {
			t.Errorf("HasUpstreamDomain(%q) = %v want %v", host, got, want)
		}
	}
}

func TestDefaultRulesYAMLShape(t *testing.T) {
	y := DefaultRulesYAML("gw:80")
	// Docker Hub (aliases folded to docker.io by the adapter) plus the public
	// registries a client addresses by name.
	if !strings.Contains(y, `match: ["registry-1.docker.io", "docker.io", "index.docker.io"]`) {
		t.Fatalf("docker hub rule missing:\n%s", y)
	}
	if !strings.Contains(y, `"ghcr.io"`) || !strings.Contains(y, `"quay.io"`) {
		t.Fatalf("public registry rule missing:\n%s", y)
	}
	// Targets are bare host:port (routing is by preserved Host). add_prefix may
	// carry /pkgs/..., but the target line must not.
	for _, line := range strings.Split(y, "\n") {
		if strings.Contains(line, "target:") && strings.Contains(line, "/pkgs/") {
			t.Fatalf("target must be bare host:port, got %q", line)
		}
	}
	// A path-shaped mirror emits strip/add.
	if !strings.Contains(y, `strip_prefix: "/dl/android/maven2"`) ||
		!strings.Contains(y, `add_prefix: "/pkgs/maven"`) {
		t.Fatalf("google maven strip/add missing:\n%s", y)
	}
}
