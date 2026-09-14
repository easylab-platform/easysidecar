package main

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
	if !strings.Contains(y, `match: ["registry-1.docker.io", "docker.io", "production.cloudflare.docker.com"]`) {
		t.Fatalf("OCI rule missing:\n%s", y)
	}
	if strings.Contains(y, "@@") || strings.Contains(y, "/pkgs/") {
		t.Fatal("targets must be bare host:port (routing is by preserved Host)")
	}
}
