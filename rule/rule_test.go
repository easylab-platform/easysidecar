package rule

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRules(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const sampleRules = `
rules:
  - match: ["docker.io", "registry-1.docker.io", "production.cloudflare.docker.com"]
    action: rewrite
    target: "gateway.easylab.svc:8080"
  - match: ["*.npmjs.org", "npmjs.org"]
    action: rewrite
    target: "gateway.easylab.svc:8080"
  - match: ["*.evil.example", "malware.example"]
    action: block
default: direct
`

func TestLoadRules(t *testing.T) {
	rs, err := LoadRules(writeRules(t, sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Default != ActionDirect {
		t.Fatalf("default = %q", rs.Default)
	}
	if !rs.HasRewrite() {
		t.Fatal("sample has rewrite rules")
	}
}

func TestLoadRulesValidation(t *testing.T) {
	cases := map[string]string{
		"empty match":     "rules:\n  - action: block\n",
		"missing action":  "rules:\n  - match: [a.com]\n",
		"unknown action":  "rules:\n  - match: [a.com]\n    action: teleport\n",
		"rewrite w/o tgt": "rules:\n  - match: [a.com]\n    action: rewrite\n",
		"bad default":     "rules: []\ndefault: rewrite\n",
	}
	for name, yaml := range cases {
		if _, err := LoadRules(writeRules(t, yaml)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"docker.io", "docker.io", true},
		{"docker.io", "registry-1.docker.io", true}, // bare suffix
		{"docker.io", "notdocker.io", false},        // suffix must be label-bounded
		{"*.npmjs.org", "registry.npmjs.org", true},
		{"*.npmjs.org", "npmjs.org", false}, // star needs ≥1 label
		{"*.npmjs.org", "a.b.npmjs.org", true},
		{"exact.example", "exact.example", true},
		{"exact.example", "other.example", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.pattern, c.host); got != c.want {
			t.Errorf("MatchHost(%q, %q) = %v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestDeciderMatrix(t *testing.T) {
	rs, err := LoadRules(writeRules(t, sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecider(rs, false)
	cases := []struct {
		host, origIP string
		action       Action
		decrypt      bool
	}{
		{"registry-1.docker.io", "8.8.8.8", ActionRewrite, true},
		{"registry.npmjs.org", "8.8.8.8", ActionRewrite, true},
		{"cdn.evil.example", "8.8.8.8", ActionBlock, false},
		{"example.com", "8.8.8.8", ActionDirect, false}, // default
	}
	for _, c := range cases {
		dec := d.Decide(c.host, c.origIP)
		if dec.Action != c.action {
			t.Errorf("Decide(%q,%q) = %s want %s", c.host, c.origIP, dec.Action, c.action)
		}
		if d.ShouldDecrypt(dec) != c.decrypt {
			t.Errorf("ShouldDecrypt(%q) = %v want %v", c.host, d.ShouldDecrypt(dec), c.decrypt)
		}
	}
}

func TestMapPath(t *testing.T) {
	cases := []struct {
		name       string
		strip, add string
		in, want   string
	}{
		{"strip add", "/v2", "/v2/docker.io", "/v2/nginx/manifests/latest", "/v2/docker.io/nginx/manifests/latest"},
		{"strip only", "/proxy", "", "/proxy/dist/app.js", "/dist/app.js"},
		{"add npm", "", "/pkgs/npm", "/react", "/pkgs/npm/react"},
		{"add pypi", "", "/pkgs/pypi", "/simple/requests/", "/pkgs/pypi/simple/requests/"},
		{"strip boundary no match", "/v2", "", "/v20/foo", "/v20/foo"},
		{"strip exact root", "/pkgs", "", "/pkgs", "/"},
		{"strip trailing slash", "/api/", "", "/api/x", "/x"},
		{"noop", "", "", "/a/b", "/a/b"},
	}
	for _, c := range cases {
		r := &Rule{StripPrefix: c.strip, AddPrefix: c.add}
		if got := r.MapPath(c.in); got != c.want {
			t.Errorf("%s: MapPath(%q) = %q want %q", c.name, c.in, got, c.want)
		}
	}
}
