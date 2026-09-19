package rule

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is what happens to a connection whose hostname matched a rule.
type Action string

const (
	ActionBlock   Action = "block"
	ActionDirect  Action = "direct"
	ActionRewrite Action = "rewrite"
)

// Rule matches a set of hostnames (exact, "*.suffix", or bare suffix) and
// prescribes an action.
type Rule struct {
	Match []string `yaml:"match"`
	// Action is block, direct, or rewrite.
	Action Action `yaml:"action"`
	// Target is the rewrite destination, "host:port" (an optional scheme://
	// prefix selects client TLS to the target). The original path is used
	// verbatim unless StripPrefix/AddPrefix transform it.
	Target string `yaml:"target,omitempty"`
	// StripPrefix removes a leading path prefix from the incoming request
	// path before AddPrefix is applied (no-op when it does not match).
	StripPrefix string `yaml:"strip_prefix,omitempty"`
	// StripPrefixes is the multi-prefix form: the first one that matches the
	// request path is removed (a mirror serving the same content under
	// several prefixes, e.g. repo.spring.io/release and /milestone). It is
	// mutually exclusive with StripPrefix.
	StripPrefixes []string `yaml:"strip_prefixes,omitempty"`
	// AddPrefix prepends a path prefix after stripping (e.g. "/artifacts/npm" to
	// steer registry.npmjs.org/react → artifact/artifacts/npm/react).
	AddPrefix string `yaml:"add_prefix,omitempty"`
	// PathPrefix, when set, restricts this rule to requests whose path starts
	// with it (segment boundary respected). It lets one host serve several
	// targets: a rule claims only its path subtree, and other paths on the same
	// host fall through to a later rule (typically the catch-all).
	PathPrefix string `yaml:"path_prefix,omitempty"`
	// Mitm forces decryption for this rule even when MitmDefault is false
	// (rewrite rules decrypt regardless; a block/direct rule never does).
	Mitm bool `yaml:"mitm,omitempty"`
}

// MapPath applies the rule's strip/add prefix transform to an absolute
// request path. Both prefixes are optional; the result always has a leading
// slash. A strip prefix removes a leading segment boundary (exact match or
// followed by "/"), so stripping "/v2" from "/v2/foo" yields "/foo" but
// leaves "/v20" untouched. With several strips the first match wins.
func (r *Rule) MapPath(p string) string {
	for _, sp := range r.strips() {
		if sp == "" {
			continue
		}
		matched := false
		switch {
		case strings.HasSuffix(sp, "/"):
			if strings.HasPrefix(p, sp) {
				p = p[len(sp):]
				matched = true
			}
		case p == sp:
			p = "/"
			matched = true
		case strings.HasPrefix(p, sp+"/"):
			p = p[len(sp):]
			matched = true
		}
		if matched {
			break // first matching prefix wins
		}
	}
	if r.AddPrefix != "" {
		p = strings.TrimSuffix(r.AddPrefix, "/") + "/" + strings.TrimPrefix(p, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// strips returns the effective strip prefixes: the plural form when set, else
// the singular.
func (r *Rule) strips() []string {
	if len(r.StripPrefixes) > 0 {
		return r.StripPrefixes
	}
	if r.StripPrefix != "" {
		return []string{r.StripPrefix}
	}
	return nil
}

// MatchedStrip returns the strip prefix that applies to p, or "" when none
// does. It is the prefix the caller records as X-Forwarded-Prefix.
func (r *Rule) MatchedStrip(p string) string {
	for _, sp := range r.strips() {
		if sp == "" {
			continue
		}
		switch {
		case strings.HasSuffix(sp, "/"):
			if strings.HasPrefix(p, sp) {
				return sp
			}
		case p == sp, strings.HasPrefix(p, sp+"/"):
			return sp
		}
	}
	return ""
}

// RuleSet is the parsed policy. First matching rule wins.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
	// Default is the action for connections no rule matched (direct|block).
	Default Action `yaml:"default"`
	// MitmDefault decrypts every intercepted TLS connection even when the
	// matched rule is direct (opt-in full-MITM posture). Default false.
	MitmDefault bool `yaml:"mitm_default"`
}

// LoadRules parses the YAML rule set from path.
func LoadRules(path string) (*RuleSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rs RuleSet
	if err := yaml.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	if rs.Default == "" {
		rs.Default = ActionDirect
	}
	for i, r := range rs.Rules {
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("rule %d: empty match", i)
		}
		switch r.Action {
		case ActionBlock, ActionDirect, ActionRewrite:
		case "":
			return nil, fmt.Errorf("rule %d: missing action", i)
		default:
			return nil, fmt.Errorf("rule %d: unknown action %q", i, r.Action)
		}
		if r.Action == ActionRewrite && r.Target == "" {
			return nil, fmt.Errorf("rule %d: rewrite requires target", i)
		}
	}
	switch rs.Default {
	case ActionDirect, ActionBlock:
	default:
		return nil, fmt.Errorf("default must be direct|block, got %q", rs.Default)
	}
	return &rs, nil
}

// HasRewrite reports whether any rule rewrites (and therefore requires a
// MITM authority at startup).
func (rs *RuleSet) HasRewrite() bool {
	for _, r := range rs.Rules {
		if r.Action == ActionRewrite || r.Mitm {
			return true
		}
	}
	return rs.MitmDefault
}

// matchHost reports whether pattern matches host. Patterns are exact
// ("registry.npmjs.org"), suffix wildcards ("*.npmjs.org"), bare suffixes
// ("npmjs.org" matches npmjs.org and anything under it), or the catch-all "*"
// which matches any PUBLIC hostname (cluster-local names, IPs and localhost are
// excluded, so "cache everything" never captures in-cluster traffic). Matching
// ignores case and a trailing dot.
func MatchHost(pattern, host string) bool {
	if pattern == "*" {
		return IsPublicHost(host)
	}
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".npmjs.org"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	// Bare suffix: host == pattern (checked above) or host ends with
	// "."+pattern.
	return strings.HasSuffix(host, "."+pattern)
}

// IsPublicHost mirrors the targets.IsPublicHost guard just enough to be
// dependency-free here: a dotted DNS name that is not an IP, localhost or a
// cluster-local suffix.
func IsPublicHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	h = strings.Trim(h, "[]")
	if h == "" || h == "localhost" {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	for _, suf := range []string{".local", ".svc", ".cluster.local", ".internal"} {
		if strings.HasSuffix(h, suf) {
			return false
		}
	}
	return strings.Contains(h, ".")
}

// Decision is the outcome of classifying a connection.
type Decision struct {
	Action Action
	// Rule is the matched rule (nil for the default action).
	Rule *Rule
	// Host is the classified hostname (SNI / Host header / "" when unknown).
	Host string
}

// Decider classifies connections against a RuleSet. It is safe for
// concurrent use (the rule set is immutable after load).
type Decider struct {
	rs          *RuleSet
	mitmDefault bool
}

// NewDecider builds a Decider over an immutable rule set.
func NewDecider(rs *RuleSet, mitmDefault bool) *Decider {
	return &Decider{rs: rs, mitmDefault: mitmDefault || rs.MitmDefault}
}

// Decide classifies by hostname and (for fallback classification) the
// original destination address.
// Decide classifies by hostname only (connection-level: SNI, or a plain-HTTP
// request with no path yet). Rules that declare PathPrefix are skipped here,
// because the path is not known at connection setup; per-request callers use
// DecidePath so path-scoped rules can match.
func (d *Decider) Decide(host, origDstIP string) Decision {
	for i := range d.rs.Rules {
		r := &d.rs.Rules[i]
		if r.PathPrefix != "" {
			continue // path-scoped: needs DecidePath
		}
		for _, m := range r.Match {
			if MatchHost(m, host) {
				return Decision{Action: r.Action, Rule: r, Host: host}
			}
		}
	}
	return Decision{Action: d.rs.Default, Host: host}
}

// DecidePath classifies one HTTP request by host AND path: a rule matches when
// its hosts match and (its PathPrefix is empty or the request path is under
// it). This is what lets one host serve several targets — e.g. dl.google.com's
// /dl/android/maven2 (maven) vs /android/repository (netcache): the maven rule
// claims its prefix, and any other path falls through to the catch-all.
func (d *Decider) DecidePath(host, path string) Decision {
	for i := range d.rs.Rules {
		r := &d.rs.Rules[i]
		if r.PathPrefix != "" && !pathHasPrefix(path, r.PathPrefix) {
			continue
		}
		for _, m := range r.Match {
			if MatchHost(m, host) {
				return Decision{Action: r.Action, Rule: r, Host: host}
			}
		}
	}
	return Decision{Action: d.rs.Default, Host: host}
}

// pathHasPrefix reports whether p is under prefix at a segment boundary ("/a"
// matches "/a", "/a/b", but not "/ab").
func pathHasPrefix(p, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return true
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// ShouldDecrypt reports whether the decision requires MITM.
func (d *Decider) ShouldDecrypt(dec Decision) bool {
	if dec.Action != ActionDirect && dec.Action != ActionRewrite {
		return false
	}
	if dec.Action == ActionRewrite {
		return true
	}
	return d.mitmDefault
}
