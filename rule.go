package main

import (
	"fmt"
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
	// Target is the rewrite destination, "host:port" plus an optional path
	// prefix that replaces the original absolute path (used to steer
	// registry.npmjs.org/pkg → gateway/pkgs/npm/pkg).
	Target string `yaml:"target,omitempty"`
	// Mitm forces decryption for this rule even when MitmDefault is false
	// (rewrite rules decrypt regardless; a block/direct rule never does).
	Mitm bool `yaml:"mitm,omitempty"`
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
// ("registry.npmjs.org"), suffix wildcards ("*.npmjs.org"), or bare suffixes
// ("npmjs.org" matches npmjs.org and anything under it). Matching ignores
// case and a trailing dot.
func matchHost(pattern, host string) bool {
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
	bypass      []string
}

// NewDecider builds a Decider. bypassCIDRs are destinations that must never
// be intercepted (defense in depth: the iptables RETURN rules already keep
// them away; this guards a misconfigured init).
func NewDecider(rs *RuleSet, mitmDefault bool, bypassCIDRs []string) *Decider {
	return &Decider{rs: rs, mitmDefault: mitmDefault || rs.MitmDefault, bypass: bypassCIDRs}
}

// Decide classifies by hostname and (for fallback classification) the
// original destination address.
func (d *Decider) Decide(host, origDstIP string) Decision {
	if inAnyCIDR(origDstIP, d.bypass) {
		return Decision{Action: ActionDirect, Host: host}
	}
	for i := range d.rs.Rules {
		r := &d.rs.Rules[i]
		for _, m := range r.Match {
			if matchHost(m, host) {
				return Decision{Action: r.Action, Rule: r, Host: host}
			}
		}
	}
	return Decision{Action: d.rs.Default, Host: host}
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
