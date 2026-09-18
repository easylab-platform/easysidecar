//go:build linux

package capture

import (
	"strings"
	"testing"
)

// argsOf renders invocations as "bin table -A chain ..." for assertions.
func argsOf(invs []invocation) []string {
	out := make([]string, 0, len(invs))
	for _, inv := range invs {
		out = append(out, inv.bin+" "+strings.Join(inv.args, " "))
	}
	return out
}

func containsRule(invs []invocation, want string) bool {
	for _, s := range argsOf(invs) {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func TestBuildRulesForcesDNSAndTCP(t *testing.T) {
	invs := buildRules(withDefaults(Policy{SelfIP: "10.1.2.3"}), false)
	for _, want := range []string{
		"nat -A EASYSIDECAR -p udp --dport 53 -j DNAT --to-destination 10.1.2.3:53",
		"nat -A EASYSIDECAR -p tcp --dport 53 -j DNAT --to-destination 10.1.2.3:53",
		"nat -A EASYSIDECAR -p tcp -j DNAT --to-destination 10.1.2.3:15001",
		"filter -A EASYSIDECAR_EGRESS -p udp --dport 443 -j LOG",
		"filter -A EASYSIDECAR_EGRESS -p udp -j LOG",
		"filter -A EASYSIDECAR_EGRESS -j LOG",
	} {
		if !containsRule(invs, want) {
			t.Errorf("missing rule %q in:\n%s", want, strings.Join(argsOf(invs), "\n"))
		}
	}
	// Loopback and fwmark always RETURN first.
	if !containsRule(invs, "nat -A EASYSIDECAR -o lo -j RETURN") {
		t.Error("loopback RETURN missing")
	}
	if !containsRule(invs, "nat -A EASYSIDECAR -m mark --mark 0x1e1 -j RETURN") {
		t.Error("fwmark RETURN missing")
	}
}

func TestBuildRulesRejectModes(t *testing.T) {
	invs := buildRules(withDefaults(Policy{SelfIP: "10.1.2.3", UDPMode: "reject", DefaultMode: "reject"}), false)
	// h3 UDP, generic UDP and default egress all reject.
	for _, want := range []string{
		"filter -A EASYSIDECAR_EGRESS -p udp --dport 443 -j REJECT",
		"filter -A EASYSIDECAR_EGRESS -p udp -j REJECT",
		"filter -A EASYSIDECAR_EGRESS -j REJECT",
	} {
		if !containsRule(invs, want) {
			t.Errorf("missing reject rule %q in:\n%s", want, strings.Join(argsOf(invs), "\n"))
		}
	}
}

func TestBuildRulesUDPAllowAndExempts(t *testing.T) {
	invs := buildRules(withDefaults(Policy{
		SelfIP:      "10.1.2.3",
		UDPAllow:    []string{"1.2.3.4", "10.0.0.0/8:123"},
		ExemptCIDRs: []string{"172.18.0.10/32"},
		DNSUpstream: "172.18.0.10:53",
		UIDs:        []string{"1000"},
	}), false)
	for _, want := range []string{
		"filter -A EASYSIDECAR_EGRESS -p udp -d 1.2.3.4 -j RETURN",
		"filter -A EASYSIDECAR_EGRESS -p udp -d 10.0.0.0/8:123 -j RETURN",
		"filter -A EASYSIDECAR_EGRESS -d 172.18.0.10/32 -j RETURN",
		"filter -A EASYSIDECAR_EGRESS -d 172.18.0.10 -j RETURN",
		"nat -A EASYSIDECAR -m owner --uid-owner 1000 -j RETURN",
	} {
		if !containsRule(invs, want) {
			t.Errorf("missing rule %q in:\n%s", want, strings.Join(argsOf(invs), "\n"))
		}
	}
}

func TestBuildRulesForward(t *testing.T) {
	invs := buildRules(withDefaults(Policy{SelfIP: "10.1.2.3", ForwardPort: 15006}), false)
	for _, want := range []string{
		"nat -A EASYSIDECAR_PRE -p tcp -j DNAT --to-destination 10.1.2.3:15006",
		"filter -A EASYSIDECAR_FORWARD -p udp -j LOG",
	} {
		if !containsRule(invs, want) {
			t.Errorf("missing forwarded rule %q in:\n%s", want, strings.Join(argsOf(invs), "\n"))
		}
	}
}

func TestBuildRulesV6HasNoCaptureDNAT(t *testing.T) {
	invs := buildRules(withDefaults(Policy{SelfIP: "10.1.2.3"}), true)
	for _, s := range argsOf(invs) {
		if strings.Contains(s, "ip6tables nat") && strings.Contains(s, "DNAT") {
			t.Fatalf("v6 must not DNAT (no v6 capture yet): %s", s)
		}
	}
	if !containsRule(invs, "ip6tables -t filter -A EASYSIDECAR_EGRESS -j LOG") {
		t.Error("v6 egress policy missing")
	}
}

func TestChainNamesStable(t *testing.T) {
	if ChainNat == "" || ChainPre == "" || ChainFilt == "" || ChainFwd == "" {
		t.Fatal("chain names must be set")
	}
}
