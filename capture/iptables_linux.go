//go:build linux

// Package capture implements privileged transparent interception: the
// iptables rules an init container installs and the SO_ORIGINAL_DST lookup
// that recovers the destination a redirected connection was really addressed
// to.
package capture

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Chain names. One chain per purpose keeps installation idempotent (flush +
// rebuild) and cleanup trivial.
const (
	// ChainNat is the nat/OUTPUT chain: DNS forcing + TCP redirect.
	ChainNat = "EASYSIDECAR"
	// ChainPre is the nat/PREROUTING chain: same, for forwarded (VM) traffic.
	ChainPre = "EASYSIDECAR_PRE"
	// ChainFilt is the filter/OUTPUT chain: UDP policy + default egress policy.
	ChainFilt = "EASYSIDECAR_EGRESS"
	// ChainFwd is the filter/FORWARD chain: the forwarded-traffic equivalent.
	ChainFwd = "EASYSIDECAR_FORWARD"
)

// Mark is the fwmark stamped on the sidecar's own outbound sockets so the nat
// chain exempts them from the redirect (no self-loop).
const Mark = 0x1e1

// Policy describes the interception rules for one Pod network namespace.
type Policy struct {
	// SelfIP is the Pod IP (DNAT target). Empty uses 127.0.0.1.
	SelfIP string
	// CapturePort is the TCP listener for redirected connections.
	CapturePort int
	// ForwardPort is the TCP listener for forwarded (VM guest) connections;
	// 0 disables the PREROUTING/FORWARD rules.
	ForwardPort int
	// DNSPort is the sidecar resolver's port (DNS is forced there).
	DNSPort int
	// UDPCapturePort is the sidecar listener for other redirected UDP; 0
	// disables UDP capture (UDP then only gets the log/reject policy).
	UDPCapturePort int
	// Mark is the fwmark exempting the sidecar's own sockets.
	Mark int

	// DNSUpstream is the real resolver the sidecar forwards to
	// ("ip:port" or "ip"); it is exempt so the sidecar's own DNS dials are not
	// redirected back into itself.
	DNSUpstream string
	// UDPAllow are manually-allowed UDP endpoints ("host" or "cidr", optionally
	// ":port"); UDP traffic to them is returned unmodified. They are emitted
	// before the h3 rule so an explicitly-allowed endpoint wins.
	UDPAllow []string
	// UDPMode is "log" (log + pass) or "reject" for UDP that is neither DNS,
	// h3 nor an allowed endpoint.
	UDPMode string
	// DefaultMode is "log" or "reject" for all other egress (ICMP, raw, and
	// any protocol the nat chain did not DNAT).
	DefaultMode string
	// ExemptCIDRs are destinations that always pass (cluster resolver,
	// apiserver, node/Pod/Service CIDRs).
	ExemptCIDRs []string
	// UIDs are local UIDs exempt from redirection (owner match).
	UIDs []string
}

// invocation is one iptables/ip6tables command. bestEffort tolerates the
// benign "chain exists / hook absent" errors of -N and -D.
type invocation struct {
	bin        string
	args       []string
	bestEffort bool
}

// execCommand is the exec seam (tests replace it to capture invocations).
var execCommand = exec.Command

// Install builds and applies the interception rules for both address families.
// It is idempotent: the chains are created if absent, flushed, then rebuilt.
func Install(p Policy) error {
	p = withDefaults(p)
	for _, inv := range buildRules(p, false) {
		if err := run(inv); err != nil {
			return err
		}
	}
	// IPv6 is best-effort: many Pods have no IPv6 at all, and the kernel may
	// lack ip6tables. Interception over v6 is not implemented yet, so v6 egress
	// only gets the log/reject policy (it cannot be captured).
	for _, inv := range buildRules(p, true) {
		_ = run(inv)
	}
	return nil
}

// Uninstall removes every hook and chain (best effort).
func Uninstall() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		for _, c := range []struct{ table, parent, chain string }{
			{"nat", "OUTPUT", ChainNat},
			{"nat", "PREROUTING", ChainPre},
			{"filter", "OUTPUT", ChainFilt},
			{"filter", "FORWARD", ChainFwd},
		} {
			_ = run(invocation{bin, []string{"-t", c.table, "-D", c.parent, "-j", c.chain}, true})
			_ = run(invocation{bin, []string{"-t", c.table, "-F", c.chain}, true})
			_ = run(invocation{bin, []string{"-t", c.table, "-X", c.chain}, true})
		}
	}
}

func withDefaults(p Policy) Policy {
	if p.CapturePort == 0 {
		p.CapturePort = 15001
	}
	if p.DNSPort == 0 {
		p.DNSPort = 53
	}
	if p.Mark == 0 {
		p.Mark = Mark
	}
	if p.UDPMode == "" {
		p.UDPMode = "log"
	}
	if p.DefaultMode == "" {
		p.DefaultMode = "log"
	}
	return p
}

// buildRules returns the ordered invocations for one address family.
func buildRules(p Policy, v6 bool) []invocation {
	bin := "iptables"
	rejectWith := "icmp-port-unreachable"
	if v6 {
		bin = "ip6tables"
		rejectWith = "icmp6-port-unreachable"
	}
	dst := p.dnatHost()
	var out []invocation
	add := func(table string, args ...string) {
		out = append(out, invocation{bin, append([]string{"-t", table}, args...), false})
	}
	best := func(table string, args ...string) {
		out = append(out, invocation{bin, append([]string{"-t", table}, args...), true})
	}
	// ensure creates/flushes a chain and (re)hooks it at the top of parent.
	ensure := func(table, parent, chain string) {
		best(table, "-N", chain)
		add(table, "-F", chain)
		best(table, "-D", parent, "-j", chain)
		add(table, "-I", parent, "-j", chain)
	}
	dnat := func(table, chain, proto string, dport int, port int) {
		add(table, "-A", chain, "-p", proto, "--dport", strconv.Itoa(dport),
			"-j", "DNAT", "--to-destination", net.JoinHostPort(dst, strconv.Itoa(port)))
	}

	// ---- nat: DNS forcing + TCP redirect ----
	ensure("nat", "OUTPUT", ChainNat)
	add("nat", "-A", ChainNat, "-o", "lo", "-j", "RETURN")
	add("nat", "-A", ChainNat, "-m", "mark", "--mark", hexMark(p.Mark), "-j", "RETURN")
	for _, uid := range p.UIDs {
		add("nat", "-A", ChainNat, "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
	}
	if ip := hostOnly(p.DNSUpstream); ip != "" {
		add("nat", "-A", ChainNat, "-d", ip, "-p", "udp", "--dport", "53", "-j", "RETURN")
		add("nat", "-A", ChainNat, "-d", ip, "-p", "tcp", "--dport", "53", "-j", "RETURN")
	}
	add("nat", "-A", ChainNat, "-p", "tcp", "--dport", strconv.Itoa(p.CapturePort), "-j", "RETURN")
	add("nat", "-A", ChainNat, "-p", "tcp", "--dport", strconv.Itoa(p.DNSPort), "-j", "RETURN")
	add("nat", "-A", ChainNat, "-p", "udp", "--dport", strconv.Itoa(p.DNSPort), "-j", "RETURN")
	if !v6 {
		// Force DNS to the sidecar resolver (any configured resolver is
		// overridden; only the exempt upstream above escapes).
		dnat("nat", ChainNat, "udp", 53, p.DNSPort)
		dnat("nat", ChainNat, "tcp", 53, p.DNSPort)
		// Manually-allowed UDP destinations are not redirected (they pass).
		for _, ep := range p.UDPAllow {
			if ep = strings.TrimSpace(ep); ep == "" {
				continue
			}
			add("nat", "-A", ChainNat, "-p", "udp", "-d", ep, "-j", "RETURN")
		}
		// Other UDP goes to the UDP capture listener so it is logged (and
		// relayed) with its real destination. In reject mode the filter chain
		// drops disallowed flows before they can be useful; we still redirect
		// so the drop is logged by the sidecar rather than the kernel.
		if p.UDPCapturePort > 0 {
			add("nat", "-A", ChainNat, "-p", "udp", "-j", "DNAT",
				"--to-destination", net.JoinHostPort(dst, strconv.Itoa(p.UDPCapturePort)))
		}
		// Redirect every remaining TCP connection to the capture listener.
		add("nat", "-A", ChainNat, "-p", "tcp", "-j", "DNAT",
			"--to-destination", net.JoinHostPort(dst, strconv.Itoa(p.CapturePort)))
	}

	// ---- nat PREROUTING: forwarded (VM guest) traffic ----
	if p.ForwardPort > 0 {
		ensure("nat", "PREROUTING", ChainPre)
		add("nat", "-A", ChainPre, "-m", "mark", "--mark", hexMark(p.Mark), "-j", "RETURN")
		add("nat", "-A", ChainPre, "-p", "tcp", "--dport", strconv.Itoa(p.ForwardPort), "-j", "RETURN")
		if !v6 {
			dnat("nat", ChainPre, "udp", 53, p.DNSPort)
			dnat("nat", ChainPre, "tcp", 53, p.DNSPort)
			for _, ep := range p.UDPAllow {
				if ep = strings.TrimSpace(ep); ep == "" {
					continue
				}
				add("nat", "-A", ChainPre, "-p", "udp", "-d", ep, "-j", "RETURN")
			}
			if p.UDPCapturePort > 0 {
				add("nat", "-A", ChainPre, "-p", "udp", "-j", "DNAT",
					"--to-destination", net.JoinHostPort(dst, strconv.Itoa(p.UDPCapturePort)))
			}
			add("nat", "-A", ChainPre, "-p", "tcp", "-j", "DNAT",
				"--to-destination", net.JoinHostPort(dst, strconv.Itoa(p.ForwardPort)))
		}
	}

	// ---- filter: UDP policy + default egress policy ----
	exempt := func(chain string) {
		add("filter", "-A", chain, "-o", "lo", "-j", "RETURN")
		if self := p.selfIPOnly(); self != "" {
			add("filter", "-A", chain, "-d", self, "-j", "RETURN")
		}
		add("filter", "-A", chain, "-m", "mark", "--mark", hexMark(p.Mark), "-j", "RETURN")
		for _, uid := range p.UIDs {
			add("filter", "-A", chain, "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
		}
		if ip := hostOnly(p.DNSUpstream); ip != "" {
			add("filter", "-A", chain, "-d", ip, "-j", "RETURN")
		}
		for _, c := range p.ExemptCIDRs {
			if c = strings.TrimSpace(c); c != "" {
				add("filter", "-A", chain, "-d", c, "-j", "RETURN")
			}
		}
	}
	// match builds "-p proto [--dport N]" for a policy stage.
	match := func(proto, dport string) []string {
		var m []string
		if proto != "" {
			m = append(m, "-p", proto)
		}
		if dport != "" {
			m = append(m, "--dport", dport)
		}
		return m
	}
	// stage logs (best-effort: LOG needs nf_log, absent on some kernels) then
	// applies the mode to exactly the same match.
	stage := func(chain, proto, dport, kind, mode string) {
		m := match(proto, dport)
		logArgs := append(append([]string{"-A", chain}, m...), "-j", "LOG", "--log-prefix", logPrefix(kind))
		best("filter", logArgs...)
		act := append(append([]string{"-A", chain}, m...), "-j")
		if mode == "reject" {
			act = append(act, "REJECT", "--reject-with", rejectWith)
		} else {
			act = append(act, "RETURN")
		}
		add("filter", act...)
	}
	policy := func(chain string) {
		// Manually-allowed UDP endpoints win over the h3/generic UDP policy.
		for _, ep := range p.UDPAllow {
			if ep = strings.TrimSpace(ep); ep == "" {
				continue
			}
			add("filter", "-A", chain, "-p", "udp", "-d", ep, "-j", "RETURN")
		}
		// h3 next: no QUIC interception yet, so udp/443 follows the UDP mode.
		stage(chain, "udp", "443", "H3", p.UDPMode)
		stage(chain, "udp", "", "UDP", p.UDPMode)
		stage(chain, "", "", "EGRESS", p.DefaultMode)
	}

	ensure("filter", "OUTPUT", ChainFilt)
	exempt(ChainFilt)
	policy(ChainFilt)

	if p.ForwardPort > 0 {
		ensure("filter", "FORWARD", ChainFwd)
		exempt(ChainFwd)
		policy(ChainFwd)
	}
	return out
}

func (p Policy) dnatHost() string {
	if p.SelfIP == "" || p.SelfIP == "0.0.0.0" {
		return "127.0.0.1"
	}
	return p.SelfIP
}

func (p Policy) selfIPOnly() string {
	if p.SelfIP == "" || p.SelfIP == "0.0.0.0" {
		return ""
	}
	return p.SelfIP
}

func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func hexMark(m int) string { return fmt.Sprintf("0x%x", m) }

func logPrefix(kind string) string { return "EASYSIDECAR-" + kind + " " }

// run executes one invocation. bestEffort invocations swallow their error
// (used for -N/-D, whose "exists"/"absent" failures are expected).
func run(inv invocation) error {
	out, err := execCommand(inv.bin, inv.args...).CombinedOutput()
	if err != nil {
		if inv.bestEffort {
			return nil
		}
		return fmt.Errorf("%s %s: %v: %s", inv.bin, strings.Join(inv.args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
