//go:build linux

package capture

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Chain is the nat chain the init container owns. Keeping all rules in one
// chain makes installation idempotent (flush + rebuild) and cleanup trivial.
const Chain = "EASYSIDECAR"

// Install sets up transparent TCP interception for the Pod's network
// namespace: every outbound TCP connection is DNAT'd to the sidecar's capture
// listener, except
//
//   - loopback traffic (the sidecar's own local dials),
//   - packets carrying the sidecar's fwmark (its upstream dials, set via
//     SO_MARK so the redirect cannot loop),
//   - traffic to the capture port itself.
//
// DNAT (not REDIRECT) is used because the REDIRECT target is unavailable on
// some kernels; SO_ORIGINAL_DST still recovers the pre-NAT destination. The
// DNAT target is the Pod IP (selfIP) when known, else 127.0.0.1: both reach
// the sidecar's listener, but the Pod IP also covers connections whose source
// is the host network.
func Install(selfIP string, port, mark int) error {
	host := "127.0.0.1"
	if selfIP != "" {
		host = selfIP
	}
	target := host + ":" + strconv.Itoa(port)
	rules := [][]string{
		{"-t", "nat", "-N", Chain},
		{"-t", "nat", "-F", Chain},
		{"-t", "nat", "-A", Chain, "-o", "lo", "-j", "RETURN"},
		{"-t", "nat", "-A", Chain, "-m", "mark", "--mark", fmt.Sprintf("0x%x", mark), "-j", "RETURN"},
		{"-t", "nat", "-A", Chain, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "RETURN"},
		{"-t", "nat", "-A", Chain, "-p", "tcp", "-j", "DNAT", "--to-destination", target},
	}
	for _, r := range rules {
		if err := iptables(r...); err != nil {
			return fmt.Errorf("iptables %s: %w", strings.Join(r, " "), err)
		}
	}
	// Idempotent hook: -C succeeds when already present.
	if err := iptables("-t", "nat", "-C", "OUTPUT", "-j", Chain); err != nil {
		if err := iptables("-t", "nat", "-A", "OUTPUT", "-j", Chain); err != nil {
			return fmt.Errorf("hook OUTPUT: %w", err)
		}
	}
	return nil
}

// Uninstall removes the hook and the chain (best effort).
func Uninstall() {
	_ = iptables("-t", "nat", "-D", "OUTPUT", "-j", Chain)
	_ = iptables("-t", "nat", "-F", Chain)
	_ = iptables("-t", "nat", "-X", Chain)
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
