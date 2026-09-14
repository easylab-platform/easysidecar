package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// This file implements the init-container role: install the iptables rules
// that steer the Pod's outbound traffic into easyproxy, then exit. The rules
// live in the Pod's network namespace and last for its lifetime.
//
//	OUTPUT tcp -> cluster bypass RETURN -> REDIRECT 7893   (HTTP/HTTPS)
//	OUTPUT udp 443 REJECT                                  (kill QUIC)
//	OUTPUT udp 53 REDIRECT 7894                            (DNS hijack)
//
// With -intercept-all-tcp the first rule covers every TCP port (cluster
// bypass still applies) so non-standard ports are also classified.
func runInit(cfg *Config) error {
	// Idempotency: flush our custom chain first so a retried init (pod
	// recreate re-runs it in a fresh netns; belt and braces) converges.
	run := func(args ...string) error {
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("-t", "nat", "-N", "EASYPROXY"); err != nil {
		// Chain may already exist.
		if !strings.Contains(err.Error(), "Chain already exists") {
			return err
		}
	}
	_ = run("-t", "nat", "-F", "EASYPROXY")

	// Cluster ranges must never be intercepted (internal registry, NATS,
	// gateway, kube-dns).
	for _, cidr := range cfg.BypassCIDRs {
		if err := run("-t", "nat", "-A", "EASYPROXY", "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}

	ports := []string{"80", "443"}
	if cfg.InterceptAllTCP {
		ports = nil
	}
	if ports == nil {
		if err := run("-t", "nat", "-A", "EASYPROXY", "-p", "tcp", "-j", "REDIRECT", "--to-ports", portOf(cfg.RedirAddr)); err != nil {
			return err
		}
	} else {
		for _, p := range ports {
			if err := run("-t", "nat", "-A", "EASYPROXY", "-p", "tcp", "--dport", p, "-j", "REDIRECT", "--to-ports", portOf(cfg.RedirAddr)); err != nil {
				return err
			}
		}
	}
	if err := run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "EASYPROXY"); err != nil {
		// The hook may already exist from a previous run in this netns.
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	// Kill QUIC so browsers/HTTP3 clients fall back to interceptable TCP.
	if err := run("-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"); err != nil {
		return err
	}
	// Hijack DNS so hostname-based rules see every lookup (and blocked
	// domains can be answered authoritatively).
	if err := run("-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", portOf(cfg.DNSAddr)); err != nil {
		return err
	}
	return nil
}

// portOf extracts the numeric port from a "host:port" listen address.
func portOf(addr string) string {
	_, p, err := hostPort(addr)
	if err != nil {
		return "7893"
	}
	return p
}
