// Package easyproxy is a lightweight transparent egress proxy for EasyLab
// workloads (CI builds, sandboxes, services). An init container installs
// iptables rules that REDIRECT outbound TCP 80/443 (and UDP/53 DNS) into
// easyproxy; easyproxy then classifies every connection by hostname — SNI for
// TLS, Host header for plain HTTP, the original destination for the rest —
// against a rule set and applies one of three actions:
//
//	block   reset the connection immediately
//	direct  splice the bytes through to the real destination (no decryption)
//	rewrite decrypt (MITM, when the rule opts in) and forward to an EasyLab
//	        pull-through endpoint instead of the original destination
//
// easyproxy is NOT a general-purpose proxy: it is the enforcement point for
// workload egress policy (blocklist, force-through-internal-registry), kept
// intentionally small and auditable.
package main

import "log"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("easyproxy: %v", err)
	}
	if err := run(cfg); err != nil {
		log.Fatalf("easyproxy: %v", err)
	}
}
