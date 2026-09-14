package main

import (
	"fmt"
	"net"
	"strings"
)

// run loads the rule set and serves the listeners (spoof mode is the only
// interception mechanism).
func run(cfg *Config) error {
	return runProxy(cfg)
}

// runProxy loads rules and serves every listener until one fails. The spoof
// flag selects the no-netfilter mode (DNS + direct :443/:80 listeners) in
// place of the REDIRECT listener.
func runProxy(cfg *Config) error {
	rules, err := LoadRules(cfg.RulesFile)
	if err != nil {
		return err
	}
	logger := &ConnLogger{}
	decisions := NewDecider(rules, cfg.MitmDefault, cfg.BypassCIDRs)

	// MITM authority (nil when no CA configured: rewrite rules then fail
	// closed with a clear error instead of silently bypassing policy).
	var mitm *MITM
	if cfg.CaCert != "" && cfg.CaKey != "" {
		mitm, err = LoadMITM(cfg.CaCert, cfg.CaKey)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
	} else if rules.HasRewrite() {
		return fmt.Errorf("rules contain rewrite entries but no -ca-cert/-ca-key: rewrite requires MITM")
	}

	// Spoof is the only interception mode: DNS-based, no netfilter.
	return runSpoof(cfg, decisions, mitm, logger)
}

// runSpoof serves the dns-spoof mode listeners: the resolver plus the direct
// TLS/HTTP faces. It composes with an upstream egress proxy (mihomo) for
// DIRECT traffic.
func runSpoof(cfg *Config, decisions *Decider, mitm *MITM, logger *ConnLogger) error {
	upstreams := []string{withPort(cfg.UpstreamDNS, "53")}
	dns := &SpoofDNS{
		Addr: cfg.SpoofDNSAddr, SelfIP: cfg.SelfIP,
		UpstreamDNS: upstreams, Decider: decisions, Logger: logger,
	}
	tcp := &SpoofTCP{
		TLSAddr: cfg.SpoofTLSAddr, HTTPAddr: cfg.SpoofHTTPAddr,
		Decider: decisions, MITM: mitm, UpstreamProxy: cfg.UpstreamProxy, Logger: logger,
	}
	logger.Log(ConnLogEntry{Action: "info", Dst: "spoof mode: self=" + cfg.SelfIP +
		" dns-upstream=" + strings.Join(upstreams, ",") + " egress-proxy=" + cfg.UpstreamProxy})

	errCh := make(chan error, 2)
	go func() { errCh <- dns.Serve() }()
	go func() { errCh <- tcp.Serve() }()
	return <-errCh
}

// withPort appends :53 when an upstream resolver is given as a bare IP.
func withPort(host, port string) string {
	if host == "" {
		return "8.8.8.8:53"
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Contains(host, ":") { // bare IPv6
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
