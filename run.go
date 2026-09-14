package main

import (
	"fmt"
	"net"
)

// run dispatches on the process role. Init mode installs iptables rules and
// exits; proxy mode loads the rule set and serves the listeners.
func run(cfg *Config) error {
	switch cfg.Mode {
	case ModeInit:
		return runInit(cfg)
	case ModeProxy:
		return runProxy(cfg)
	}
	return fmt.Errorf("unhandled mode %q", cfg.Mode)
}

// runProxy loads rules and serves every listener until one fails.
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

	errCh := make(chan error, 3)
	go func() { errCh <- ServeRedir(cfg.RedirAddr, decisions, mitm, logger) }()
	go func() {
		ln, err := net.Listen("tcp", cfg.ConnectAddr)
		if err != nil {
			errCh <- fmt.Errorf("connect listen %s: %w", cfg.ConnectAddr, err)
			return
		}
		errCh <- ServeConnect(ln, decisions, mitm, logger)
	}()
	go func() { errCh <- ServeDNS(cfg.DNSAddr, decisions, logger) }()
	return <-errCh
}
