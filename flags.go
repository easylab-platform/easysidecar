package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Mode selects the process role. The single image serves both the init
// container (installs iptables rules, then exits) and the long-running proxy.
type Mode string

const (
	ModeProxy Mode = "proxy"
	ModeInit  Mode = "init"
)

// Config is the assembled runtime configuration.
type Config struct {
	Mode Mode
	// RulesFile is the YAML rule set (proxy mode).
	RulesFile string
	// CaCert/CaKey are the MITM CA paths (proxy mode; empty disables MITM).
	CaCert, CaKey string
	// CIDRs to never intercept (cluster service/pod ranges, the internal
	// registry, loopback). Used by init mode for RETURN rules and by proxy
	// mode to double-check the original destination.
	BypassCIDRs []string
	// Listen addresses (proxy mode).
	RedirAddr, DNSAddr, ConnectAddr string
	// MitmDefault, when true, decrypts every intercepted TLS connection that
	// reaches the decision point (the rewrite rules always decrypt). Default
	// false: only rewrite rules decrypt.
	MitmDefault bool
	// InterceptAllTCP extends the init iptables rules from 80/443 to all TCP
	// (cluster bypass still applies). Default false.
	InterceptAllTCP bool

	// ---- dns-spoof mode (no netfilter) ----
	//
	// Spoof enables the no-kernel-dependency interception mode: the sidecar
	// answers DNS itself (returning its own Pod IP for rewrite-matched
	// hostnames, NXDOMAIN for blocked ones, the real answer otherwise) and
	// listens directly on TCP :443/:80. Workloads get dnsConfig pointing at
	// the sidecar. Requires no NET_ADMIN, no iptables, no tun.
	Spoof bool
	// SelfIP is the address the sidecar answers spoofed names with (the Pod
	// IP). Defaults from POD_IP, then the first non-loopback IPv4.
	SelfIP string
	// UpstreamDNS is the real resolver the sidecar forwards DIRECT queries
	// to (the cluster CoreDNS service IP). Required in spoof mode.
	UpstreamDNS string
	// UpstreamProxy is an optional upstream HTTP proxy (e.g. mihomo) used for
	// DIRECT egress, so spoof mode composes with an existing cluster egress
	// proxy instead of dialing from the Pod directly.
	UpstreamProxy string
	// Spoof listen addresses (spoof mode).
	SpoofDNSAddr, SpoofTLSAddr, SpoofHTTPAddr string
}

func parseFlags() (*Config, error) {
	cfg := &Config{}
	flag.Var((*modeFlag)(&cfg.Mode), "mode", "process role: proxy (default) or init")
	flag.StringVar(&cfg.RulesFile, "rules", "", "YAML rule set file (proxy mode)")
	flag.StringVar(&cfg.CaCert, "ca-cert", "", "MITM CA certificate PEM (proxy mode)")
	flag.StringVar(&cfg.CaKey, "ca-key", "", "MITM CA private key PEM (proxy mode)")
	bypass := flag.String("bypass-cidrs", "", "comma-separated CIDRs to never intercept (cluster ranges)")
	flag.StringVar(&cfg.RedirAddr, "redir-addr", "127.0.0.1:7893", "transparent REDIRECT listener")
	flag.StringVar(&cfg.DNSAddr, "dns-addr", "127.0.0.1:7894", "DNS hijack listener (UDP/53 redirected here)")
	flag.StringVar(&cfg.ConnectAddr, "connect-addr", "127.0.0.1:7890", "explicit HTTP CONNECT proxy listener")
	flag.BoolVar(&cfg.MitmDefault, "mitm-default", false, "decrypt all intercepted TLS (not just rewrite rules)")
	flag.BoolVar(&cfg.InterceptAllTCP, "intercept-all-tcp", false, "init mode: intercept all TCP, not just 80/443")
	flag.BoolVar(&cfg.Spoof, "spoof", false, "dns-spoof mode: answer DNS + listen on 80/443 directly (no iptables/tun)")
	flag.StringVar(&cfg.SelfIP, "self-ip", "", "spoof mode: Pod IP to answer spoofed names with (default POD_IP, then first non-loopback IPv4)")
	flag.StringVar(&cfg.UpstreamDNS, "upstream-dns", "", "spoof mode: real resolver for DIRECT queries (cluster CoreDNS)")
	flag.StringVar(&cfg.UpstreamProxy, "upstream-proxy", "", "optional upstream HTTP proxy for DIRECT egress (e.g. mihomo)")
	flag.StringVar(&cfg.SpoofDNSAddr, "spoof-dns-addr", "0.0.0.0:53", "spoof mode: DNS listen address")
	flag.StringVar(&cfg.SpoofTLSAddr, "spoof-tls-addr", "0.0.0.0:443", "spoof mode: TLS listen address")
	flag.StringVar(&cfg.SpoofHTTPAddr, "spoof-http-addr", "0.0.0.0:80", "spoof mode: plain-HTTP listen address")
	flag.Parse()

	for _, c := range strings.Split(*bypass, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			cfg.BypassCIDRs = append(cfg.BypassCIDRs, c)
		}
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeProxy
	}
	switch cfg.Mode {
	case ModeInit:
		if len(cfg.BypassCIDRs) == 0 {
			return nil, fmt.Errorf("init mode requires -bypass-cidrs")
		}
	case ModeProxy:
		if cfg.RulesFile == "" {
			return nil, fmt.Errorf("proxy mode requires -rules")
		}
		if cfg.Spoof {
			if cfg.UpstreamDNS == "" {
				return nil, fmt.Errorf("spoof mode requires -upstream-dns")
			}
			if cfg.SelfIP == "" {
				cfg.SelfIP = os.Getenv("POD_IP")
			}
			if cfg.SelfIP == "" {
				ip, err := firstNonLoopbackIPv4()
				if err != nil {
					return nil, fmt.Errorf("spoof mode: cannot determine self IP: %w", err)
				}
				cfg.SelfIP = ip
			}
		}
	default:
		return nil, fmt.Errorf("unknown mode %q (proxy|init)", string(cfg.Mode))
	}
	return cfg, nil
}

// modeFlag adapts Mode to flag.Value.
type modeFlag Mode

func (m *modeFlag) String() string { return string(*m) }

func (m *modeFlag) Set(s string) error {
	switch Mode(s) {
	case ModeProxy, ModeInit:
		*m = modeFlag(Mode(s))
		return nil
	}
	return fmt.Errorf("invalid mode %q (proxy|init)", s)
}
