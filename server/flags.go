package server

import (
	"flag"
	"fmt"
	"os"

	"github.com/easylab-platform/easysidecar/relay"
)

// Mode selects the process role. Today there is exactly one: the long-running
// proxy. (An iptables "init" role existed while REDIRECT mode was implemented;
// DNS-spoof replaced it and needs no netfilter.) It is kept as a value so a
// future init/capture role can be added without reshaping the CLI.
type Mode string

const (
	ModeProxy Mode = "proxy"
)

// Config is the assembled runtime configuration.
type Config struct {
	Mode Mode
	// RulesFile is the YAML rule set.
	RulesFile string
	// CaCert/CaKey are the MITM CA paths (empty disables MITM, which is only
	// valid when no rewrite rule is present).
	CaCert, CaKey string
	// MitmDefault, when true, decrypts every intercepted TLS connection that
	// reaches the decision point (the rewrite rules always decrypt). Default
	// false: only rewrite rules decrypt.
	MitmDefault bool

	// DNS-spoof is the interception mechanism: the sidecar is the Pod's
	// resolver and answers rewrite-matched names with its own IP, then serves
	// :443/:80 directly. No NET_ADMIN, no iptables, no tun.
	//
	// Spoof enables it.
	Spoof bool
	// SelfIP is the address the sidecar answers spoofed names with (the Pod
	// IP). Defaults from POD_IP, then the first non-loopback IPv4.
	SelfIP string
	// UpstreamDNS is the real resolver the sidecar forwards DIRECT queries
	// to (the cluster CoreDNS service IP). Required.
	UpstreamDNS string
	// UpstreamProxy is an optional upstream HTTP proxy (e.g. mihomo) used for
	// DIRECT egress, so spoof mode composes with the cluster egress proxy
	// instead of dialing from the Pod directly.
	UpstreamProxy string
	// Spoof listen addresses.
	SpoofDNSAddr, SpoofTLSAddr, SpoofHTTPAddr string
}

func ParseFlags() (*Config, error) {
	cfg := &Config{}
	flag.Var((*modeFlag)(&cfg.Mode), "mode", "process role: proxy (default)")
	flag.StringVar(&cfg.RulesFile, "rules", "", "YAML rule set file")
	flag.StringVar(&cfg.CaCert, "ca-cert", "", "MITM CA certificate PEM")
	flag.StringVar(&cfg.CaKey, "ca-key", "", "MITM CA private key PEM")
	flag.BoolVar(&cfg.MitmDefault, "mitm-default", false, "decrypt all intercepted TLS (not just rewrite rules)")
	flag.BoolVar(&cfg.Spoof, "spoof", false, "dns-spoof mode: answer DNS + listen on 80/443 directly (no iptables/tun)")
	flag.StringVar(&cfg.SelfIP, "self-ip", "", "spoof mode: Pod IP to answer spoofed names with (default POD_IP, then first non-loopback IPv4)")
	flag.StringVar(&cfg.UpstreamDNS, "upstream-dns", "", "spoof mode: real resolver for DIRECT queries (cluster CoreDNS)")
	flag.StringVar(&cfg.UpstreamProxy, "upstream-proxy", "", "optional upstream HTTP proxy for DIRECT egress (e.g. mihomo)")
	flag.StringVar(&cfg.SpoofDNSAddr, "spoof-dns-addr", "0.0.0.0:53", "spoof mode: DNS listen address")
	flag.StringVar(&cfg.SpoofTLSAddr, "spoof-tls-addr", "0.0.0.0:443", "spoof mode: TLS listen address")
	flag.StringVar(&cfg.SpoofHTTPAddr, "spoof-http-addr", "0.0.0.0:80", "spoof mode: plain-HTTP listen address")
	flag.Parse()

	if cfg.Mode == "" {
		cfg.Mode = ModeProxy
	}
	switch cfg.Mode {
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
				ip, err := relay.FirstNonLoopbackIPv4()
				if err != nil {
					return nil, fmt.Errorf("spoof mode: cannot determine self IP: %w", err)
				}
				cfg.SelfIP = ip
			}
		}
	default:
		return nil, fmt.Errorf("unknown mode %q (proxy)", string(cfg.Mode))
	}
	return cfg, nil
}

// modeFlag adapts Mode to flag.Value.
type modeFlag Mode

func (m *modeFlag) String() string { return string(*m) }

func (m *modeFlag) Set(s string) error {
	switch Mode(s) {
	case ModeProxy:
		*m = modeFlag(Mode(s))
		return nil
	}
	return fmt.Errorf("invalid mode %q (proxy)", s)
}
