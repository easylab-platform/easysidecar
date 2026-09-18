package server

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/easylab-platform/easysidecar/relay"
)

// Mode selects the process role. Today there is exactly one: the long-running
// proxy. (An iptables "init" role existed while REDIRECT mode was implemented;
// DNS-spoof replaced it and needs no netfilter.) It is kept as a value so a
// future init/capture role can be added without reshaping the CLI.
type Mode string

const (
	ModeProxy Mode = "proxy"
	// ModeCapture is the privileged all-port face: an init container installs
	// iptables rules that REDIRECT/DNAT the Pod's outbound TCP to -capture-addr,
	// and the sidecar recovers the real destination via SO_ORIGINAL_DST. It is
	// the same process as proxy mode plus a capture listener; DNS is NOT
	// intercepted (the workload keeps the cluster resolver).
	ModeCapture Mode = "capture"
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

	// Capture mode: listen for iptables-redirected TCP and recover the real
	// destination from SO_ORIGINAL_DST. CaptureAddr is the high port the init
	// container's rules target (default 0.0.0.0:15001).
	CaptureAddr string
	// CaptureInit, when true, installs the iptables rules and exits (the init
	// container role). Requires NET_ADMIN.
	CaptureInit bool
	// CaptureUIDs exempts these UIDs from redirection (the sidecar itself).
	CaptureUIDs []string
	// CaptureDNS, when true, also runs the spoof resolver alongside capture.
	// Capture alone cannot reach a rewrite host whose name does not resolve
	// publicly (NXDOMAIN); the resolver answers those with SelfIP, and the
	// netfilter redirect then steers the connection to the capture listener.
	// Requires SelfIP and UpstreamDNS, and the Pod must use the sidecar as its
	// resolver (dnsPolicy=None).
	CaptureDNS bool
	// CaptureForwardAddr is the listener for forwarded (VM guest) connections.
	// Non-empty enables the PREROUTING/FORWARD rules. Empty disables.
	CaptureForwardAddr string
	// CaptureUDPAllow lists manually-allowed UDP endpoints ("host" or "cidr",
	// optionally ":port"). UDP to them passes unmodified.
	CaptureUDPAllow []string
	// CaptureUDPMode is "log" (default) or "reject": what happens to UDP that
	// is not DNS, not h3 and not in CaptureUDPAllow.
	CaptureUDPMode string
	// CaptureDefaultMode is "log" (default) or "reject": what happens to all
	// other egress (ICMP, raw, uncaptured protocols).
	CaptureDefaultMode string
	// CaptureExemptCIDRs always pass (cluster resolver, apiserver, node/Pod/
	// Service CIDRs). Only meaningful for the log/reject policies.
	CaptureExemptCIDRs []string
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
	flag.StringVar(&cfg.CaptureAddr, "capture-addr", "0.0.0.0:15001", "capture mode: listen address for redirected TCP")
	flag.BoolVar(&cfg.CaptureInit, "capture-init", false, "capture mode: install iptables rules and exit (init container role)")
	flag.BoolVar(&cfg.CaptureDNS, "capture-dns", false, "capture mode: also run the spoof resolver (for rewrite names that do not resolve publicly)")
	uids := flag.String("capture-uids", "", "capture mode: comma-separated UIDs exempt from redirection (default: the sidecar's own UID)")
	forwardAddr := flag.String("capture-forward-addr", "", "capture mode: listener for forwarded (VM guest) TCP; non-empty enables PREROUTING/FORWARD rules")
	udpAllow := flag.String("capture-udp-allow", "", "capture mode: comma-separated UDP endpoints that always pass (host[:port] or cidr[:port])")
	flag.StringVar(&cfg.CaptureUDPMode, "capture-udp-mode", "log", "capture mode: policy for non-DNS/h3 UDP: log|reject")
	flag.StringVar(&cfg.CaptureDefaultMode, "capture-default-mode", "log", "capture mode: policy for other egress (ICMP/raw): log|reject")
	exempt := flag.String("capture-exempt-cidrs", "", "capture mode: comma-separated CIDRs that always pass (resolver/apiserver/node/pod/service)")
	flag.Parse()
	cfg.CaptureUIDs = splitCSV(*uids)
	cfg.CaptureUDPAllow = splitCSV(*udpAllow)
	cfg.CaptureExemptCIDRs = splitCSV(*exempt)
	cfg.CaptureForwardAddr = *forwardAddr

	if cfg.Mode == "" {
		cfg.Mode = ModeProxy
	}
	// The upstream proxy is configured as an HTTP URL; the dialers want
	// host:port. Normalize once here so every face agrees.
	cfg.UpstreamProxy = hostPort(cfg.UpstreamProxy)
	switch cfg.Mode {
	case ModeProxy, ModeCapture:
		if cfg.Mode == ModeCapture && cfg.CaptureInit {
			// The init container only installs the netfilter redirect; it
			// needs neither a rule set nor DNS/self-IP.
			return cfg, nil
		}
		if cfg.RulesFile == "" {
			return nil, fmt.Errorf("%s mode requires -rules", cfg.Mode)
		}
		if cfg.Spoof || cfg.Mode == ModeCapture {
			if (cfg.Spoof || cfg.CaptureDNS) && cfg.UpstreamDNS == "" {
				return nil, fmt.Errorf("%s requires -upstream-dns", dnsModeName(cfg))
			}
			if cfg.Spoof || cfg.CaptureDNS {
				if cfg.SelfIP == "" {
					cfg.SelfIP = os.Getenv("POD_IP")
				}
				if cfg.SelfIP == "" {
					ip, err := relay.FirstNonLoopbackIPv4()
					if err != nil {
						return nil, fmt.Errorf("%s: cannot determine self IP: %w", dnsModeName(cfg), err)
					}
					cfg.SelfIP = ip
				}
			}
		}
	default:
		return nil, fmt.Errorf("unknown mode %q (proxy|capture)", string(cfg.Mode))
	}
	return cfg, nil
}

// dnsModeName names the mode for error messages.
func dnsModeName(cfg *Config) string {
	if cfg.Mode == ModeCapture {
		return "capture dns assist"
	}
	return "spoof mode"
}

// hostPort strips an http(s):// scheme from a proxy URL, leaving host:port.
func hostPort(s string) string {
	if s == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(s, "http://"); ok {
		return strings.TrimSuffix(rest, "/")
	}
	if rest, ok := strings.CutPrefix(s, "https://"); ok {
		return strings.TrimSuffix(rest, "/")
	}
	return strings.TrimSuffix(s, "/")
}

// splitCSV trims and drops empties from a comma-separated flag value.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// modeFlag adapts Mode to flag.Value.
type modeFlag Mode

func (m *modeFlag) String() string { return string(*m) }

func (m *modeFlag) Set(s string) error {
	switch Mode(s) {
	case ModeProxy, ModeCapture:
		*m = modeFlag(Mode(s))
		return nil
	}
	return fmt.Errorf("invalid mode %q (proxy|capture)", s)
}
