package server

import (
	"fmt"
	"net"
	"strings"

	"github.com/easylab-platform/easysidecar/capture"
	"github.com/easylab-platform/easysidecar/dns"
	"github.com/easylab-platform/easysidecar/logging"
	"github.com/easylab-platform/easysidecar/mitm"
	"github.com/easylab-platform/easysidecar/relay"
	"github.com/easylab-platform/easysidecar/rule"
)

// Run loads the rule set and serves the listeners for the configured mode.
func Run(cfg *Config) error {
	// The init-container role installs the netfilter rules and exits; it never
	// serves traffic.
	if cfg.Mode == ModeCapture && cfg.CaptureInit {
		return runCaptureInit(cfg)
	}
	return runProxy(cfg)
}

// runCaptureInit installs transparent-interception rules for the Pod and
// returns. It runs once, as an init container with NET_ADMIN.
func runCaptureInit(cfg *Config) error {
	_, port, err := net.SplitHostPort(cfg.CaptureAddr)
	if err != nil {
		return fmt.Errorf("capture-init: bad -capture-addr %q: %w", cfg.CaptureAddr, err)
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return fmt.Errorf("capture-init: bad port %q: %w", port, err)
	}
	_, dnsPort, err := net.SplitHostPort(cfg.SpoofDNSAddr)
	if err != nil {
		return fmt.Errorf("capture-init: bad -spoof-dns-addr %q: %w", cfg.SpoofDNSAddr, err)
	}
	dp, err := net.LookupPort("udp", dnsPort)
	if err != nil {
		return fmt.Errorf("capture-init: bad dns port %q: %w", dnsPort, err)
	}
	up := 0
	if cfg.CaptureUDPAddr != "" {
		_, uport, uerr := net.SplitHostPort(cfg.CaptureUDPAddr)
		if uerr != nil {
			return fmt.Errorf("capture-init: bad -capture-udp-addr %q: %w", cfg.CaptureUDPAddr, uerr)
		}
		up, err = net.LookupPort("udp", uport)
		if err != nil {
			return fmt.Errorf("capture-init: bad udp port %q: %w", uport, err)
		}
	}
	fp := 0
	if cfg.CaptureForwardAddr != "" {
		_, fport, ferr := net.SplitHostPort(cfg.CaptureForwardAddr)
		if ferr != nil {
			return fmt.Errorf("capture-init: bad -capture-forward-addr %q: %w", cfg.CaptureForwardAddr, ferr)
		}
		fp, err = net.LookupPort("tcp", fport)
		if err != nil {
			return fmt.Errorf("capture-init: bad forward port %q: %w", fport, err)
		}
	}
	if err := capture.Install(capture.Policy{
		SelfIP:         cfg.SelfIP,
		CapturePort:    p,
		ForwardPort:    fp,
		DNSPort:        dp,
		UDPCapturePort: up,
		Mark:           capture.Mark,
		DNSUpstream:    cfg.UpstreamDNS,
		UDPAllow:       cfg.CaptureUDPAllow,
		UDPMode:        cfg.CaptureUDPMode,
		DefaultMode:    cfg.CaptureDefaultMode,
		ExemptCIDRs:    cfg.CaptureExemptCIDRs,
		UIDs:           cfg.CaptureUIDs,
	}); err != nil {
		return err
	}
	logging.NewConnLogger().Log(logging.ConnLogEntry{
		Action: "info", Dst: fmt.Sprintf("capture-init: dns->:%d tcp->%s udp->:%d udp-mode=%s default-mode=%s (mark 0x%x)",
			dp, cfg.CaptureAddr, up, cfg.CaptureUDPMode, cfg.CaptureDefaultMode, capture.Mark)})
	return nil
}

// runProxy loads rules and serves every listener until one fails. cfg.Spoof
// selects the DNS-spoof face; otherwise the privileged capture face is served
// (the init container already installed the redirect).
func runProxy(cfg *Config) error {
	rules, err := rule.LoadRules(cfg.RulesFile)
	if err != nil {
		return err
	}
	logger := logging.NewConnLogger()
	decisions := rule.NewDecider(rules, cfg.MitmDefault)

	// MITM authority (nil when no CA configured: rewrite rules then fail
	// closed with a clear error instead of silently bypassing policy).
	var m *mitm.MITM
	if cfg.CaCert != "" && cfg.CaKey != "" {
		m, err = mitm.LoadMITM(cfg.CaCert, cfg.CaKey)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
	} else if rules.HasRewrite() {
		return fmt.Errorf("rules contain rewrite entries but no -ca-cert/-ca-key: rewrite requires MITM")
	}

	if cfg.Mode == ModeCapture {
		return runCapture(cfg, decisions, m, logger)
	}
	return runSpoof(cfg, decisions, m, logger)
}

// runSpoof serves the dns-spoof mode listeners: the resolver plus the direct
// TLS/HTTP faces. It composes with an upstream egress proxy (mihomo) for
// DIRECT traffic.
func runSpoof(cfg *Config, decisions *rule.Decider, m *mitm.MITM, logger *logging.ConnLogger) error {
	upstreams := []string{withPort(cfg.UpstreamDNS, "53")}
	srv := &dns.SpoofDNS{
		Addr: cfg.SpoofDNSAddr, SelfIP: cfg.SelfIP,
		UpstreamDNS: upstreams, Decider: decisions, Logger: logger,
	}
	tcp := &relay.SpoofTCP{
		TLSAddr: cfg.SpoofTLSAddr, HTTPAddr: cfg.SpoofHTTPAddr,
		Decider: decisions, MITM: m, UpstreamProxy: cfg.UpstreamProxy, Logger: logger,
	}
	logger.Log(logging.ConnLogEntry{Action: "info", Dst: "spoof mode: self=" + cfg.SelfIP +
		" dns-upstream=" + strings.Join(upstreams, ",") + " egress-proxy=" + cfg.UpstreamProxy})

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Serve() }()
	go func() { errCh <- tcp.Serve() }()
	return <-errCh
}

// runCapture serves the all-port capture listener. The init container has
// already pointed the Pod's outbound TCP at -capture-addr; each connection's
// real destination arrives via SO_ORIGINAL_DST.
//
// With CaptureDNS the spoof resolver AND the spoof :443/:80 faces also run.
// Names the policy rewrites may not resolve publicly (NXDOMAIN), so the
// resolver answers them with SelfIP; a client dialing the Pod IP hits the
// loopback exemption in the nat chain, so the spoof faces must be listening
// there for the connection to be served. Publicly-resolvable names still take
// the capture path (real IP -> redirect -> SO_ORIGINAL_DST).
func runCapture(cfg *Config, decisions *rule.Decider, m *mitm.MITM, logger *logging.ConnLogger) error {
	webPorts := map[int]bool{}
	for _, p := range cfg.CaptureTCPPorts {
		webPorts[p] = true
	}
	tcp := &relay.CaptureTCP{
		Addr: cfg.CaptureAddr, Decider: decisions, MITM: m,
		UpstreamProxy: cfg.UpstreamProxy, ProxyURL: cfg.UpstreamProxy,
		WebPorts: webPorts, Logger: logger, Mark: capture.Mark,
	}
	logger.Log(logging.ConnLogEntry{Action: "info", Dst: "capture mode: listen=" + cfg.CaptureAddr +
		" egress-proxy=" + cfg.UpstreamProxy + " dns-assist=" + boolStr(cfg.CaptureDNS) +
		" forward=" + cfg.CaptureForwardAddr})

	servers := []func() error{tcp.Serve}
	if cfg.CaptureUDPAddr != "" {
		udp := &relay.CaptureUDP{
			Addr: cfg.CaptureUDPAddr, Mark: capture.Mark, Logger: logger,
			Allow: cfg.CaptureUDPAllow, Mode: cfg.CaptureUDPMode,
		}
		servers = append(servers, udp.Serve)
	}
	if cfg.CaptureForwardAddr != "" {
		// Forwarded (VM guest) connections carry SO_ORIGINAL_DST too, so the
		// same face serves them on a second listener.
		fwd := &relay.CaptureTCP{
			Addr: cfg.CaptureForwardAddr, Decider: decisions, MITM: m,
			UpstreamProxy: cfg.UpstreamProxy, ProxyURL: cfg.UpstreamProxy,
			WebPorts: webPorts, Logger: logger, Mark: capture.Mark,
		}
		servers = append(servers, fwd.Serve)
	}
	if cfg.CaptureDNS {
		upstreams := []string{withPort(cfg.UpstreamDNS, "53")}
		srv := &dns.SpoofDNS{
			Addr: cfg.SpoofDNSAddr, SelfIP: cfg.SelfIP,
			UpstreamDNS: upstreams, Decider: decisions, Logger: logger,
			Mark: capture.Mark, ForwardDirect: true,
		}
		spoof := &relay.SpoofTCP{
			TLSAddr: cfg.SpoofTLSAddr, HTTPAddr: cfg.SpoofHTTPAddr,
			Decider: decisions, MITM: m, UpstreamProxy: cfg.UpstreamProxy, ProxyURL: cfg.UpstreamProxy,
			Logger: logger, Mark: capture.Mark,
		}
		servers = append(servers, srv.Serve, spoof.Serve)
	}
	if len(servers) == 1 {
		return servers[0]()
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s func() error) { errCh <- s() }(s)
	}
	return <-errCh
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
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
