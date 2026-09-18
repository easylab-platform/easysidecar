package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/easylab-platform/easysidecar/capture"
	"github.com/easylab-platform/easysidecar/logging"
	"github.com/easylab-platform/easysidecar/mitm"
	"github.com/easylab-platform/easysidecar/rule"
)

// CaptureTCP is the privileged, all-port interception face. An init container
// installs iptables rules that send the Pod's outbound TCP to :15001; each
// accepted connection carries its real destination in SO_ORIGINAL_DST, so the
// sidecar does not depend on DNS to know where the client was going.
//
// It reuses the spoof face's classification and relay logic. The hostname is
// learned from the stream: TLS gives SNI, plain HTTP gives the Host header; a
// stream that is neither is spliced raw to its original destination.
type CaptureTCP struct {
	Addr          string // listen address, e.g. 0.0.0.0:15001
	Decider       *rule.Decider
	MITM          *mitm.MITM
	UpstreamProxy string
	ProxyURL      string // scheme://host:port form for the web face's direct proxy
	// WebPorts are the ports proxied as web (HTTP/h2c transparent). A port not
	// in the set is still captured, but only logged and spliced raw. TLS is
	// classified by SNI on every port.
	WebPorts map[int]bool
	Logger   *logging.ConnLogger
	// Mark stamps SO_MARK on the sidecar's own upstream sockets so the nat
	// chain's mark RETURN exempts them from the redirect (no self-loop). Zero
	// disables marking.
	Mark int
}

// Serve accepts intercepted connections until the listener fails.
func (s *CaptureTCP) Serve() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("capture listen %s: %w", s.Addr, err)
	}
	s.Logger.Log(logging.ConnLogEntry{Action: "info", Dst: "listening capture-tcp " + s.Addr})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// handle recovers the original destination and relays the connection.
func (s *CaptureTCP) handle(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return
	}
	origIP, origPort, err := capture.OriginalDst(tc)
	if err != nil || origIP == nil || origPort == 0 {
		s.Logger.Log(logging.ConnLogEntry{Action: "error", Dst: tc.RemoteAddr().String(),
			Err: "SO_ORIGINAL_DST: " + errString(err)})
		_ = c.Close()
		return
	}
	host := origIP.String()
	e := logging.ConnLogEntry{Dst: net.JoinHostPort(host, strconv.Itoa(origPort))}

	// Peek the first bytes to classify the wire protocol. The peeked bytes
	// stay buffered and are replayed to whichever path we take.
	tr := newTLSReader(c)
	sni, isTLS, serr := tr.sni()
	switch {
	case serr == nil && isTLS:
		host = strings.TrimSuffix(sni, ".")
		e.Host = host
		s.decideAndAct(c, host, origPort, tr, e)

	case serr == errNotTLS && s.isWebPort(origPort) && isH2CPreface(tr.buffered()):
		// Cleartext HTTP/2 (prior knowledge). The per-request handler reads
		// the :authority pseudo-header, so classification is per request.
		s.handleWeb(c, host, origPort, tr, true, e)

	case serr == errNotTLS && s.isWebPort(origPort) && looksLikeHTTP(tr.buffered()):
		// Plain HTTP/1.1. Same per-request handler.
		s.handleWeb(c, host, origPort, tr, false, e)

	default:
		// TLS without SNI, or a non-web protocol: classify by the original
		// destination address and splice raw (logged, not proxied).
		e.Host = host
		dec := s.Decider.Decide(host, "")
		switch dec.Action {
		case rule.ActionBlock:
			e.Action = "block"
			e.Rule = firstMatch(dec)
			s.Logger.Log(e)
			resetConn(c)
		case rule.ActionDirect:
			if s.Decider.ShouldDecrypt(dec) && s.MITM != nil && isTLS {
				e.Action = "mitm-direct"
				e.Mitm = true
				s.mitmRelay(c, tr.replay(), host, e)
				return
			}
			e.Action = "direct"
			e.Rule = firstMatch(dec)
			s.passthrough(c, host, origPort, tr, e)
		default: // rewrite with no SNI: nothing to map, pass through
			e.Action = "direct"
			s.passthrough(c, host, origPort, tr, e)
		}
	}
}

// isWebPort reports whether a destination port is proxied as web. An empty set
// means the default {80, 443}.
func (s *CaptureTCP) isWebPort(port int) bool {
	if len(s.WebPorts) == 0 {
		return port == 80 || port == 443
	}
	return s.WebPorts[port]
}

// handleWeb proxies a plaintext HTTP/1.1 or h2c connection through the shared
// web face: every request is classified by its Host/:authority and either
// rewritten to the rule target or transparently forwarded to the original
// destination. Both paths log method/path/status.
func (s *CaptureTCP) handleWeb(c net.Conn, origHost string, origPort int, tr *tlsReader, isH2 bool, e logging.ConnLogEntry) {
	replay := &bufferedConn{Conn: c, r: tr.replay()}
	face := &webFace{
		origHost: origHost, origPort: origPort, scheme: "http",
		decider: s.Decider, dialCtx: s.markedDialContext(), proxyURL: s.ProxyURL, logger: s.Logger,
	}
	if err := serveWebConn(replay, face.handler(), isH2); err != nil {
		s.Logger.Log(logging.ConnLogEntry{Dst: e.Dst, Action: "web", Err: err.Error()})
	}
}

// decideAndAct classifies a captured TLS stream by hostname.
func (s *CaptureTCP) decideAndAct(c net.Conn, host string, port int, tr *tlsReader, e logging.ConnLogEntry) {
	dec := s.Decider.Decide(host, "")
	switch dec.Action {
	case rule.ActionBlock:
		e.Action = "block"
		e.Rule = firstMatch(dec)
		s.Logger.Log(e)
		resetConn(c)
		return
	case rule.ActionRewrite:
		if s.MITM == nil {
			e.Action = "rewrite-denied"
			e.Err = "no CA configured"
			s.Logger.Log(e)
			resetConn(c)
			return
		}
		e.Action = "rewrite"
		e.Rule = firstMatch(dec)
		e.Mitm = true
		s.Logger.Log(e)
		s.rewriteRelay(c, tr.replay(), dec.Rule, host, e)
	case rule.ActionDirect:
		if s.Decider.ShouldDecrypt(dec) && s.MITM != nil {
			e.Action = "mitm-direct"
			e.Mitm = true
			s.mitmRelay(c, tr.replay(), host, e)
			return
		}
		e.Action = "direct"
		e.Rule = firstMatch(dec)
		s.passthrough(c, host, port, tr, e)
	}
}

// passthrough splices a stream to its original destination (or via the
// upstream proxy when configured), replaying the ClientHello/peeked bytes read
// during classification.
func (s *CaptureTCP) passthrough(c net.Conn, host string, port int, tr *tlsReader, e logging.ConnLogEntry) {
	up, err := s.dialEgress(net.JoinHostPort(host, strconv.Itoa(port)), e)
	if err != nil {
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	defer func() { _ = up.Close() }()
	if tr != nil && len(tr.buffered()) > 0 {
		if _, err := up.Write(tr.buffered()); err != nil {
			e.Err = err.Error()
			s.Logger.Log(e)
			return
		}
	}
	_ = logging.Relay(c, up, s.Logger, e)
}

// rewriteRelay / mitmRelay delegate to the shared relay implementations so the
// capture face behaves exactly like the spoof face once a hostname is known.
func (s *CaptureTCP) rewriteRelay(c net.Conn, r io.Reader, rl *rule.Rule, host string, e logging.ConnLogEntry) {
	rewriteRelayConnDial(c, r, rl, host, e, s.MITM, s.Logger, s.markedDialContext())
}

func (s *CaptureTCP) mitmRelay(c net.Conn, r io.Reader, host string, e logging.ConnLogEntry) {
	mitmRelayConn(c, r, host, e, s.MITM, s.dialEgress, s.Logger)
}

// markedDialContext returns the transport dialer for the capture face: every
// socket gets SO_MARK so the nat chain exempts it from the redirect. nil when
// no mark is configured.
func (s *CaptureTCP) markedDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Mark == 0 {
		return nil
	}
	d := capture.MarkedDialer(s.Mark)
	return d.DialContext
}

// dialEgress dials the target directly, or via the configured upstream HTTP
// proxy using CONNECT. Mirrors SpoofTCP.dialEgress so capture mode composes
// with the cluster egress proxy.
//
// Every socket is stamped with s.Mark first: the nat chain RETURNs marked
// traffic, so the sidecar's own egress is not redirected back into itself.
func (s *CaptureTCP) dialEgress(addr string, e logging.ConnLogEntry) (net.Conn, error) {
	dial := func(target string) (net.Conn, error) {
		if s.Mark == 0 {
			return net.DialTimeout("tcp", target, 10*time.Second)
		}
		d := capture.MarkedDialer(s.Mark)
		d.Timeout = 10 * time.Second
		return d.Dial("tcp", target)
	}
	if s.UpstreamProxy == "" {
		conn, err := dial(addr)
		if err != nil {
			e.Err = err.Error()
		}
		return conn, err
	}
	conn, err := dial(s.UpstreamProxy)
	if err != nil {
		e.Err = "upstream proxy dial: " + err.Error()
		return nil, err
	}
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		e.Err = "upstream proxy write: " + err.Error()
		_ = conn.Close()
		return nil, err
	}
	br := newHeaderReader(conn)
	status, err := br.readStatus()
	if err != nil {
		e.Err = "upstream proxy read: " + err.Error()
		_ = conn.Close()
		return nil, err
	}
	if status != 200 {
		e.Err = fmt.Sprintf("upstream proxy CONNECT status %d", status)
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT status %d", status)
	}
	return &bufferedConn{Conn: conn, r: br.rest()}, nil
}

// looksLikeHTTP reports whether the buffered prefix starts with an HTTP method.
func looksLikeHTTP(b []byte) bool {
	for _, m := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return "no original destination"
	}
	return err.Error()
}
