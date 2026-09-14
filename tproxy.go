package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// This file implements the transparent REDIRECT listener. The iptables
// REDIRECT preserves the original destination; SO_ORIGINAL_DST recovers it.

const solOriginalDst = 80 // SO_ORIGINAL_DST from linux/netfilter_ipv4.h

// originalDst returns the pre-REDIRECT destination of a redirected TCP
// connection.
func originalDst(c *net.TCPConn) (string, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var dst string
	var opErr error
	err = rc.Control(func(fd uintptr) {
		dst, opErr = getsockoptOriginalDst(fd)
	})
	if err != nil {
		return "", err
	}
	if opErr != nil {
		return "", opErr
	}
	return dst, nil
}

// classifyHost determines the hostname for a connection: SNI for TLS, Host
// header for plain HTTP, "" otherwise.
func classifyHost(c net.Conn) (host string, tr *tlsReader, err error) {
	tr = newTLSReader(c)
	h, ok, lerr := tr.sni()
	if lerr == nil && ok {
		return strings.TrimSuffix(h, "."), tr, nil
	}
	if lerr == nil && !ok {
		return "", tr, nil // valid TLS without SNI
	}
	if lerr == errNotTLS {
		// Plain HTTP: peek the request head for a Host header.
		h := peekHTTPHost(tr)
		return h, tr, nil
	}
	return "", tr, lerr
}

// peekHTTPHost scans the buffered bytes for a Host header on the first
// request line boundary; returns "" when absent (body may follow later).
func peekHTTPHost(tr *tlsReader) string {
	b := tr.buffered()
	// Only look if we already have header terminators or a full first line
	// block; the caller gives us whatever arrived with the SYN data.
	s := string(b)
	i := indexFold(s, "\r\nhost:")
	if i < 0 {
		i = indexFold(s, "\nhost:")
		if i < 0 {
			return ""
		}
	}
	rest := s[i+len("\nhost:"):]
	j := strings.IndexAny(rest, "\r\n")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// indexFold is strings.Index with case-insensitive matching for ASCII.
func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

// ServeRedir accepts redirected connections and applies the decision.
func ServeRedir(addr string, d *Decider, mitm *MITM, logger *ConnLogger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("redir listen %s: %w", addr, err)
	}
	logger.Log(ConnLogEntry{Action: "info", Dst: "listening redir " + addr})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleRedirect(c.(*net.TCPConn), d, mitm, logger)
	}
}

// handleRedirect classifies one connection and executes the decision.
func handleRedirect(c *net.TCPConn, d *Decider, mitm *MITM, logger *ConnLogger) {
	defer func() { _ = c.Close() }()
	dst, err := originalDst(c)
	if err != nil {
		// Not a redirected socket (local test dial): fall back to the
		// connection's own remote address.
		dst = c.RemoteAddr().String()
	}
	host, tr, err := classifyHost(c)
	if err != nil && err != io.EOF {
		logger.Log(ConnLogEntry{Action: "error", Dst: dst, Err: err.Error()})
		return
	}
	origHost, _, _ := hostPort(dst)
	if host == "" {
		host = origHost
	}
	dec := d.Decide(host, origHost)
	e := ConnLogEntry{Host: host, Dst: dst}

	switch dec.Action {
	case ActionBlock:
		e.Action = "block"
		e.Rule = firstMatch(dec)
		logger.Log(e)
		// RST: close with SO_LINGER 0 to abort rather than FIN.
		resetConn(c)
		return

	case ActionDirect:
		if d.ShouldDecrypt(dec) && mitm != nil && isTLS(tr) {
			e.Action = "mitm-direct"
			e.Mitm = true
			mitmRelay(c, tr, dst, host, mitm, logger, e)
			return
		}
		e.Action = "direct"
		e.Rule = firstMatch(dec)
		up, err := net.DialTimeout("tcp", dst, 10*time.Second)
		if err != nil {
			e.Err = err.Error()
			logger.Log(e)
			return
		}
		defer func() { _ = up.Close() }()
		// Replay any bytes consumed while peeking, then splice.
		if tr != nil && len(tr.buffered()) > 0 {
			if _, err := up.Write(tr.buffered()); err != nil {
				e.Err = err.Error()
				logger.Log(e)
				return
			}
		}
		_ = relay(c, up, logger, e)

	case ActionRewrite:
		if mitm == nil {
			// Fail closed: rewrite without a CA must not silently pass
			// through (that would defeat the policy).
			e.Action = "rewrite-denied"
			e.Err = "no CA configured"
			logger.Log(e)
			resetConn(c)
			return
		}
		e.Action = "rewrite"
		e.Rule = firstMatch(dec)
		e.Mitm = true
		rewriteRelay(c, tr, dec.Rule, host, mitm, logger, e)
	}
}

// isTLS reports whether the peeked bytes are a TLS ClientHello.
func isTLS(tr *tlsReader) bool {
	return tr != nil && len(tr.buffered()) > 0 && tr.buffered()[0] == 0x16
}

// firstMatch returns the matched pattern for logging ("" for default).
func firstMatch(dec Decision) string {
	if dec.Rule == nil || len(dec.Rule.Match) == 0 {
		return ""
	}
	return dec.Rule.Match[0]
}

// mitmRelay terminates the client TLS, dials the real destination with
// ServerName set to the client's SNI host, and splices both TLS streams.
// Content is decryptable in the middle only for logging (the v1 logger does
// not inspect payloads; this exists for future policy hooks).
func mitmRelay(c *net.TCPConn, tr *tlsReader, dst, host string, mitm *MITM, logger *ConnLogger, e ConnLogEntry) {
	tlsCfg, err := mitm.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return
	}
	tlsSrv := tls.Server(c, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		e.Err = "client handshake: " + err.Error()
		logger.Log(e)
		return
	}
	up, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return
	}
	defer func() { _ = up.Close() }()
	tlsUp := tls.Client(up, &tls.Config{ServerName: host, InsecureSkipVerify: false})
	if err := tlsUp.Handshake(); err != nil {
		e.Err = "upstream handshake: " + err.Error()
		logger.Log(e)
		return
	}
	if tr != nil && len(tr.buffered()) > tr.n {
		// Unconsumed ClientHello bytes must reach the upstream TLS client...
		// but tlsUp is a fresh TLS session; the buffered bytes belong to the
		// CLIENT's original session, not ours. Drop them: the client session
		// here is ours (terminated), the upstream session is ours too.
		_ = tr
	}
	_ = relay(tlsSrv, tlsUp, logger, e)
}

// rewriteRelay terminates the client TLS and forwards to the rule's target
// (an EasyLab pull-through endpoint), preserving the client's Host header so
// gateway-side protocol adapters see the original upstream hostname.
func rewriteRelay(c *net.TCPConn, tr *tlsReader, rule *Rule, host string, mitm *MITM, logger *ConnLogger, e ConnLogEntry) {
	tlsCfg, err := mitm.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return
	}
	tlsSrv := tls.Server(c, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		e.Err = "client handshake: " + err.Error()
		logger.Log(e)
		return
	}
	up, err := net.DialTimeout("tcp", rule.Target, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return
	}
	defer func() { _ = up.Close() }()
	_ = relay(tlsSrv, up, logger, e)
}

// resetConn aborts with RST instead of a graceful FIN.
func resetConn(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}
