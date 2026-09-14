package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// This file implements the spoof-mode TCP faces: the sidecar listens directly
// on :443 (TLS) and :80 (plain HTTP). Because DNS answers for rewrite-matched
// names point at the sidecar, every such connection arrives here with no
// netfilter involved. Classification uses SNI (TLS) or the Host header.

// SpoofTCP serves the direct TLS/HTTP listeners for spoof mode.
type SpoofTCP struct {
	TLSAddr       string
	HTTPAddr      string
	Decider       *Decider
	MITM          *MITM
	UpstreamProxy string // optional HTTP proxy for DIRECT egress (mihomo)
	Logger        *ConnLogger
}

// Serve starts both listeners; it blocks until one fails.
func (s *SpoofTCP) Serve() error {
	errCh := make(chan error, 2)
	if s.TLSAddr != "" {
		go func() { errCh <- s.serveTLS() }()
	}
	if s.HTTPAddr != "" {
		go func() { errCh <- s.serveHTTP() }()
	}
	return <-errCh
}

func (s *SpoofTCP) serveTLS() error {
	ln, err := net.Listen("tcp", s.TLSAddr)
	if err != nil {
		return fmt.Errorf("spoof tls listen %s: %w", s.TLSAddr, err)
	}
	s.Logger.Log(ConnLogEntry{Action: "info", Dst: "listening spoof-tls " + s.TLSAddr})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleTLS(c)
	}
}

func (s *SpoofTCP) serveHTTP() error {
	ln, err := net.Listen("tcp", s.HTTPAddr)
	if err != nil {
		return fmt.Errorf("spoof http listen %s: %w", s.HTTPAddr, err)
	}
	s.Logger.Log(ConnLogEntry{Action: "info", Dst: "listening spoof-http " + s.HTTPAddr})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleHTTP(c)
	}
}

// handleTLS classifies a direct TLS connection by SNI and acts.
func (s *SpoofTCP) handleTLS(c net.Conn) {
	host, tr, err := classifyHost(c)
	if err != nil && err != io.EOF {
		s.Logger.Log(ConnLogEntry{Action: "error", Dst: c.RemoteAddr().String(), Err: err.Error()})
		_ = c.Close()
		return
	}
	dec := s.Decider.Decide(host, "")
	e := ConnLogEntry{Host: host, Dst: c.RemoteAddr().String()}

	switch dec.Action {
	case ActionBlock:
		e.Action = "block"
		e.Rule = firstMatch(dec)
		s.Logger.Log(e)
		resetConn(c)
		return

	case ActionRewrite:
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
		s.rewriteRelay(c, tr, dec.Rule, host, e)

	case ActionDirect:
		if s.Decider.ShouldDecrypt(dec) && s.MITM != nil {
			e.Action = "mitm-direct"
			e.Mitm = true
			s.mitmRelay(c, host, e)
			return
		}
		e.Action = "direct"
		e.Rule = firstMatch(dec)
		s.passthrough(c, host, tr, e)
	}
}

// mitmRelay terminates the client TLS and re-originates to the real host
// (direct) through the upstream proxy when configured.
func (s *SpoofTCP) mitmRelay(c net.Conn, host string, e ConnLogEntry) {
	tlsCfg, err := s.MITM.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	tlsSrv := tls.Server(c, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		e.Err = "client handshake: " + err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	up, err := s.dialEgress(net.JoinHostPort(host, "443"), e)
	if err != nil {
		s.Logger.Log(e)
		_ = tlsSrv.Close()
		return
	}
	tlsUp := tls.Client(up, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		e.Err = "upstream handshake: " + err.Error()
		s.Logger.Log(e)
		_ = tlsSrv.Close()
		return
	}
	_ = relay(tlsSrv, tlsUp, s.Logger, e)
}

// rewriteRelay terminates the client TLS and forwards the decrypted stream to
// the rule target (an easylab pull-through endpoint reached inside the
// cluster over plain HTTP).
func (s *SpoofTCP) rewriteRelay(c net.Conn, tr *tlsReader, rule *Rule, host string, e ConnLogEntry) {
	tlsCfg, err := s.MITM.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	tlsSrv := tls.Server(c, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		e.Err = "client handshake: " + err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	up, err := net.DialTimeout("tcp", rule.Target, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
		_ = tlsSrv.Close()
		return
	}
	defer func() { _ = up.Close() }()
	_ = relay(tlsSrv, up, s.Logger, e)
}

// passthrough splices an un-decrypted TLS stream to the real host (or via the
// upstream proxy when configured).
func (s *SpoofTCP) passthrough(c net.Conn, host string, tr *tlsReader, e ConnLogEntry) {
	up, err := s.dialEgress(net.JoinHostPort(host, "443"), e)
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
	_ = relay(c, up, s.Logger, e)
}

// dialEgress dials the target directly, or via the configured upstream HTTP
// proxy (mihomo) using CONNECT so the cluster's egress policy still applies.
func (s *SpoofTCP) dialEgress(addr string, e ConnLogEntry) (net.Conn, error) {
	if s.UpstreamProxy == "" {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			e.Err = err.Error()
		}
		return conn, err
	}
	conn, err := net.DialTimeout("tcp", s.UpstreamProxy, 10*time.Second)
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
	// Read the proxy's status line + headers.
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

// handleHTTP handles plain-HTTP requests to the sidecar (Host-based
// classification). Only useful for rewrite/block of non-TLS traffic.
func (s *SpoofTCP) handleHTTP(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := newHeaderReader(c)
	host, err := br.readHost()
	if err != nil {
		return
	}
	dec := s.Decider.Decide(host, "")
	e := ConnLogEntry{Host: host, Dst: c.RemoteAddr().String(), Action: string(dec.Action)}
	switch dec.Action {
	case ActionBlock:
		s.Logger.Log(e)
		resetConn(c)
	case ActionRewrite:
		up, err := net.DialTimeout("tcp", dec.Rule.Target, 10*time.Second)
		if err != nil {
			e.Err = err.Error()
			s.Logger.Log(e)
			return
		}
		defer func() { _ = up.Close() }()
		// Replay the parsed request head (with the original Host preserved).
		if _, err := up.Write(br.bufferedAll()); err != nil {
			return
		}
		_ = relay(c, up, s.Logger, e)
	case ActionDirect:
		up, err := s.dialEgress(net.JoinHostPort(host, "80"), e)
		if err != nil {
			s.Logger.Log(e)
			return
		}
		defer func() { _ = up.Close() }()
		if _, err := up.Write(br.bufferedAll()); err != nil {
			return
		}
		_ = relay(c, up, s.Logger, e)
	}
}
