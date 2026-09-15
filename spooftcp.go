package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
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
		// Log the classification immediately: the relayed connection may stay
		// open (keep-alive clients such as apt/cargo/maven), and the audit
		// entry must not wait for it to close.
		e.Action = "rewrite"
		e.Rule = firstMatch(dec)
		e.Mitm = true
		s.Logger.Log(e)
		s.rewriteRelay(c, tr.replay(), dec.Rule, host, e)

	case ActionDirect:
		if s.Decider.ShouldDecrypt(dec) && s.MITM != nil {
			e.Action = "mitm-direct"
			e.Mitm = true
			s.mitmRelay(c, tr.replay(), host, e)
			return
		}
		e.Action = "direct"
		e.Rule = firstMatch(dec)
		s.passthrough(c, host, tr, e)
	}
}

// mitmRelay terminates the client TLS and re-originates to the real host
// (direct) through the upstream proxy when configured. r replays the
// classification-read bytes into the TLS server.
func (s *SpoofTCP) mitmRelay(c net.Conn, r io.Reader, host string, e ConnLogEntry) {
	tlsCfg, err := s.MITM.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	tlsSrv := tls.Server(bothReader{r, c}, tlsCfg)
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

// rewriteRelay terminates the client TLS and proxies the decrypted HTTP
// traffic to the rule target (an easylab pull-through endpoint reached inside
// the cluster). r replays the classification-read bytes. Every request on the
// (keep-alive) connection has its path mapped through the rule's strip/add
// prefixes before forwarding; the original Host header is preserved.
func (s *SpoofTCP) rewriteRelay(c net.Conn, r io.Reader, rule *Rule, host string, e ConnLogEntry) {
	tlsCfg, err := s.MITM.TLSConfigFor(host)
	if err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	tlsSrv := tls.Server(bothReader{r, c}, tlsCfg)
	if err := tlsSrv.Handshake(); err != nil {
		e.Err = "client handshake: " + err.Error()
		s.Logger.Log(e)
		_ = c.Close()
		return
	}
	defer func() { _ = tlsSrv.Close() }()
	if err := s.serveRewritten(tlsSrv, rule, host); err != nil {
		e.Err = err.Error()
		s.Logger.Log(e)
	}
}

// serveRewritten runs an HTTP/1.1 proxy over one already-established
// connection: each request is re-originated to the rule target with its path
// mapped (host preserved), responses stream back unchanged. This keeps
// keep-alive, chunked bodies, and multiple requests per connection correct —
// a raw byte splice would only rewrite the first request head.
func (s *SpoofTCP) serveRewritten(conn net.Conn, rule *Rule, host string) error {
	scheme, addr := parseTarget(rule.Target)
	transport := &http.Transport{}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{ServerName: hostOf(addr)}
	}
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = scheme
			req.URL.Host = addr
			req.URL.Path = rule.MapPath(req.URL.Path)
			req.Host = host // preserve the upstream's Host for adapter routing
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	ln := newSingleConnListener(conn)
	srv := &http.Server{Handler: rp, ReadHeaderTimeout: 30 * time.Second}
	err := srv.Serve(ln)
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// singleConnListener yields one prepared connection, then blocks until that
// connection is closed (used to layer net/http over an already-handshaked
// conn without a real listener).
type singleConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return &notifyCloseConn{Conn: c, ln: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return dummyAddr("easyproxy") }

// notifyCloseConn signals its listener when net/http closes the connection.
type notifyCloseConn struct {
	net.Conn
	ln *singleConnListener
}

func (c *notifyCloseConn) Close() error {
	err := c.Conn.Close()
	_ = c.ln.Close()
	return err
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

// parseTarget splits a rule target into (scheme, "host:port"). Plain is
// assumed when no scheme is present (in-cluster pull-through endpoints).
func parseTarget(t string) (string, string) {
	if rest, ok := strings.CutPrefix(t, "https://"); ok {
		return "https", rest
	}
	return "http", strings.TrimPrefix(t, "http://")
}

func hostOf(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return strings.Trim(addr[:i], "[]")
	}
	return addr
}

// mustDial is a bounded dial whose failure is logged via the entry.
func mustDial(addr string, e ConnLogEntry, logger *ConnLogger) net.Conn {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return errConn{err}
	}
	return conn
}

// errConn is a net.Conn whose reads/writes immediately return the stored
// error, so the relay exits instead of blocking.
type errConn struct{ err error }

func (c errConn) Read([]byte) (int, error)       { return 0, c.err }
func (c errConn) Write([]byte) (int, error)      { return 0, c.err }
func (errConn) Close() error                     { return nil }
func (errConn) LocalAddr() net.Addr              { return nil }
func (errConn) RemoteAddr() net.Addr             { return nil }
func (errConn) SetDeadline(time.Time) error      { return nil }
func (errConn) SetReadDeadline(time.Time) error  { return nil }
func (errConn) SetWriteDeadline(time.Time) error { return nil }

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
		// Run a full HTTP/1.1 proxy over the (plain) connection so every
		// request on a keep-alive connection gets its path mapped. The head
		// already consumed by readHost is replayed ahead of the rest.
		// Log at classification time (a keep-alive relay may stay open).
		e.Action = "rewrite"
		e.Rule = firstMatch(dec)
		s.Logger.Log(e)
		replay := io.MultiReader(bytes.NewReader(br.buf), br.br)
		if err := s.serveRewritten(&bufferedConn{Conn: c, r: replay}, dec.Rule, host); err != nil {
			s.Logger.Log(ConnLogEntry{Host: host, Dst: e.Dst, Action: "rewrite", Err: err.Error()})
		}
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

// serveSpoofTLS is a test/DI seam: run the TLS face on a prepared listener.
func serveSpoofTLS(ln net.Listener, d *Decider, mitm *MITM, logger *ConnLogger) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSpoofTLSConn(c, d, mitm, logger)
	}
}

// handleSpoofTLSConn is the test/DI seam for one spoof-TLS connection.
func handleSpoofTLSConn(c net.Conn, d *Decider, mitm *MITM, logger *ConnLogger) {
	s := &SpoofTCP{Decider: d, MITM: mitm, Logger: logger}
	s.handleTLS(c)
}

// bothReader reads from a buffered source first, then falls through to the
// live connection — used to hand classification-read bytes to the TLS server
// before it starts reading the raw stream.
type bothReader struct {
	r io.Reader
	c net.Conn
}

func (b bothReader) Read(p []byte) (int, error)         { return b.r.Read(p) }
func (b bothReader) Write(p []byte) (int, error)        { return b.c.Write(p) }
func (b bothReader) Close() error                       { return b.c.Close() }
func (b bothReader) LocalAddr() net.Addr                { return b.c.LocalAddr() }
func (b bothReader) RemoteAddr() net.Addr               { return b.c.RemoteAddr() }
func (b bothReader) SetDeadline(t time.Time) error      { return b.c.SetDeadline(t) }
func (b bothReader) SetReadDeadline(t time.Time) error  { return b.c.SetReadDeadline(t) }
func (b bothReader) SetWriteDeadline(t time.Time) error { return b.c.SetWriteDeadline(t) }
