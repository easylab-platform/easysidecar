package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// This file implements the explicit HTTP proxy face (HTTP_PROXY env points
// workloads at it). CONNECT goes through the same rule engine as the
// transparent face; plain-HTTP absolute-URI requests are handled too so
// HTTP_PROXY without HTTPS also classifies.

// ServeConnect serves the explicit proxy listener.
func ServeConnect(ln net.Listener, d *Decider, mitm *MITM, logger *ConnLogger) error {
	logger.Log(ConnLogEntry{Action: "info", Dst: "listening connect " + ln.Addr().String()})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConnect(c.(*net.TCPConn), d, mitm, logger)
	}
}

// handleConnect parses one proxy request and executes the decision.
func handleConnect(c *net.TCPConn, d *Decider, mitm *MITM, logger *ConnLogger) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		logger.Log(ConnLogEntry{Action: "error", Err: "parse: " + err.Error()})
		return
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	authority := host // host:port for dialing
	hostname := host
	if h, _, err2 := hostPort(host); err2 == nil {
		hostname = h
	} else {
		// No port: assume 443 for CONNECT (TLS), 80 otherwise.
		if req.Method == http.MethodConnect {
			authority = host + ":443"
		} else {
			authority = host + ":80"
		}
	}
	dec := d.Decide(hostname, hostname)
	e := ConnLogEntry{Host: host, Action: string(dec.Action), Rule: firstMatch(dec)}

	switch dec.Action {
	case ActionBlock:
		logger.Log(e)
		resetConn(c)
		return

	case ActionDirect:
		if req.Method == http.MethodConnect {
			// Tunnel: connect and answer 200, then splice (TLS passes
			// through unless MitmDefault).
			if d.ShouldDecrypt(dec) && mitm != nil {
				e.Action = "mitm-direct"
				e.Mitm = true
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				connectMITM(c, authority, hostname, mitm, logger, e)
				return
			}
			up, err := net.DialTimeout("tcp", authority, 10*time.Second)
			if err != nil {
				e.Err = err.Error()
				logger.Log(e)
				httpFail(c, http.StatusBadGateway, err.Error())
				return
			}
			defer func() { _ = up.Close() }()
			if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			// Replay bytes buffered before the tunnel starts (rare for
			// CONNECT).
			if n := br.Buffered(); n > 0 {
				if _, err := io.CopyN(up, br, int64(n)); err != nil {
					return
				}
			}
			_ = relay(c, up, logger, e)
			return
		}
		// Plain HTTP absolute-form request: forward with original Host.
		proxyPlainHTTP(c, req, br, host, logger, e)

	case ActionRewrite:
		if mitm == nil {
			e.Action = "rewrite-denied"
			logger.Log(e)
			httpFail(c, http.StatusBadGateway, "rewrite rule without CA")
			return
		}
		if req.Method == http.MethodConnect {
			e.Mitm = true
			if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			connectRewrite(c, hostname, dec.Rule, mitm, logger, e)
			return
		}
		// Plain HTTP rewrite: respond by fetching from the target with the
		// original Host preserved as X-Forwarded-Host.
		httpRewrite(c, req, br, dec.Rule, host, logger, e)
	}
}

// connectMITM terminates the tunneled TLS for a direct action (MitmDefault).
func connectMITM(c *net.TCPConn, dialAddr, host string, mitm *MITM, logger *ConnLogger, e ConnLogEntry) {
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
	up, err := net.DialTimeout("tcp", dialAddr, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		return
	}
	defer func() { _ = up.Close() }()
	tlsUp := tls.Client(up, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		e.Err = "upstream handshake: " + err.Error()
		logger.Log(e)
		return
	}
	_ = relay(tlsSrv, tlsUp, logger, e)
}

// connectRewrite terminates the tunneled TLS and forwards to the rule target
// (no second TLS unless the target is https:// — EasyLab gateway inside the
// cluster is plain HTTP behind its own ingress).
func connectRewrite(c *net.TCPConn, host string, rule *Rule, mitm *MITM, logger *ConnLogger, e ConnLogEntry) {
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

// proxyPlainHTTP forwards an absolute-form plain-HTTP request.
func proxyPlainHTTP(c *net.TCPConn, req *http.Request, br *bufio.Reader, host string, logger *ConnLogger, e ConnLogEntry) {
	up, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		httpFail(c, http.StatusBadGateway, err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	if err := req.Write(up); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		_, _ = io.CopyN(up, br, int64(n))
	}
	_ = relay(c, up, logger, e)
}

// httpRewrite rewrites a plain-HTTP request toward the rule target.
func httpRewrite(c *net.TCPConn, req *http.Request, br *bufio.Reader, rule *Rule, host string, logger *ConnLogger, e ConnLogEntry) {
	origHost := req.Host
	req.URL.Host = rule.Target
	req.Host = origHost // preserve the upstream hostname for the adapter
	req.Header.Set("X-Forwarded-Host", origHost)
	up, err := net.DialTimeout("tcp", rule.Target, 10*time.Second)
	if err != nil {
		e.Err = err.Error()
		logger.Log(e)
		httpFail(c, http.StatusBadGateway, err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	if err := req.Write(up); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		_, _ = io.CopyN(up, br, int64(n))
	}
	_ = relay(c, up, logger, e)
}

// httpFail writes a minimal error response.
func httpFail(c net.Conn, code int, msg string) {
	status := fmt.Sprintf("%d %s", code, strings.ToUpper(http.StatusText(code)))
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, len(msg), msg)
}
