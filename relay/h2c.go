package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2"

	"github.com/easylab-platform/easysidecar/logging"
	"github.com/easylab-platform/easysidecar/rule"
)

// h2cPreface is the HTTP/2 connection preface a client sends before any
// cleartext (h2c, prior-knowledge) frames.
const h2cPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// isH2CPreface reports whether b starts with the HTTP/2 cleartext preface.
// The client may not have sent the full preface yet, so a prefix of it also
// matches (the caller only peeks a bounded amount).
func isH2CPreface(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) >= len(h2cPreface) {
		return bytes.Equal(b[:len(h2cPreface)], []byte(h2cPreface))
	}
	return bytes.HasPrefix([]byte(h2cPreface), b)
}

// h2cTransport is the transport used to reach an h2c upstream when the client
// itself spoke h2c (so the protocol is preserved end to end).
func h2cTransport(dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)) *http2.Transport {
	t := &http2.Transport{AllowHTTP: true}
	if dialCtx != nil {
		t.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialCtx(ctx, network, addr)
		}
	}
	return t
}

// buildTransparentProxy forwards each request to the connection's original
// destination without rewriting the path or Host. It is the "direct" HTTP/h2c
// path: the request is proxied (so it is visible and logged) rather than
// spliced raw. scheme is the client's scheme ("http"/"https"); origHost/origPort
// is where the client was really headed.
func buildTransparentProxy(origHost string, origPort int, scheme string, dialCtx func(ctx context.Context, network, addr string) (net.Conn, error), proxyURL string, log func(*http.Request, int)) *httputil.ReverseProxy {
	addr := net.JoinHostPort(origHost, strconv.Itoa(origPort))
	transport := &http.Transport{}
	if dialCtx != nil {
		transport.DialContext = dialCtx
	}
	if u := httpProxyURL(proxyURL); u != nil {
		transport.Proxy = http.ProxyURL(u)
	}
	return &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = scheme
			req.URL.Host = addr
			// Keep the original path and Host verbatim.
		},
		ModifyResponse: func(resp *http.Response) error {
			if log != nil {
				log(resp.Request, resp.StatusCode)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			if log != nil {
				log(r, http.StatusBadGateway)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// httpProxyURL parses "host:port" into a proxy URL, or nil when empty.
func httpProxyURL(hostport string) *url.URL {
	if strings.TrimSpace(hostport) == "" {
		return nil
	}
	u, err := url.Parse("http://" + hostport)
	if err != nil {
		return nil
	}
	return u
}

// hostOfAuthority strips an optional port from an HTTP :authority / Host value.
func hostOfAuthority(a string) string {
	a = strings.TrimSpace(a)
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// serveWebConn runs an http.Handler over one already-established connection,
// dispatching to the HTTP/2 server for h2 (cleartext prior-knowledge or
// TLS-negotiated) and the HTTP/1.1 server otherwise.
func serveWebConn(conn net.Conn, h http.Handler, isH2 bool) error {
	if tc, ok := conn.(*tls.Conn); ok {
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			isH2 = true
		}
	}
	if isH2 {
		srv := &http2.Server{}
		srv.ServeConn(conn, &http2.ServeConnOpts{Handler: h})
		return nil
	}
	return serveHTTP1Conn(conn, h)
}

// webFace builds the per-request handler shared by the capture and spoof faces
// for plaintext HTTP/h2c and for MITM-decrypted HTTP. Every request is
// classified by its Host/:authority, so a single h2c connection carrying
// multiple authorities is routed correctly.
type webFace struct {
	origHost string // original destination IP (fallback authority + dial target)
	origPort int
	scheme   string // scheme the client used: "http" or "https"
	// spoof is set for the DNS-spoof face: the connection arrived at the
	// sidecar, so "direct" must dial the request's Host header, not origHost.
	spoof    bool
	decider  *rule.Decider
	dialCtx  func(ctx context.Context, network, addr string) (net.Conn, error)
	proxyURL string // optional upstream HTTP proxy for direct requests
	logger   *logging.ConnLogger
}

// handler classifies and proxies each request.
func (w *webFace) handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		host := hostOfAuthority(req.Host)
		if host == "" {
			host = w.origHost
		}
		dec := w.decider.DecidePath(host, req.URL.Path)
		switch dec.Action {
		case rule.ActionBlock:
			w.log(req, host, "block", http.StatusForbidden)
			http.Error(rw, "blocked by egress policy", http.StatusForbidden)
		case rule.ActionRewrite:
			if dec.Rule == nil {
				w.proxyDirect(rw, req, host)
				return
			}
			rp := buildRewriteProxy(dec.Rule, host, w.scheme, w.dialCtx,
				func(r *http.Request, status int) { w.log(r, host, "rewrite", status) })
			rp.ServeHTTP(rw, req)
		default:
			w.proxyDirect(rw, req, host)
		}
	})
}

func (w *webFace) proxyDirect(rw http.ResponseWriter, req *http.Request, host string) {
	dialHost, dialPort := w.origHost, w.origPort
	if w.spoof {
		// The sidecar was dialed directly; the real upstream is the Host.
		dialHost = host
		dialPort = 80
		if w.scheme == "https" {
			dialPort = 443
		}
	}
	rp := buildTransparentProxy(dialHost, dialPort, w.scheme, w.dialCtx, w.proxyURL,
		func(r *http.Request, status int) { w.log(r, host, "direct", status) })
	rp.ServeHTTP(rw, req)
}

func (w *webFace) log(req *http.Request, host, action string, status int) {
	if w.logger == nil {
		return
	}
	w.logger.Log(logging.ConnLogEntry{
		Host:   host,
		Dst:    net.JoinHostPort(w.origHost, strconv.Itoa(w.origPort)),
		Action: action,
		Method: req.Method,
		Path:   req.URL.RequestURI(),
		Status: status,
	})
}
