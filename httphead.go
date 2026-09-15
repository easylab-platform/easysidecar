package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// headerReader reads an HTTP request head (request line + headers) from a
// connection while retaining the bytes for replay to the upstream.
type headerReader struct {
	c   net.Conn
	br  *bufio.Reader
	buf []byte
	// target is the request-line target (origin- or absolute-form). Empty for
	// non-request heads (e.g. a proxy CONNECT response).
	target string
}

func newHeaderReader(c net.Conn) *headerReader {
	return &headerReader{c: c, br: bufio.NewReader(c)}
}

// readHost reads the request head and returns the Host header value.
func (h *headerReader) readHost() (string, error) {
	line, err := h.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	h.target = requestTargetOf(line)
	h.buf = append(h.buf, line...)
	for {
		l, err := h.br.ReadString('\n')
		if err != nil {
			return "", err
		}
		h.buf = append(h.buf, l...)
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	for _, line := range strings.Split(string(h.buf), "\n") {
		if rest, ok := cutHeader(line, "Host:"); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("no Host header")
}

// requestTargetOf extracts the URI from an HTTP request line
// ("METHOD target VERSION"); "" when the line is not a request line.
func requestTargetOf(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// rewriteTarget rewrites the request-line target path with fn, preserving any
// query string and absolute-form scheme/authority prefix.
func rewriteTarget(target string, fn func(string) string) string {
	prefix, rest := "", target
	if i := strings.Index(target, "://"); i >= 0 {
		after := target[i+3:]
		slash := strings.IndexByte(after, '/')
		if slash < 0 {
			return target // authority only, nothing to map
		}
		prefix, rest = target[:i+3+slash], after[slash:]
	}
	path, query := rest, ""
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		path, query = rest[:q], rest[q:]
	}
	mapped := fn(path)
	if mapped == path {
		return target
	}
	return prefix + mapped + query
}

// readStatus reads a proxy CONNECT response status line + headers.
func (h *headerReader) readStatus() (int, error) {
	line, err := h.br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	h.buf = append(h.buf, line...)
	for {
		l, err := h.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		h.buf = append(h.buf, l...)
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	var proto string
	var status int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d", &proto, &status); err != nil {
		return 0, err
	}
	return status, nil
}

// rest returns a reader over any bytes buffered beyond the head.
func (h *headerReader) rest() *bufio.Reader { return h.br }

// rewrite returns the request head with its request-line target mapped by fn,
// plus any bytes already buffered past the head (body / pipelined data)
// verbatim. When fn is nil or leaves the target unchanged it is
// byte-identical to bufferedAll.
func (h *headerReader) rewrite(fn func(string) string) []byte {
	if fn == nil || h.target == "" {
		return h.bufferedAll()
	}
	mapped := rewriteTarget(h.target, fn)
	if mapped == h.target {
		return h.bufferedAll()
	}
	s := string(h.buf)
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return h.bufferedAll()
	}
	eol := "\n"
	if i > 0 && s[i-1] == '\r' {
		eol = "\r\n"
	}
	line := strings.TrimRight(s[:i], "\r")
	j := strings.Index(line, h.target)
	if j < 0 {
		return h.bufferedAll()
	}
	rebuilt := line[:j] + mapped + line[j+len(h.target):]
	head := rebuilt + eol + s[i+1:]
	return append([]byte(head), h.extra()...)
}

// extra returns any bytes bufio has buffered beyond the head.
func (h *headerReader) extra() []byte {
	n := h.br.Buffered()
	if n == 0 {
		return nil
	}
	peek, _ := h.br.Peek(n)
	return append([]byte(nil), peek...)
}

// bufferedAll returns the raw head plus anything already buffered (used to
// replay the request to the upstream).
func (h *headerReader) bufferedAll() []byte {
	extra := h.br.Buffered()
	if extra == 0 {
		return h.buf
	}
	peek, _ := h.br.Peek(extra)
	out := make([]byte, 0, len(h.buf)+len(peek))
	out = append(out, h.buf...)
	out = append(out, peek...)
	return out
}

func cutHeader(line, key string) (string, bool) {
	if len(line) >= len(key) && strings.EqualFold(line[:len(key)], key) {
		return line[len(key):], true
	}
	return "", false
}

// bufferedConn is a net.Conn whose reads first drain a buffered reader
// (everything the proxy sent after its status line).
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite delegates to the wrapped conn's half-close when available (plain
// TCP), otherwise falls back to a full Close (tls.Conn sends close_notify).
func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}
