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
}

func newHeaderReader(c net.Conn) *headerReader {
	return &headerReader{c: c, br: bufio.NewReader(c)}
}

// readHost reads the request head and returns the Host header value.
func (h *headerReader) readHost() (string, error) {
	for {
		line, err := h.br.ReadString('\n')
		if err != nil {
			return "", err
		}
		h.buf = append(h.buf, line...)
		if line == "\r\n" || line == "\n" {
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
