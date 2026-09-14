package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"time"
)

// ConnLogger writes one JSON line per classified connection. Stdout is the
// container log; an external collector can ship it to audit_log.
type ConnLogger struct {
	w *json.Encoder
}

// NewConnLogger builds a logger on stderr-friendly stdout.
func NewConnLogger() *ConnLogger {
	l := &ConnLogger{}
	l.w = json.NewEncoder(log.Writer())
	return l
}

// ConnLogEntry is one classified connection.
type ConnLogEntry struct {
	TS     string `json:"ts"`
	Host   string `json:"host,omitempty"`
	Dst    string `json:"dst,omitempty"` // original destination (redirect) or upstream
	Action string `json:"action"`
	Rule   string `json:"rule,omitempty"` // first match pattern
	Mitm   bool   `json:"mitm,omitempty"`
	Bytes  int64  `json:"bytes"`
	Err    string `json:"err,omitempty"`
}

// Log emits an entry; logging failures are swallowed (never break traffic).
func (l *ConnLogger) Log(e ConnLogEntry) {
	if l == nil {
		return
	}
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	_ = l.w.Encode(e)
}

// relay copies both directions of an established connection, counting the
// bytes pushed downstream. It returns the copy error (if any).
func relay(down, up net.Conn, l *ConnLogger, e ConnLogEntry) error {
	done := make(chan error, 2)
	go func() {
		n, err := copyOne(up, down)
		e.Bytes += n
		done <- err
	}()
	go func() {
		n, err := copyOne(down, up)
		e.Bytes += n
		done <- err
	}()
	err1 := <-done
	// The first finished direction signals the peer. For TLS conns a bare
	// halfClose is a no-op (no close_notify), so fully Close the TLS side —
	// that sends close_notify and the client's pending read returns EOF.
	// Plain TCP conns still get a graceful half-close.
	closeOne(down)
	closeOne(up)
	err2 := <-done
	if err1 != nil {
		e.Err = err1.Error()
	} else {
		e.Err = errErr2String(err2)
	}
	l.Log(e)
	return err1
}

func errErr2String(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// copyOne is a plain io.Copy alias (kept for future zero-copy tuning).
func copyOne(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}

// closeOne finishes a relayed direction: TCP conns get a graceful
// half-close; TLS conns get a full Close (sends close_notify so the peer's
// read unblocks — tls.Conn has no exposed half-close).
func closeOne(c net.Conn) {
	if _, isTLS := c.(*tls.Conn); isTLS {
		_ = c.Close()
		return
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
}
