package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// This file implements the minimal TLS record-layer reader needed to extract
// the SNI hostname from a ClientHello without terminating the connection.
// It reads exactly the handshake bytes, then the caller replays everything
// (buffered bytes + the live stream) to the upstream.

// maxClientHello bounds the ClientHello we are willing to buffer (records
// with huge certificate request extensions are not our use case).
const maxClientHello = 64 << 10

// errNotTLS is returned when the first bytes are not a TLS record (plain
// HTTP/2 prior knowledge, raw protocols).
var errNotTLS = errors.New("not a TLS handshake")

// errNoSNI means the ClientHello carried no server_name extension.
var errNoSNI = errors.New("no SNI in ClientHello")

// tlsReader wraps the connection bytes with a small replay buffer.
type tlsReader struct {
	r   io.Reader
	buf []byte // bytes read ahead (record header + ClientHello)
	n   int
}

func newTLSReader(r io.Reader) *tlsReader {
	return &tlsReader{r: r, buf: make([]byte, maxClientHello)}
}

// Read implements io.Reader: serves buffered bytes first, then the stream.
func (t *tlsReader) Read(p []byte) (int, error) {
	if t.n > 0 {
		c := copy(p, t.buf[:t.n])
		t.n -= c
		return c, nil
	}
	return t.r.Read(p)
}

// buffered returns the bytes read so far (for replay).
func (t *tlsReader) buffered() []byte { return t.buf[:t.n] }

// replay wraps the connection so buffered bytes are served before the live
// stream. Consume it fully; reading past the buffer switches to the raw conn.
func (t *tlsReader) replay() io.Reader {
	return struct {
		io.Reader
		io.Writer
	}{io.MultiReader(bytes.NewReader(t.buffered()), t.r), nopWriter{}}
}

// nopWriter discards writes (MultiReader needs a Writer slot).
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// sni peeks the ClientHello server_name. On success the full handshake
// remains buffered for replay. ok=false with err==nil means "not TLS / no
// SNI — treat as opaque TCP".
func (t *tlsReader) sni() (host string, ok bool, err error) {
	// TLS record header: type(1) version(2) length(2).
	for t.n < 5 {
		c, rerr := t.r.Read(t.buf[t.n:5])
		t.n += c
		if rerr != nil {
			if t.n == 0 {
				return "", false, io.EOF
			}
			return "", false, rerr
		}
	}
	if t.buf[0] != 0x16 { // handshake record
		return "", false, errNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(t.buf[3:5]))
	if recLen > maxClientHello-5 {
		return "", false, fmt.Errorf("TLS record too large: %d", recLen)
	}
	// Read the record body (the ClientHello handshake message).
	for t.n < 5+recLen {
		c, rerr := t.r.Read(t.buf[t.n : 5+recLen])
		t.n += c
		if rerr != nil {
			return "", false, rerr
		}
	}
	body := t.buf[5 : 5+recLen]
	// Handshake: type(1) len(3). ClientHello = 0x01.
	if body[0] != 0x01 {
		return "", false, errNotTLS
	}
	hs := body[4:]
	// ClientHello: version(2) random(32) session_id(1+N) cipher(2+N)
	// compression(1+N) extensions(2+N...).
	p := 2 + 32
	if p+1 > len(hs) {
		return "", false, errNotTLS
	}
	sidLen := int(hs[p])
	p += 1 + sidLen
	if p+2 > len(hs) {
		return "", false, errNotTLS
	}
	csLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2 + csLen
	if p+1 > len(hs) {
		return "", false, errNotTLS
	}
	compLen := int(hs[p])
	p += 1 + compLen
	if p+2 > len(hs) {
		return "", false, errNotTLS
	}
	extLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for p+4 <= end {
		extType := binary.BigEndian.Uint16(hs[p : p+2])
		extLen := int(binary.BigEndian.Uint16(hs[p+2 : p+4]))
		p += 4
		if p+extLen > end {
			break
		}
		if extType == 0x0000 { // server_name
			return parseSNIExt(hs[p : p+extLen])
		}
		p += extLen
	}
	return "", false, errNoSNI
}

// parseSNIExt extracts the first host_name entry.
func parseSNIExt(data []byte) (string, bool, error) {
	if len(data) < 2 {
		return "", false, errNotTLS
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen > len(data)-2 {
		listLen = len(data) - 2
	}
	p := 2
	for p+3 <= 2+listLen {
		nameType := data[p]
		nameLen := int(binary.BigEndian.Uint16(data[p+1 : p+3]))
		p += 3
		if p+nameLen > 2+listLen {
			break
		}
		if nameType == 0 { // host_name
			return string(data[p : p+nameLen]), true, nil
		}
		p += nameLen
	}
	return "", false, errNoSNI
}
