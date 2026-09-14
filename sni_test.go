package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestSNIParsing drives the ClientHello reader with a real TLS client.
func TestSNIParsing(t *testing.T) {
	// A server whose handshake we never complete: the reader only needs the
	// ClientHello bytes.
	clientHelloCh := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 16<<10)
		n, _ := c.Read(buf)
		clientHelloCh <- buf[:n]
		_ = c.Close()
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	tlsCfg := &tls.Config{ServerName: "registry.npmjs.org", InsecureSkipVerify: true}
	tlsC := tls.Client(c, tlsCfg)
	// Start the handshake (sends the ClientHello); it will fail when the
	// server closes — that's fine, we only need the bytes.
	go func() { _ = tlsC.Handshake() }()
	time.Sleep(100 * time.Millisecond)

	var hello []byte
	select {
	case hello = <-clientHelloCh:
	default:
	}
	if len(hello) == 0 {
		t.Fatal("no ClientHello captured")
	}

	tr := newTLSReader(bytes.NewReader(hello))
	host, ok, err := tr.sni()
	if err != nil || !ok {
		t.Fatalf("sni: ok=%v err=%v", ok, err)
	}
	if host != "registry.npmjs.org" {
		t.Fatalf("host = %q", host)
	}
	// The full handshake must be buffered for replay.
	if len(tr.buffered()) != len(hello) {
		t.Fatalf("buffered %d != hello %d", len(tr.buffered()), len(hello))
	}
}

// TestSNIPlainHTTP verifies non-TLS traffic yields errNotTLS.
func TestSNIPlainHTTP(t *testing.T) {
	tr := newTLSReader(bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	if _, _, err := tr.sni(); err != errNotTLS {
		t.Fatalf("err = %v want errNotTLS", err)
	}
}

// TestSNIReplay verifies the buffered bytes replay through Read.
func TestSNIReplay(t *testing.T) {
	// Build a minimal valid ClientHello via crypto/tls on the wire.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	helloCh := make(chan []byte, 1)
	go func() {
		c, _ := ln.Accept()
		buf := make([]byte, 16<<10)
		n, _ := c.Read(buf)
		helloCh <- buf[:n]
		_ = c.Close()
	}()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer func() { _ = c.Close() }()
	tlsC := tls.Client(c, &tls.Config{ServerName: "a.b.example", InsecureSkipVerify: true})
	go func() { _ = tlsC.Handshake() }()
	time.Sleep(100 * time.Millisecond)
	var hello []byte
	select {
	case hello = <-helloCh:
	default:
	}
	if hello == nil {
		t.Skip("no hello captured")
	}

	tr := newTLSReader(bytes.NewReader(hello))
	if _, _, err := tr.sni(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(hello))
	if _, err := tr.Read(got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatal("replay mismatch")
	}
}

// TestLoadMITMAndLeaf verifies CA loading and per-host leaf issuance (SAN).
func TestLoadMITMAndLeaf(t *testing.T) {
	// Mint a CA for the test.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "easyproxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := t.TempDir()+"/ca.crt", t.TempDir()+"/ca.key"
	if err := writePEM(certPath, "CERTIFICATE", caDER); err != nil {
		t.Fatal(err)
	}
	if err := writePEMKey(keyPath, caKey); err != nil {
		t.Fatal(err)
	}

	m, err := LoadMITM(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := m.LeafFor("registry.npmjs.org")
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(x.DNSNames) != 1 || x.DNSNames[0] != "registry.npmjs.org" {
		t.Fatalf("SAN = %v", x.DNSNames)
	}
	// Issued by our CA.
	if err := x.CheckSignatureFrom(mustParseCA(caDER)); err != nil {
		t.Fatalf("leaf not signed by CA: %v", err)
	}
	// Cached: same pointer.
	leaf2, _ := m.LeafFor("registry.npmjs.org")
	if leaf2 != leaf {
		t.Fatal("leaf not cached")
	}
}

func mustParseCA(der []byte) *x509.Certificate {
	c, _ := x509.ParseCertificate(der)
	return c
}
