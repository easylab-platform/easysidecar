package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestH2ALPNAdvertised: the MITM config must offer h2 (gRPC/Connect clients
// need it) ahead of http/1.1 so legacy clients still negotiate h1.
func TestH2ALPNAdvertised(t *testing.T) {
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
	dir := t.TempDir()
	certPath, keyPath := dir+"/ca.crt", dir+"/ca.key"
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
	cfg, err := m.TLSConfigFor("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Fatalf("NextProtos = %v", cfg.NextProtos)
	}
}
