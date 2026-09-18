package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// MITM is the certificate authority used to decrypt rewrite-targeted
// connections. It signs a leaf certificate per hostname on demand (cached)
// with the injected CA. The CA key lives in a K8s Secret scoped to the
// namespace — compromise is contained to that namespace's egress.
type MITM struct {
	ca     tls.Certificate
	caX509 *x509.Certificate

	mu     sync.Mutex
	leaves map[string]*tls.Certificate // hostname -> leaf
}

// LoadMITM parses the CA cert+key pair.
func LoadMITM(certPath, keyPath string) (*MITM, error) {
	ca, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !leaf.IsCA {
		return nil, fmt.Errorf("configured certificate is not a CA")
	}
	return &MITM{ca: ca, caX509: leaf, leaves: map[string]*tls.Certificate{}}, nil
}

// LeafFor returns a TLS certificate for hostname, minting (and caching) one
// when absent. Leaf lifetime is short (24h) so CA rotation propagates.
func (m *MITM) LeafFor(host string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if leaf, ok := m.leaves[host]; ok {
		return leaf, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"easylab-easysidecar"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caX509, &key.PublicKey, m.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, m.caX509.Raw},
		PrivateKey:  key,
	}
	m.leaves[host] = leaf
	return leaf, nil
}

// TLSConfigFor builds the server-side TLS config for a MITM'd hostname.
func (m *MITM) TLSConfigFor(host string) (*tls.Config, error) {
	leaf, err := m.LeafFor(host)
	if err != nil {
		return nil, err
	}
	// Advertise h2 in ALPN: gRPC/Connect clients (buf, some SDKs) require it.
	// serveRewritten branches on the negotiated protocol, so an h2-capable
	// client gets a real HTTP/2 server; everyone else falls back to HTTP/1.1.
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
