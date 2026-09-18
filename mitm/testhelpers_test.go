package mitm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/easylab-platform/easysidecar/testca"
)

func writePEM(path, blockType string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600)
}

func writePEMKey(path string, key *rsa.PrivateKey) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600)
}

// mintTestCA delegates to testca so the CA shape matches the relay tests.
func mintTestCA() ([]byte, []byte, error) { return testca.Mint() }
