package procedure

import (
	"github.com/cloudflare/cfssl/helpers"
	"github.com/ericyan/lorica/internal/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Sign finds the key pair with the public key in the CA certificate and
// then signs the CSR with that key. The CA certificate, CSR as well as
// the resulting certificate are PEM-encoded.
func Sign(tk *cryptoki.Token, cfg *ca.Config, caPEM, csrPEM []byte) ([]byte, error) {
	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		return nil, err
	}

	key, err := cryptoki.FindKeyPair(tk, caCert.PublicKey)
	if err != nil {
		return nil, err
	}

	ca, err := ca.New(caCert, cfg, key)
	if err != nil {
		return nil, err
	}

	return ca.Sign(csrPEM)
}
