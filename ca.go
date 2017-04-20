package lorica

import (
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/ericyan/lorica/cryptoki"
)

// CA represents a certification authority.
type CA struct {
	Cert   *x509.Certificate
	Policy *config.Signing
	key    *cryptoki.KeyPair
}

// Sign signs CSR and returns certificate. Both CSR and certificate are
// PEM-encoded.
func (ca *CA) Sign(csrPEM []byte) ([]byte, error) {
	s, err := local.NewSigner(ca.key, ca.Cert, signer.DefaultSigAlgo(ca.key), ca.Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %s", err)
	}

	req := signer.SignRequest{Request: string(csrPEM)}

	return s.Sign(req)
}

// NewCA returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func NewCA(cert *x509.Certificate, policy *config.Signing, key *cryptoki.KeyPair) (*CA, error) {
	return &CA{cert, policy, key}, nil
}
