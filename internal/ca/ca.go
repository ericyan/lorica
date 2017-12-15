package ca

import (
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/ericyan/lorica/cryptoki"
)

// CA represents a certification authority.
type CA struct {
	key    *cryptoki.KeyPair
	signer *local.Signer
}

// Sign signs CSR and returns certificate. Both CSR and certificate are
// PEM-encoded.
func (ca *CA) Sign(csrPEM []byte) ([]byte, error) {
	req := signer.SignRequest{Request: string(csrPEM)}

	return ca.signer.Sign(req)
}

// New returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func New(cert *x509.Certificate, cfg *Config, key *cryptoki.KeyPair) (*CA, error) {
	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}

	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %s", err)
	}

	return &CA{key, signer}, nil
}
