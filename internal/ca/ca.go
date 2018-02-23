package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// CertificationAuthority represents a certification authority.
type CertificationAuthority struct {
	signer.Signer
}

// New returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func New(cert *x509.Certificate, cfg *Config, key crypto.Signer) (*CertificationAuthority, error) {
	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}

	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %s", err)
	}

	return &CertificationAuthority{signer}, nil
}

// SignPEM signs a PEM-encoded CSR and returns the certificate in PEM.
func (ca *CertificationAuthority) SignPEM(csrPEM []byte) ([]byte, error) {
	req := signer.SignRequest{Request: string(csrPEM)}

	return ca.Sign(req)
}
