package ca

import (
	"crypto"
	"crypto/x509"

	"github.com/cloudflare/cfssl/certdb"
)

// CertificationAuthority represents a certification authority.
type CertificationAuthority struct {
	db certdb.Accessor

	Issuer
}

// New returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func New(cert *x509.Certificate, cfg *Config, key crypto.Signer) (*CertificationAuthority, error) {
	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}

	db, err := openDB(cfg.Database)
	if err != nil {
		return nil, err
	}

	issuer, err := NewIssuer(key, cert, policy, db)
	if err != nil {
		return nil, err
	}

	return &CertificationAuthority{db, issuer}, nil
}
