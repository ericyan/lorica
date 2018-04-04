package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/json"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

type KeyProvider interface {
	GenerateKeyPair(label string, algo string, size int) (crypto.Signer, error)
	FindKeyPair(key crypto.PublicKey) (crypto.Signer, error)
}

// CertificationAuthority represents a certification authority.
type CertificationAuthority struct {
	db *database

	cert *x509.Certificate

	Issuer
	Revoker
}

// Init creates a CA with given config.
func Init(cfg *Config, kp KeyProvider) (*CertificationAuthority, error) {
	req := cfg.CertificateRequest()
	key, err := kp.GenerateKeyPair(req.CN, req.KeyRequest.Algo(), req.KeyRequest.Size())
	if err != nil {
		return nil, err
	}

	db, err := openDB(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		return nil, err
	}
	err = db.SetMetadata([]byte("csr"), csrPEM)
	if err != nil {
		return nil, err
	}

	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}

	ca, err := newCA(key, nil, policy, db)
	if err != nil {
		return nil, err
	}

	if cfg.SelfSign {
		certPEM, err := ca.Issue(csrPEM)
		if err != nil {
			return nil, err
		}
		err = db.SetMetadata([]byte("cert"), certPEM)
		if err != nil {
			return nil, err
		}

		ca.cert, err = helpers.ParseCertificatePEM(certPEM)
		if err != nil {
			return nil, err
		}
	}

	return ca, nil
}

// Open opens an existing CA.
func Open(caFile string, kp KeyProvider) (*CertificationAuthority, error) {
	db, err := openDB(caFile)
	if err != nil {
		return nil, err
	}

	certPEM, err := db.GetMetadata([]byte("cert"))
	if err != nil {
		return nil, err
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	key, err := kp.FindKeyPair(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	policyJSON, err := db.GetMetadata([]byte("policy"))
	if err != nil {
		return nil, err
	}
	var policy *config.Signing
	err = json.Unmarshal(policyJSON, policy)
	if err != nil {
		return nil, err
	}

	return newCA(key, cert, policy, db)
}

// newCA returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func newCA(key crypto.Signer, cert *x509.Certificate, policy *config.Signing, db *database) (*CertificationAuthority, error) {
	issuer, err := NewIssuer(key, cert, policy, db.Accessor())
	if err != nil {
		return nil, err
	}

	revoker, err := NewRevoker(db.Accessor())
	if err != nil {
		return nil, err
	}

	return &CertificationAuthority{db, cert, issuer, revoker}, nil
}

// Certificate returns the certificate of the CA.
func (ca *CertificationAuthority) Certificate() *x509.Certificate {
	return ca.cert
}

// GetMetadata returns the metadata with given key.
func (ca *CertificationAuthority) GetMetadata(key string) ([]byte, error) {
	return ca.db.GetMetadata([]byte(key))
}
