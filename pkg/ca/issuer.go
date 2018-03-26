package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

type Issuer interface {
	// Issue signs a PEM-encoded CSR and returns the certificate in PEM.
	Issue(csrPEM []byte) (certPEM []byte, err error)
}

type issuer struct {
	signer.Signer
}

// NewIssuer returns a new Issuer backed by a CFSSL local signer.
func NewIssuer(key crypto.Signer, cert *x509.Certificate, policy *config.Signing, db certdb.Accessor) (Issuer, error) {
	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %s", err)
	}

	if db == nil {
		return nil, errors.New("nil db")
	}
	signer.SetDBAccessor(db)

	return &issuer{signer}, nil
}

// Issue implements the Issuer interface.
func (i *issuer) Issue(csrPEM []byte) ([]byte, error) {
	req := signer.SignRequest{Request: string(csrPEM)}

	return i.Sign(req)
}
