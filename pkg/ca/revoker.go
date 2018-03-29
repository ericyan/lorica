package ca

import (
	"errors"

	"github.com/cloudflare/cfssl/certdb"
)

type Revoker interface {
	// Revoke marks the certificate identified by its serial number and
	// authority key identifier revoked. The reasonCode is defined in
	// RFC 5280 5.3.1.
	Revoke(serial, aki string, reasonCode int) error
}

type revoker struct {
	db certdb.Accessor
}

// NewRevoker returns a new Rovoker.
func NewRevoker(db certdb.Accessor) (Revoker, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}

	return &revoker{db}, nil
}

// Revoke implements the Revoker interface.
func (r *revoker) Revoke(serial, aki string, reasonCode int) error {
	return r.db.RevokeCertificate(serial, aki, reasonCode)
}
