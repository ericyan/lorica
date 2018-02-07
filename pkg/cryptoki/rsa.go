package cryptoki

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
)

// rsaKeyRequest contains parameters for generating RSA key pairs.
type rsaKeyRequest struct {
	*genericKeyRequest

	size int
}

// newRSAKeyRequest returns an RSA key request.
func newRSAKeyRequest(label string, size int) (*rsaKeyRequest, error) {
	gkr := &genericKeyRequest{label}
	return &rsaKeyRequest{gkr, size}, nil
}

// Algo returns the requested key algorithm, "rsa", as a string.
func (kr *rsaKeyRequest) Algo() string {
	return RSA
}

// Size returns the requested key size in bits.
func (kr *rsaKeyRequest) Size() int {
	return kr.size
}

// Mechanisms returns a list of PKCS#11 mechanisms for generating an RSA
// key pair.
func (kr *rsaKeyRequest) Mechanisms() []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
}

// PublicAttrs returns the PKCS#11 public key object attributes for the
// RSA key request (PKCS #11-M1 6.1.2).
func (kr *rsaKeyRequest) PublicAttrs() []*pkcs11.Attribute {
	return append(kr.genericKeyRequest.PublicAttrs(),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, kr.Size()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	)
}

// rsaPublicKey represents an RSA public key.
type rsaPublicKey struct {
	modulus        []byte
	publicExponent []byte
}

// newRSAPublicKey returns a rsaPublicKey using a crypto.PublicKey.
func newRSAPublicKey(key *rsa.PublicKey) (*rsaPublicKey, error) {
	modulus := key.N.Bytes()
	exponent := big.NewInt(int64(key.E)).Bytes()

	return &rsaPublicKey{modulus, exponent}, nil
}

// Attrs returns the PKCS#11 public key object attributes for the RSA
// public key.
func (key *rsaPublicKey) Attrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.modulus),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, key.publicExponent),
	}
}

// CryptoKey recreates the crypto.PublicKey.
func (key *rsaPublicKey) CryptoKey() (crypto.PublicKey, error) {
	if key.modulus == nil || key.publicExponent == nil {
		return nil, errors.New("invalid rsaPublicKey")
	}

	n := new(big.Int).SetBytes(key.modulus)
	e := int(new(big.Int).SetBytes(key.publicExponent).Int64())

	return &rsa.PublicKey{n, e}, nil
}
