package cryptoki

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
)

// rsaKeyRequest contains parameters for generating RSA key pairs.
type rsaKeyRequest struct {
	size int
}

// NewRSAKeyRequest returns an RSA key request.
func NewRSAKeyRequest(size int) KeyRequest {
	return &rsaKeyRequest{size}
}

// Algo returns the requested key algorithm, "rsa", as a string.
func (kr *rsaKeyRequest) Algo() string {
	return "rsa"
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

// Attrs returns the PKCS#11 public key object attributes for the RSA
// key request (PKCS #11-M1 6.1.2).
func (kr *rsaKeyRequest) Attrs() ([]*pkcs11.Attribute, error) {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, kr.Size()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	}, nil
}

type rsaKeyParams struct {
	modulus  []byte
	exponent []byte
}

func parseRSAKeyParams(key *rsa.PublicKey) (*rsaKeyParams, error) {
	modulus := key.N.Bytes()
	exponent := big.NewInt(int64(key.E)).Bytes()

	return &rsaKeyParams{modulus, exponent}, nil
}

// Attrs returns the PKCS#11 public key object attributes for the RSA
// public key. if the underling public key is undefined, no error will
// be returned, but the attribute values will be nil.
func (kp *rsaKeyParams) Attrs() ([]*pkcs11.Attribute, error) {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, kp.modulus),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, kp.exponent),
	}, nil
}

// Key recreates the public key using the key params.
func (kp *rsaKeyParams) Key() (*rsa.PublicKey, error) {
	if kp.modulus == nil {
		return nil, errors.New("missing public modulus")
	}
	if kp.exponent == nil {
		return nil, errors.New("missing public exponent")
	}

	n := new(big.Int).SetBytes(kp.modulus)
	e := int(new(big.Int).SetBytes(kp.exponent).Int64())

	return &rsa.PublicKey{n, e}, nil
}
