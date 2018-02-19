package cryptoki

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
)

// pkcs1v15DigestPrefixes provides precomputed prefixes for consturcting
// DigestInfo which is a DER-serialised ASN.1 struct:
//
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
var pkcs1v15DigestPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:    {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

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
