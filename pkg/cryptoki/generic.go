package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"hash/crc64"

	"github.com/miekg/pkcs11"
)

// Supported algorithm strings. Compatible with CFSSL.
const (
	RSA   = "rsa"
	ECDSA = "ecdsa"
)

// A keyRequest is a request for generating a new key pair.
type keyRequest interface {
	Algo() string
	Size() int
	KeyID() uint
	Mechanisms() []*pkcs11.Mechanism
	PublicAttrs() []*pkcs11.Attribute
	PrivateAttrs() []*pkcs11.Attribute
}

// newKeyRequest returns an algorithm-specific keyRequest.
func newKeyRequest(label, algo string, size int) (keyRequest, error) {
	switch algo {
	case RSA:
		return newRSAKeyRequest(label, size)
	case ECDSA:
		return newECDSAKeyRequest(label, size)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

// genericKeyRequest partially implements the keyRequest interface. It
// is supposed to be embedded into an algorithm-specific implementation.
type genericKeyRequest struct {
	label string
}

// KeyID returns the identifier deviated from the label.
func (gkr *genericKeyRequest) KeyID() uint {
	return uint(crc64.Checksum([]byte(gkr.label), crc64.MakeTable(crc64.ECMA)))
}

// PublicAttrs returns PKCS#11 attributes for generating a public key.
// Algorithm-specific implementations may provide additional attributes
// by overwriting this method.
func (gkr *genericKeyRequest) PublicAttrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		// Common storage object attributes (PKCS #11-B 10.4)
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, gkr.label),
		// Common key attributes (PKCS #11-B 10.7)
		pkcs11.NewAttribute(pkcs11.CKA_ID, gkr.KeyID()),
		// Common public key attributes (PKCS #11-B 10.8)
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
}

// PrivateAttrs returns PKCS#11 attributes for generating a private key.
func (gkr *genericKeyRequest) PrivateAttrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		// Common storage object attributes (PKCS #11-B 10.4)
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, gkr.label),
		// Common key attributes (PKCS #11-B 10.7)
		pkcs11.NewAttribute(pkcs11.CKA_ID, gkr.KeyID()),
		// Common private key attributes (PKCS #11-B 10.9)
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
}

// publicKey represents a generic public key containing PKCS#11 attributes.
type publicKey interface {
	Attrs() []*pkcs11.Attribute
	CryptoKey() (crypto.PublicKey, error)
}

func newPublicKey(pub crypto.PublicKey) (publicKey, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return newRSAPublicKey(key)
	case *ecdsa.PublicKey:
		return newECDSAPublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported public key of type %T", pub)
	}
}
