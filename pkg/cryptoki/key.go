package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// A KeyRequest is a generic request for a new key pair.
type KeyRequest interface {
	Algo() string
	Size() int
}

// A keyRequest is a KeyRequest with additional internal methods.
type keyRequest interface {
	KeyRequest
	Mechanisms() []*pkcs11.Mechanism
	Attrs() ([]*pkcs11.Attribute, error)
}

// keyParams provides a method for extracting attributes from a key.
type keyParams interface {
	Attrs() ([]*pkcs11.Attribute, error)
}

// KeyPair implements the crypto.Signer interface using a key pair kept
// in PKCS #11 cryptographic token.
type KeyPair struct {
	tk         *Token
	pub        crypto.PublicKey
	privHandle pkcs11.ObjectHandle
}

// Public returns the public key of the key pair.
func (kp *KeyPair) Public() crypto.PublicKey {
	return kp.pub
}

// Sign signs digest with the private key. The entropy from rand will
// be ignored.
//
// For RSA, the signature scheme will be RSASSA-PKCS1-v1_5, unless opts
// is an *rsa.PSSOptions in which case RSASSA-PSS scheme will be used.
//
// For ECDSA, the resulting signature will be a DER-serialised, ASN.1
// signature structure.
func (kp *KeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("input massage must be hashed")
	}

	switch kp.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return kp.tk.Sign(pkcs11.CKM_RSA_PKCS_PSS, digest, kp.privHandle, opts)
		}

		return kp.tk.Sign(pkcs11.CKM_RSA_PKCS, digest, kp.privHandle, opts)
	case *ecdsa.PublicKey:
		return kp.tk.Sign(pkcs11.CKM_ECDSA, digest, kp.privHandle, opts)
	default:
		return nil, fmt.Errorf("unrecognized key type %T", kp.pub)
	}
}

// NewKeyPair generates a new key pair inside the token and returns the
// KeyPair for signing.
func NewKeyPair(tk *Token, label string, kr KeyRequest) (*KeyPair, error) {
	pubHandle, privHandle, err := tk.GenerateKeyPair(label, kr)
	if err != nil {
		return nil, err
	}

	pub, err := tk.ExportPublicKey(pubHandle)
	if err != nil {
		return nil, err

	}

	return &KeyPair{tk, pub, privHandle}, nil
}

// FindKeyPair looks up the key pair inside the token with matching
// public key.
func FindKeyPair(tk *Token, pub crypto.PublicKey) (*KeyPair, error) {
	// First, looks up the given public key in the token, and returns get
	// its object handle if found.
	var kp keyParams
	var err error
	switch key := pub.(type) {
	case *rsa.PublicKey:
		kp, err = parseRSAKeyParams(key)
	case *ecdsa.PublicKey:
		kp, err = parseECDSAKeyParams(key)
	default:
		return nil, fmt.Errorf("unsupported public key of type %T", pub)
	}
	if err != nil {
		return nil, err
	}

	template, err := kp.Attrs()
	if err != nil {
		return nil, err
	}

	pubHandle, err := tk.findObject(template)
	if err != nil {
		return nil, err
	}

	// Then looks up the private key with matching CKA_ID of the given public key handle.
	attrs, err := tk.module.GetAttributeValue(tk.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, err
	}

	if len(attrs) == 0 || attrs[0].Type != pkcs11.CKA_ID {
		return nil, errors.New("invalid attribute value")
	}
	publicKeyID := attrs[0].Value

	privHandle, err := tk.findObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publicKeyID),
	})
	if err != nil {
		return nil, err
	}

	return &KeyPair{tk, pub, privHandle}, nil
}
