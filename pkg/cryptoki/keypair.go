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

// KeyPair implements the crypto.Signer interface using a key pair kept
// in PKCS #11 cryptographic token.
type KeyPair struct {
	tk         *Token
	pub        crypto.PublicKey
	privHandle pkcs11.ObjectHandle
}

// GenerateKeyPair generates a key pair inside the token.
func (tk *Token) GenerateKeyPair(label string, algo string, size int) (*KeyPair, error) {
	kr, err := newKeyRequest(label, algo, size)
	if err != nil {
		return nil, err
	}

	pubHandle, privHandle, err := tk.module.GenerateKeyPair(tk.session, kr.Mechanisms(), kr.PublicAttrs(), kr.PrivateAttrs())
	if err != nil {
		return nil, err
	}

	pub, err := tk.ExportPublicKey(pubHandle)
	if err != nil {
		return nil, err

	}

	return &KeyPair{tk, pub, privHandle}, nil
}

// FindKeyPair looks up a key pair inside the token with the public key.
func (tk *Token) FindKeyPair(key crypto.PublicKey) (*KeyPair, error) {
	// First, looks up the given public key in the token, and returns get
	// its object handle if found.
	pub, err := newPublicKey(key)
	if err != nil {
		return nil, err
	}

	pubHandle, err := tk.FindObject(pub.Attrs())
	if err != nil {
		return nil, err
	}

	// Then looks up the private key with matching CKA_ID of the given public key handle.
	publicKeyID, err := tk.GetAttribute(pubHandle, pkcs11.CKA_ID)
	if err != nil {
		return nil, err
	}

	privHandle, err := tk.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publicKeyID),
	})
	if err != nil {
		return nil, err
	}

	return &KeyPair{tk, pub, privHandle}, nil
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
func (kp *KeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("input is not a digest")
	}

	var mech uint
	switch kp.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			mech = pkcs11.CKM_RSA_PKCS_PSS
		} else {
			mech = pkcs11.CKM_RSA_PKCS
		}
	case *ecdsa.PublicKey:
		mech = pkcs11.CKM_ECDSA
	default:
		return nil, fmt.Errorf("unsupported key type: %T", kp.pub)
	}

	// TODO: Add support for the RSASSA-PSS (for TLS 1.3).
	if mech == pkcs11.CKM_RSA_PKCS_PSS {
		return nil, errors.New("RSASSA-PSS not supported")
	}

	// The PKCS #1 v1.5 RSA mechanism	corresponds only to the part that
	// involves RSA; so we will need to compute the DigestInfo here.
	if mech == pkcs11.CKM_RSA_PKCS {
		prefix, ok := pkcs1v15DigestPrefixes[hash]
		if !ok {
			return nil, errors.New("unsupported hash function")
		}

		digest = append(prefix, digest...)
	}

	return kp.tk.Sign(digest, kp.privHandle, mech)
}
