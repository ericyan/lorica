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
func (kp *KeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("input massage must be hashed")
	}

	var mech uint
	switch kp.pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			mech = pkcs11.CKM_RSA_PKCS_PSS

			// TODO: Support the PKCS #1 RSA PSS mechanism.
			return nil, errors.New("unsupported mechanism")
		}

		mech = pkcs11.CKM_RSA_PKCS

		// The PKCS #1 v1.5 RSA mechanism	corresponds only to the part that
		// involves RSA; it does not compute the DigestInfo, which is  a DER-
		// serialised ASN.1 struct:
		//
		//	DigestInfo ::= SEQUENCE {
		//		digestAlgorithm AlgorithmIdentifier,
		//		digest OCTET STRING
		//	}
		//
		// For performance, we precompute a prefix of the digest value that
		// makes a valid ASN.1 DER string.
		var prefix []byte
		switch opts.HashFunc() {
		case crypto.MD5:
			prefix = []byte{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10}
		case crypto.SHA1:
			prefix = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
		case crypto.SHA224:
			prefix = []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}
		case crypto.SHA256:
			prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
		case crypto.SHA384:
			prefix = []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
		case crypto.SHA512:
			prefix = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
		default:
			return nil, errors.New("unsupported hash function")
		}
		digest = append(prefix, digest...)
	case *ecdsa.PublicKey:
		mech = pkcs11.CKM_ECDSA
	default:
		return nil, fmt.Errorf("unrecognized key type %T", kp.pub)
	}

	return kp.tk.Sign(mech, digest, kp.privHandle)
}
