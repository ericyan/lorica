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
