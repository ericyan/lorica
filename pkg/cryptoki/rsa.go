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

// Get the RSA public key using the object handle.
func (tk *Token) getRSAPublicKey(handle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attrs, err := tk.module.GetAttributeValue(tk.session, handle, template)
	if err != nil {
		return nil, err
	}

	n := big.NewInt(0)
	e := int(0)
	gotModulus, gotExponent := false, false
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_MODULUS:
			n.SetBytes(a.Value)
			gotModulus = true
		case pkcs11.CKA_PUBLIC_EXPONENT:
			bigE := big.NewInt(0)
			bigE.SetBytes(a.Value)
			e = int(bigE.Int64())
			gotExponent = true
		}
	}
	if !gotModulus {
		return nil, errors.New("missing public modulus")
	}
	if !gotExponent {
		return nil, errors.New("missing public exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func getRSAPublicKeyTemplate(key *rsa.PublicKey) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
	}
}
