package cryptoki

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
)

func getRSAKeyGenAttrs(kr KeyRequest) ([]*pkcs11.Mechanism, []*pkcs11.Attribute) {
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		// RSA public key object attributes (PKCS #11-M1 6.1.2)
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, kr.Size()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		}
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
