package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"

	"github.com/miekg/pkcs11"
)

// Named curves (RFC 5480 2.1.1.1)
var curveOIDs = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P224(): asn1.ObjectIdentifier{1, 3, 132, 0, 33},
	elliptic.P256(): asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384(): asn1.ObjectIdentifier{1, 3, 132, 0, 34},
	elliptic.P521(): asn1.ObjectIdentifier{1, 3, 132, 0, 35},
}

// ecdsaKeyRequest contains parameters for generating ECDSA key pairs.
type ecdsaKeyRequest struct {
	*genericKeyRequest

	curve elliptic.Curve
}

// newECDSAKeyRequest returns a ECDSA key request.
func newECDSAKeyRequest(label string, size int) (*ecdsaKeyRequest, error) {
	gkr := &genericKeyRequest{label}

	switch size {
	case 224:
		return &ecdsaKeyRequest{gkr, elliptic.P224()}, nil
	case 256:
		return &ecdsaKeyRequest{gkr, elliptic.P256()}, nil
	case 384:
		return &ecdsaKeyRequest{gkr, elliptic.P384()}, nil
	case 521:
		return &ecdsaKeyRequest{gkr, elliptic.P521()}, nil
	default:
		return nil, errors.New("unknown elliptic curve")
	}
}

// Algo returns the requested key algorithm, "ecdsa", as a string.
func (kr *ecdsaKeyRequest) Algo() string {
	return ECDSA
}

// Size returns the requested key size, referring to a named curve.
func (kr *ecdsaKeyRequest) Size() int {
	return kr.curve.Params().BitSize
}

// Mechanisms returns a list of PKCS#11 mechanisms for generating an
// ECDSA key pair.
func (kr *ecdsaKeyRequest) Mechanisms() []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
}

// PublicAttrs returns the PKCS#11 public key object attributes for the
// ECDSA key request (PKCS #11-M1 6.3.3).
func (kr *ecdsaKeyRequest) PublicAttrs() []*pkcs11.Attribute {
	ecParams, _ := asn1.Marshal(curveOIDs[kr.curve])
	return append(kr.genericKeyRequest.PublicAttrs(),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	)
}

// ecdsaPublicKey represents an ECDSA public key.
type ecdsaPublicKey struct {
	ecParams []byte
	ecPoint  []byte
}

// newECDSAPublicKey returns an ecdsaPublicKey using a crypto.PublicKey.
func newECDSAPublicKey(key *ecdsa.PublicKey) (*ecdsaPublicKey, error) {
	curveOID, ok := curveOIDs[key.Curve]
	if !ok {
		return nil, errors.New("unknown elliptic curve")
	}

	// CKA_EC_PARAMS is DER-encoding of an ANSI X9.62 Parameters value
	ecParams, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, err
	}

	// CKA_EC_POINT is DER-encoding of ANSI X9.62 ECPoint value Q
	ecPoint, err := asn1.Marshal(asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
	})
	if err != nil {
		return nil, err
	}

	return &ecdsaPublicKey{ecParams, ecPoint}, nil
}

// Attrs returns the PKCS#11 public key object attributes for the ECDSA
// public key.
func (key *ecdsaPublicKey) Attrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, key.ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, key.ecPoint),
	}
}

// CryptoKey recreates the crypto.PublicKey.
func (key *ecdsaPublicKey) CryptoKey() (crypto.PublicKey, error) {
	if key.ecParams == nil || key.ecPoint == nil {
		return nil, errors.New("invalid ecdsaPublicKey")
	}

	var curveOID asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(key.ecParams, &curveOID)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	for c, oid := range curveOIDs {
		if curveOID.Equal(oid) {
			curve = c
			break
		}
	}
	if curve == nil {
		return nil, errors.New("invalid EC params")
	}

	var ecPoint asn1.RawValue
	_, err = asn1.Unmarshal(key.ecPoint, &ecPoint)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(curve, ecPoint.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("invalid EC point")
	}

	return &ecdsa.PublicKey{curve, x, y}, nil
}
