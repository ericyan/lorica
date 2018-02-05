package cryptoki

import (
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
	size int
}

// NewECKeyRequest returns a prime256v1 EC(DSA) key request.
func NewECKeyRequest(size int) KeyRequest {
	return &ecdsaKeyRequest{size}
}

// Algo returns the requested key algorithm, "ecdsa", as a string.
func (kr *ecdsaKeyRequest) Algo() string {
	return "ecdsa"
}

// Size returns the requested key size, referring to a named curve.
func (kr *ecdsaKeyRequest) Size() int {
	return kr.size
}

// Curve returns the elliptic curves based on key size. It returns nil
// if the curve is unknown.
func (kr *ecdsaKeyRequest) Curve() elliptic.Curve {
	switch kr.size {
	case 224:
		return elliptic.P224()
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	default:
		return nil
	}
}

// Mechanisms returns a list of PKCS#11 mechanisms for generating an
// ECDSA key pair.
func (kr *ecdsaKeyRequest) Mechanisms() []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
}

// Attrs returns the PKCS#11 public key object attributes for the ECDSA
// key request (PKCS #11-M1 6.3.3).
func (kr *ecdsaKeyRequest) Attrs() ([]*pkcs11.Attribute, error) {
	curveOID, ok := curveOIDs[kr.Curve()]
	if !ok {
		return nil, errors.New("unknown elliptic curve")
	}

	ecParams, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, err
	}

	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
	}, nil
}

type ecdsaKeyParams struct {
	ecParams []byte
	ecPoint  []byte
}

func parseECDSAKeyParams(key *ecdsa.PublicKey) (*ecdsaKeyParams, error) {
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

	return &ecdsaKeyParams{ecParams, ecPoint}, nil
}

// Attrs returns the PKCS#11 public key object attributes for the ECDSA
// public key. if the underling public key is undefined, no error will
// be returned, but the attribute values will be nil.
func (kp *ecdsaKeyParams) Attrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, kp.ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, kp.ecPoint),
	}
}

// Key recreates the public key using the key params.
func (kp *ecdsaKeyParams) Key() (*ecdsa.PublicKey, error) {
	if kp.ecParams == nil {
		return nil, errors.New("missing EC params")
	}

	var curveOID asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(kp.ecParams, &curveOID)
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

	if kp.ecPoint == nil {
		return nil, errors.New("missing EC point")
	}

	var ecPoint asn1.RawValue
	_, err = asn1.Unmarshal(kp.ecPoint, &ecPoint)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(curve, ecPoint.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("invalid EC point")
	}

	return &ecdsa.PublicKey{curve, x, y}, nil
}
