package cryptoki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

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

// Mechanisms returns a list of PKCS#11 mechanisms for generating an
// ECDSA key pair.
func (kr *ecdsaKeyRequest) Mechanisms() []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
}

// Attrs returns the PKCS#11 public key object attributes for the ECDSA
// key request (PKCS #11-M1 6.3.3).
func (kr *ecdsaKeyRequest) Attrs() ([]*pkcs11.Attribute, error) {
	// Named curves (RFC 5480 2.1.1.1)
	var curveOID asn1.ObjectIdentifier
	switch kr.size {
	case 224:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case 256:
		curveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case 384:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case 521:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, fmt.Errorf("unknown curve: %d", kr.size)
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
	// CKA_EC_PARAMS is DER-encoding of an ANSI X9.62 Parameters value
	var curveOID asn1.ObjectIdentifier
	switch key.Curve {
	case elliptic.P224():
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case elliptic.P256():
		curveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, errors.New("unknown elliptic curve")
	}
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
func (kp *ecdsaKeyParams) Attrs() ([]*pkcs11.Attribute, error) {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, kp.ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, kp.ecPoint),
	}, nil
}

// Key recreates the public key using the key params.
func (kp *ecdsaKeyParams) Key() (*ecdsa.PublicKey, error) {
	if kp.ecParams == nil {
		return nil, errors.New("missing EC params")
	}

	var curveOID asn1.ObjectIdentifier
	asn1.Unmarshal(kp.ecParams, &curveOID)

	var curve elliptic.Curve
	switch {
	case curveOID.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}):
		curve = elliptic.P224()
	case curveOID.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
		curve = elliptic.P256()
	case curveOID.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
		curve = elliptic.P384()
	case curveOID.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}):
		curve = elliptic.P521()
	default:
		return nil, errors.New("invalid EC params")
	}

	if kp.ecPoint == nil {
		return nil, errors.New("missing EC point")
	}

	var ecPoint asn1.RawValue
	asn1.Unmarshal(kp.ecPoint, &ecPoint)

	x, y := elliptic.Unmarshal(curve, ecPoint.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("invalid EC point")
	}

	return &ecdsa.PublicKey{curve, x, y}, nil
}
