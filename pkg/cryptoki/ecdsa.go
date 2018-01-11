package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

func getECDSAKeyGenAttrs(kr KeyRequest) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, error) {
	// Named curves (RFC 5480 2.1.1.1)
	var curveOID asn1.ObjectIdentifier
	switch kr.Size() {
	case 224:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case 256:
		curveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case 384:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case 521:
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, nil, fmt.Errorf("unknown curve: %d", kr.Size())
	}

	ecParams, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, nil, err
	}

	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		// Elliptic curve public key object attributes(PKCS #11-M1 6.3.3)
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		},
		nil
}

// Get the EC public key using the object handle.
func (tk *Token) getECPublicKey(handle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attrs, err := tk.module.GetAttributeValue(tk.session, handle, template)
	if err != nil {
		return nil, err
	}

	var curveOID asn1.ObjectIdentifier
	var ecPoint asn1.RawValue
	gotParams, gotPoint := false, false
	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_EC_PARAMS:
			asn1.Unmarshal(attr.Value, &curveOID)
			gotParams = true
		case pkcs11.CKA_EC_POINT:
			asn1.Unmarshal(attr.Value, &ecPoint)
			gotPoint = true
		}
	}
	if !gotParams {
		return nil, errors.New("missing EC params")
	}
	if !gotPoint {
		return nil, errors.New("missing EC point")
	}

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

	x, y := elliptic.Unmarshal(curve, ecPoint.Bytes)
	if x == nil || y == nil {
		return nil, errors.New("invalid EC point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func getECPublicKeyTemplate(key *ecdsa.PublicKey) ([]*pkcs11.Attribute, error) {
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

	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
	}, nil
}
