package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash/crc64"
	"math/big"

	"github.com/miekg/pkcs11"
)

// A Token represents a cryptographic token that implements PKCS #11.
type Token struct {
	module  *pkcs11.Ctx
	session pkcs11.SessionHandle
}

// findSlot retrieves ID of the slot with matching token label.
func findSlot(module *pkcs11.Ctx, tokenLabel string) (uint, error) {
	var nilSlot uint

	slots, err := module.GetSlotList(true)
	if err != nil {
		return nilSlot, fmt.Errorf("failed to get slot list: %s", err)
	}

	for _, slot := range slots {
		tokenInfo, err := module.GetTokenInfo(slot)
		if err != nil {
			return nilSlot, fmt.Errorf("failed to get token info: %s", err)
		}

		if tokenInfo.Label == tokenLabel {
			return slot, nil
		}
	}

	return nilSlot, fmt.Errorf("no slot with token label '%q'", tokenLabel)
}

// OpenToken opens a new session with the given cryptographic token.
func OpenToken(modulePath, tokenLabel, pin string, readOnly bool) (*Token, error) {
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, fmt.Errorf("failed to load module '%s'", modulePath)
	}

	err := module.Initialize()
	if err != nil {
		return nil, err
	}

	slotID, err := findSlot(module, tokenLabel)
	if err != nil {
		return nil, err
	}

	var flags uint
	if readOnly {
		flags = pkcs11.CKF_SERIAL_SESSION
	} else {
		flags = pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION
	}
	session, err := module.OpenSession(slotID, flags)
	if err != nil {
		return nil, err
	}

	// Log in as a normal user with given PIN.
	//
	// NOTE: Login status is application-wide, not per session. It is fine
	// if the token complains user already logged in.
	err = module.Login(session, pkcs11.CKU_USER, pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		module.CloseSession(session)
		return nil, err
	}

	return &Token{module, session}, nil
}

// Close closes the current session with the token.
//
// NOTE: We do not explicitly log out the session or unload the module
// here, as it may cause problem if there are multiple sessions active.
// In general, it will log out once the last session is closed and the
// module will be unloaded at the end of the process.
func (tk *Token) Close() error {
	err := tk.module.CloseSession(tk.session)
	if err != nil {
		return fmt.Errorf("failed to close session: %s", err)
	}

	return nil
}

// Info obtains information about the token.
func (tk *Token) Info() (pkcs11.TokenInfo, error) {
	var nilTokenInfo pkcs11.TokenInfo

	sessionInfo, err := tk.module.GetSessionInfo(tk.session)
	if err != nil {
		return nilTokenInfo, fmt.Errorf("failed to get session info: %s", err)
	}

	tokenInfo, err := tk.module.GetTokenInfo(sessionInfo.SlotID)
	if err != nil {
		return nilTokenInfo, fmt.Errorf("failed to get token info: %s", err)
	}

	return tokenInfo, nil
}

// GenerateKeyPair generates a key pair inside the token.
func (tk *Token) GenerateKeyPair(label string, kr KeyRequest) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	var nilObjectHandle pkcs11.ObjectHandle

	keyID := uint(crc64.Checksum([]byte(label), crc64.MakeTable(crc64.ECMA)))

	publicKeyTemplate := []*pkcs11.Attribute{
		// Common storage object attributes (PKCS #11-B 10.4)
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		// Common key attributes (PKCS #11-B 10.7)
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		// Common public key attributes (PKCS #11-B 10.8)
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		// Common storage object attributes (PKCS #11-B 10.4)
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		// Common key attributes (PKCS #11-B 10.7)
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		// Common private key attributes (PKCS #11-B 10.9)
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	var mech uint
	switch kr.Algo() {
	case "rsa":
		mech = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN

		// RSA public key object attributes (PKCS #11-M1 6.1.2)
		publicKeyTemplate = append(publicKeyTemplate,
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, kr.Size()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		)
	case "ecdsa":
		mech = pkcs11.CKM_EC_KEY_PAIR_GEN

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
			return nilObjectHandle, nilObjectHandle, fmt.Errorf("unknown curve: %d", kr.Size())
		}
		ecParams, err := asn1.Marshal(curveOID)
		if err != nil {
			return nilObjectHandle, nilObjectHandle, err
		}

		// Elliptic curve public key object attributes(PKCS #11-M1 6.3.3)
		publicKeyTemplate = append(publicKeyTemplate,
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		)
	default:
		return nilObjectHandle, nilObjectHandle, fmt.Errorf("unsupported algorithm: %s", kr.Algo())
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}

	return tk.module.GenerateKeyPair(tk.session, mechanism, publicKeyTemplate, privateKeyTemplate)
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

// ExportPublicKey retrieves the public key with given object handle.
func (tk *Token) ExportPublicKey(handle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	attr, err := tk.module.GetAttributeValue(tk.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, false),
	})
	if (len(attr) == 0) || (len(attr[0].Value) == 0) {
		err = errors.New("invalid public key object")
	}
	if err != nil {
		return nil, err
	}

	switch attr[0].Value[0] {
	case pkcs11.CKK_RSA:
		return tk.getRSAPublicKey(handle)
	case pkcs11.CKK_EC:
		return tk.getECPublicKey(handle)
	default:
		return nil, errors.New("unknown key type")
	}
}

// Sign signs digest with the private key in token. It is the caller's
// responsibility to compute the message digest.
func (tk *Token) Sign(mech uint, digest []byte, key pkcs11.ObjectHandle, opts crypto.SignerOpts) (signature []byte, err error) {
	var mechanism []*pkcs11.Mechanism
	switch mech {
	// The PKCS #1 v1.5 RSA mechanism	corresponds only to the part that
	// involves RSA; it does not compute the DigestInfo, which is  a DER-
	// serialised ASN.1 struct:
	//
	//	DigestInfo ::= SEQUENCE {
	//		digestAlgorithm AlgorithmIdentifier,
	//		digest OCTET STRING
	//	}
	case pkcs11.CKM_RSA_PKCS:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}

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

	case pkcs11.CKM_RSA_PKCS_PSS:
		// TODO: Support the PKCS #1 RSA PSS mechanism.
		return nil, errors.New("mechanism not available")

	// The ECDSA (without hashing) mechanism does not have a parameter.
	case pkcs11.CKM_ECDSA:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}
	default:
		return nil, errors.New("unsupported mechanism")
	}

	err = tk.module.SignInit(tk.session, mechanism, key)
	if err != nil {
		return nil, fmt.Errorf("sign init error: %s", err)
	}

	return tk.module.Sign(tk.session, digest)
}
