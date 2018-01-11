package cryptoki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash/crc64"

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

	var mechanism []*pkcs11.Mechanism
	switch kr.Algo() {
	case "rsa":
		var rsaAttrs []*pkcs11.Attribute
		mechanism, rsaAttrs = getRSAKeyGenAttrs(kr)

		publicKeyTemplate = append(publicKeyTemplate, rsaAttrs...)
	case "ecdsa":
		var ecdsaAttrs []*pkcs11.Attribute
		var err error
		mechanism, ecdsaAttrs, err = getECDSAKeyGenAttrs(kr)
		if err != nil {
			return nilObjectHandle, nilObjectHandle, err
		}

		publicKeyTemplate = append(publicKeyTemplate, ecdsaAttrs...)
	default:
		return nilObjectHandle, nilObjectHandle, fmt.Errorf("unsupported algorithm: %s", kr.Algo())
	}

	return tk.module.GenerateKeyPair(tk.session, mechanism, publicKeyTemplate, privateKeyTemplate)
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

// findObject finds an object in the token matching a template. An error
// will be returned if there is not exactly one result, or if there was
// an error during the find calls.
func (tk *Token) findObject(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	err := tk.module.FindObjectsInit(tk.session, template)
	if err != nil {
		return 0, err
	}

	objects, moreAvailable, err := tk.module.FindObjects(tk.session, 1)
	if err != nil {
		return 0, err
	}
	if moreAvailable {
		return 0, errors.New("more than one object found")
	}

	err = tk.module.FindObjectsFinal(tk.session)
	if err != nil {
		return 0, err
	}
	if len(objects) == 0 {
		return 0, errors.New("no objects found")
	}

	return objects[0], nil
}

// findPublicKey looks up the given public key in the token, and returns
// its object handle.
func (tk *Token) findPublicKey(pub crypto.PublicKey) (pkcs11.ObjectHandle, error) {
	var template []*pkcs11.Attribute
	switch key := pub.(type) {
	case *rsa.PublicKey:
		template = getRSAPublicKeyTemplate(key)
	case *ecdsa.PublicKey:
		var err error
		template, err = getECPublicKeyTemplate(key)
		if err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unsupported public key of type %T", pub)
	}

	return tk.findObject(template)
}

// findPrivateKey looks up the private key with matching CKA_ID of the
// given public key handle.
func (tk *Token) findPrivateKey(pubHandle pkcs11.ObjectHandle) (pkcs11.ObjectHandle, error) {
	attrs, err := tk.module.GetAttributeValue(tk.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return 0, err
	}
	if len(attrs) == 0 || attrs[0].Type != pkcs11.CKA_ID {
		return 0, errors.New("invalid attribute value")
	}
	publicKeyID := attrs[0].Value

	return tk.findObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publicKeyID),
	})
}
