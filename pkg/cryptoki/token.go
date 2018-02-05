package cryptoki

import (
	"crypto"
	"errors"
	"fmt"
	"hash/crc64"

	"github.com/miekg/pkcs11"
)

// A Token represents a cryptographic token that implements PKCS #11.
type Token struct {
	module *pkcs11.Ctx
	slotID uint

	session pkcs11.SessionHandle
}

// findSlot retrieves ID of the slot with matching token label.
func findSlot(module *pkcs11.Ctx, tokenLabel string) (slotID uint, err error) {
	slots, err := module.GetSlotList(true)
	if err != nil {
		return slotID, fmt.Errorf("failed to get slot list: %s", err)
	}

	for _, id := range slots {
		tokenInfo, err := module.GetTokenInfo(id)
		if err != nil {
			return slotID, fmt.Errorf("failed to get token info: %s", err)
		}

		if tokenInfo.Label == tokenLabel {
			return id, nil
		}
	}

	return slotID, fmt.Errorf("no slot with token label '%q'", tokenLabel)
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

	return &Token{module, slotID, session}, nil
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
func (tk *Token) GenerateKeyPair(label string, kr KeyRequest) (*KeyPair, error) {
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

	var req keyRequest
	switch kr.Algo() {
	case "rsa":
		req = NewRSAKeyRequest(kr.Size()).(*rsaKeyRequest)
	case "ecdsa":
		req = NewECKeyRequest(kr.Size()).(*ecdsaKeyRequest)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", kr.Algo())
	}

	attrs, err := req.Attrs()
	if err != nil {
		return nil, err
	}
	publicKeyTemplate = append(publicKeyTemplate, attrs...)

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

	pubHandle, privHandle, err := tk.module.GenerateKeyPair(tk.session, req.Mechanisms(), publicKeyTemplate, privateKeyTemplate)
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
func (tk *Token) FindKeyPair(pub crypto.PublicKey) (*KeyPair, error) {
	// First, looks up the given public key in the token, and returns get
	// its object handle if found.
	kp, err := parseKeyParams(pub)
	if err != nil {
		return nil, err
	}

	pubHandle, err := tk.FindObject(kp.Attrs())
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

// ExportPublicKey retrieves the public key with given object handle.
func (tk *Token) ExportPublicKey(handle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	value, err := tk.GetAttribute(handle, pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	if len(value) == 0 {
		return nil, errors.New("invalid public key object")
	}
	keyType := value[0]

	switch keyType {
	case pkcs11.CKK_RSA:
		kp := new(rsaKeyParams)
		kp.modulus, _ = tk.GetAttribute(handle, pkcs11.CKA_MODULUS)
		kp.exponent, _ = tk.GetAttribute(handle, pkcs11.CKA_PUBLIC_EXPONENT)
		return kp.Key()
	case pkcs11.CKK_EC:
		kp := new(ecdsaKeyParams)
		kp.ecParams, _ = tk.GetAttribute(handle, pkcs11.CKA_EC_PARAMS)
		kp.ecPoint, _ = tk.GetAttribute(handle, pkcs11.CKA_EC_POINT)
		return kp.Key()
	default:
		return nil, errors.New("unknown key type")
	}
}

// Sign signs msg with the private key inside the token. The caller is
// responsibile to compute the message digest.
func (tk *Token) Sign(mech uint, msg []byte, key pkcs11.ObjectHandle) ([]byte, error) {
	m := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}
	if err := tk.module.SignInit(tk.session, m, key); err != nil {
		return nil, err
	}

	return tk.module.Sign(tk.session, msg)
}

// FindObject returns the first object it found that matches the query.
func (tk *Token) FindObject(query []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	err := tk.module.FindObjectsInit(tk.session, query)
	if err != nil {
		return 0, err
	}

	result, _, err := tk.module.FindObjects(tk.session, 1)
	if err != nil {
		return 0, err
	}

	err = tk.module.FindObjectsFinal(tk.session)
	if err != nil {
		return 0, err
	}

	if len(result) == 0 {
		return 0, errors.New("object not found")
	}

	return result[0], nil
}

// GetAttribute obtains the value of a single object attribute. If there
// are multiple attributes of the same type, it only returns the value
// of the first one.
func (tk *Token) GetAttribute(obj pkcs11.ObjectHandle, typ uint) ([]byte, error) {
	attr, err := tk.module.GetAttributeValue(tk.session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(typ, nil),
	})
	if err != nil {
		return nil, err
	}

	if len(attr) == 0 {
		return nil, errors.New("attribute not found")
	}

	return attr[0].Value, nil
}
