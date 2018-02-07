package cryptoki

import (
	"crypto"
	"errors"
	"fmt"

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
	return tk.module.GetTokenInfo(tk.slotID)
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
		key := new(rsaPublicKey)
		key.modulus, _ = tk.GetAttribute(handle, pkcs11.CKA_MODULUS)
		key.publicExponent, _ = tk.GetAttribute(handle, pkcs11.CKA_PUBLIC_EXPONENT)
		return key.CryptoKey()
	case pkcs11.CKK_EC:
		key := new(ecdsaPublicKey)
		key.ecParams, _ = tk.GetAttribute(handle, pkcs11.CKA_EC_PARAMS)
		key.ecPoint, _ = tk.GetAttribute(handle, pkcs11.CKA_EC_POINT)
		return key.CryptoKey()
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
