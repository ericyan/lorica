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
	pin    string

	roSession *pkcs11.SessionHandle
	rwSession *pkcs11.SessionHandle
}

// OpenToken opens a new session with the given cryptographic token.
func OpenToken(modulePath, tokenLabel, pin string) (*Token, error) {
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, fmt.Errorf("failed to load module '%s'", modulePath)
	}

	err := module.Initialize()
	if err != nil {
		return nil, err
	}

	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %s", err)
	}

	var slotID uint
	for _, id := range slots {
		tokenInfo, err := module.GetTokenInfo(id)
		if err != nil {
			return nil, fmt.Errorf("failed to get token info: %s", err)
		}

		if tokenInfo.Label == tokenLabel {
			slotID = id
			break
		}
	}

	return &Token{module, slotID, pin, nil, nil}, nil
}

// openSession opens a new session and logs in with the PIN.
func (tk *Token) openSession(readOnly bool) (pkcs11.SessionHandle, error) {
	var flags uint
	if readOnly {
		flags = pkcs11.CKF_SERIAL_SESSION
	} else {
		flags = pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION
	}

	sh, err := tk.module.OpenSession(tk.slotID, flags)
	if err != nil {
		return 0, err
	}

	// Login status is application-wide, not per session. It is fine if
	// user already logged in.
	err = tk.module.Login(sh, pkcs11.CKU_USER, tk.pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		tk.module.CloseSession(sh)
		return 0, err
	}

	return sh, nil
}

// GetSession returns a writable session with the token.
func (tk *Token) GetSession() (pkcs11.SessionHandle, error) {
	if tk.rwSession == nil {
		sh, err := tk.openSession(false)
		if err != nil {
			return 0, err
		}

		tk.rwSession = &sh
	}

	return *tk.rwSession, nil
}

// GetReadOnlySession returns a read-only session with the token.
func (tk *Token) GetReadOnlySession() (pkcs11.SessionHandle, error) {
	if tk.roSession == nil {
		sh, err := tk.openSession(true)
		if err != nil {
			return 0, err
		}

		tk.roSession = &sh
	}

	return *tk.roSession, nil
}

// Close closes all sessions with the token.
func (tk *Token) Close() error {
	return tk.module.CloseAllSessions(tk.slotID)
}

// Info obtains information about the token.
func (tk *Token) Info() (pkcs11.TokenInfo, error) {
	return tk.module.GetTokenInfo(tk.slotID)
}

// FindObject returns the first object it found that matches the query.
func (tk *Token) FindObject(query []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	sh, err := tk.GetReadOnlySession()
	if err != nil {
		return 0, err
	}

	err = tk.module.FindObjectsInit(sh, query)
	if err != nil {
		return 0, err
	}

	result, _, err := tk.module.FindObjects(sh, 1)
	if err != nil {
		return 0, err
	}

	err = tk.module.FindObjectsFinal(sh)
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
	sh, err := tk.GetReadOnlySession()
	if err != nil {
		return nil, err
	}

	attr, err := tk.module.GetAttributeValue(sh, obj, []*pkcs11.Attribute{
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

// GetUintAttribute returns the value of a single object attribute as uint.
func (tk *Token) GetUintAttribute(obj pkcs11.ObjectHandle, typ uint) (uint, error) {
	value, err := tk.GetAttribute(obj, typ)
	if err != nil {
		return 0, err
	}

	if len(value) == 0 {
		return 0, errors.New("empty attribute")
	}
	return uint(value[0]), nil
}

// ExportPublicKey returns the public key object as crypto.PublicKey.
func (tk *Token) ExportPublicKey(pub pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	keyType, err := tk.GetUintAttribute(pub, pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		key := new(rsaPublicKey)
		key.modulus, _ = tk.GetAttribute(pub, pkcs11.CKA_MODULUS)
		key.publicExponent, _ = tk.GetAttribute(pub, pkcs11.CKA_PUBLIC_EXPONENT)
		return key.CryptoKey()
	case pkcs11.CKK_EC:
		key := new(ecdsaPublicKey)
		key.ecParams, _ = tk.GetAttribute(pub, pkcs11.CKA_EC_PARAMS)
		key.ecPoint, _ = tk.GetAttribute(pub, pkcs11.CKA_EC_POINT)
		return key.CryptoKey()
	default:
		return nil, errors.New("unknown key type")
	}
}

// Sign signs msg the with the private key using designated mechanism.
func (tk *Token) Sign(msg []byte, priv pkcs11.ObjectHandle, mech uint) ([]byte, error) {
	sh, err := tk.GetSession()
	if err != nil {
		return nil, err
	}

	m := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}
	if err := tk.module.SignInit(sh, m, priv); err != nil {
		return nil, err
	}

	return tk.module.Sign(sh, msg)
}
