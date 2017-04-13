package lorica

import (
	"fmt"

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
func OpenToken(modulePath, tokenLabel, pin string) (*Token, error) {
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

	session, err := module.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
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
