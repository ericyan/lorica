package cryptoki

import (
	"testing"

	"github.com/ericyan/lorica/internal/mock"
)

func TestToken(t *testing.T) {
	hsm, err := mock.NewHSM()
	if err != nil {
		t.Fatal(err)
	}
	defer hsm.Destroy()

	tk, err := OpenToken(hsm.ModulePath, hsm.TokenLabel, hsm.PIN)
	if err != nil {
		t.Error(err)
	}

	info, err := tk.Info()
	if err != nil {
		t.Error(err)
	}

	if info.Model != "SoftHSM v2" {
		t.Errorf("unexpected token model: %s", info.Model)
	}
}
