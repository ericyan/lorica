package mock

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/exec"
)

type HSM struct {
	ModulePath, TokenLabel, PIN, SOPIN, WorkingDir string
}

func NewHSM() (*HSM, error) {
	dir, err := ioutil.TempDir("", "softhsm2")
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(dir+"/softhsm2.conf", []byte("directories.tokendir = "+dir), 0600)
	if err != nil {
		return nil, err
	}

	hsm := &HSM{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "lorica_test",
		PIN:        "123456",
		SOPIN:      "lorica",
		WorkingDir: dir,
	}

	err = hsm.initToken()
	if err != nil {
		hsm.Destroy()
		return nil, err
	}

	return hsm, nil
}

func (hsm *HSM) exec(args ...string) error {
	cmd := exec.Command("softhsm2-util", args...)
	cmd.Env = []string{"SOFTHSM2_CONF=" + hsm.WorkingDir + "/softhsm2.conf"}

	return cmd.Run()
}

func (hsm *HSM) initToken() error {
	return hsm.exec("--init-token", "--free", "--label", hsm.TokenLabel, "--so-pin", hsm.SOPIN, "--pin", hsm.PIN)
}

func (hsm *HSM) Import(key, label string) error {
	id := hex.EncodeToString([]byte(label))

	return hsm.exec("--import", key, "--token", hsm.TokenLabel, "--pin", hsm.PIN, "--label", label, "--id", id)
}

func (hsm *HSM) Destroy() error {
	return os.RemoveAll(hsm.WorkingDir)
}
