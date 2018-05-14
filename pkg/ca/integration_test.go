package ca_test

import (
	"crypto"
	"crypto/ecdsa"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/ericyan/lorica/pkg/ca"
)

type fakeKeyProvider struct {
	keyPEM []byte
}

func (kp *fakeKeyProvider) GenerateKeyPair(label string, algo string, size int) (crypto.Signer, error) {
	return helpers.ParsePrivateKeyPEM(kp.keyPEM)
}

func (kp *fakeKeyProvider) FindKeyPair(key crypto.PublicKey) (crypto.Signer, error) {
	return helpers.ParsePrivateKeyPEM(kp.keyPEM)
}

func TestRootCA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	keyPEM, err := helpers.ReadBytes("testdata/prime256v1.key")
	if err != nil {
		t.Fatal(err)
	}
	kp := &fakeKeyProvider{keyPEM}

	config, err := ioutil.ReadFile("testdata/root_ca.json")
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := ca.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ca.Init(cfg, kp)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(cfg.CAFile)

	rootCA, err := ca.Open(cfg.CAFile, kp)
	if err != nil {
		log.Fatal(err)
	}

	caPub, err := rootCA.PublicKey()
	if err != nil {
		log.Fatal(err)
	}
	kpKey, _ := kp.FindKeyPair(caPub)

	a := caPub.(*ecdsa.PublicKey)
	b := kpKey.Public().(*ecdsa.PublicKey)
	if a.Curve.Params().Name != b.Curve.Params().Name || a.X.String() != b.X.String() || a.Y.String() != b.Y.String() {
		log.Fatal("ca public key mismatch")
	}
}
