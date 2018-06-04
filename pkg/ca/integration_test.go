package ca_test

import (
	"crypto"
	"crypto/ecdsa"
	"io/ioutil"
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

func initCA(configFile string, kp ca.KeyProvider) (string, error) {
	config, err := ioutil.ReadFile(configFile)
	if err != nil {
		return "", err
	}

	cfg, err := ca.LoadConfig(config)
	if err != nil {
		return "", err
	}

	_, err = ca.Init(cfg, kp)
	if err != nil {
		return "", err
	}

	return cfg.CAFile, nil
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

	caFile, err := initCA("testdata/root_ca.json", kp)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caFile)

	rootCA, err := ca.Open(caFile, kp)
	if err != nil {
		t.Fatal(err)
	}

	caPub, err := rootCA.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	kpKey, _ := kp.FindKeyPair(caPub)

	a := caPub.(*ecdsa.PublicKey)
	b := kpKey.Public().(*ecdsa.PublicKey)
	if a.Curve.Params().Name != b.Curve.Params().Name || a.X.String() != b.X.String() || a.Y.String() != b.Y.String() {
		t.Fatal("ca public key mismatch")
	}
}

func TestSubordinateCA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	keyPEM, err := helpers.ReadBytes("testdata/prime256v1.key")
	if err != nil {
		t.Fatal(err)
	}
	kp := &fakeKeyProvider{keyPEM}

	rootCAFile, err := initCA("testdata/root_ca.json", kp)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(rootCAFile)

	subCAFile, err := initCA("testdata/subordinate_ca.json", kp)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(subCAFile)

	rootCA, err := ca.Open(rootCAFile, kp)
	if err != nil {
		t.Fatal(err)
	}

	subCA, err := ca.Open(subCAFile, kp)
	if err != nil {
		t.Fatal(err)
	}

	subCSR, err := subCA.CertificateRequestPEM()
	if err != nil {
		t.Fatal(err)
	}

	subCertPEM, err := rootCA.Issue(subCSR)
	if err != nil {
		t.Fatal(err)
	}

	err = subCA.ImportCertificate(subCertPEM)
	if err != nil {
		t.Fatal(err)
	}

	subCert, err := subCA.Certificate()
	if err != nil {
		t.Fatal(err)
	}

	rootCert, err := rootCA.Certificate()
	if err != nil {
		t.Fatal(err)
	}

	if subCert.Issuer.String() != rootCert.Subject.String() {
		t.Error("subordinate ca cert not issued by root ca")
	}
}
