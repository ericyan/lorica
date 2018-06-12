package ca_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ericyan/lorica/internal/mock"
	"github.com/ericyan/lorica/pkg/ca"
)

var kp = mock.NewKeyProvider("testdata/")

func initCA(configFile, caFile string) (*ca.CertificationAuthority, error) {
	config, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	cfg, err := ca.LoadConfig(config)
	if err != nil {
		return nil, err
	}

	return ca.Init(cfg, caFile, kp)
}

func TestRootCA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f, err := ioutil.TempFile("", "lorica_test.*.ca")
	if err != nil {
		t.Fatal(err)
	}
	caFile := f.Name()

	_, err = initCA("testdata/root_ca.json", caFile)
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

	a := caPub.(*rsa.PublicKey)
	b := kpKey.Public().(*rsa.PublicKey)
	if a.N.String() != b.N.String() || a.E != b.E {
		t.Fatal("ca public key mismatch")
	}
}

func TestSubordinateCA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f1, err := ioutil.TempFile("", "lorica_test.*.ca")
	if err != nil {
		t.Fatal(err)
	}
	rootCAFile := f1.Name()

	f2, err := ioutil.TempFile("", "lorica_test.*.ca")
	if err != nil {
		t.Fatal(err)
	}
	subCAFile := f2.Name()

	_, err = initCA("testdata/root_ca.json", rootCAFile)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(rootCAFile)

	_, err = initCA("testdata/subordinate_ca.json", subCAFile)
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

	caPub, err := subCA.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	kpKey, _ := kp.FindKeyPair(caPub)

	a := caPub.(*ecdsa.PublicKey)
	b := kpKey.Public().(*ecdsa.PublicKey)
	if a.Curve.Params().Name != b.Curve.Params().Name || a.X.String() != b.X.String() || a.Y.String() != b.Y.String() {
		t.Fatal("ca public key mismatch")
	}

	if subCert.Issuer.String() != rootCert.Subject.String() {
		t.Error("subordinate ca cert not issued by root ca")
	}
}
