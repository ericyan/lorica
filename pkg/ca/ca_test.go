package ca

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/cloudflare/cfssl/helpers"
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

func newFakeCA(cfg *Config) (*CertificationAuthority, error) {
	db, err := openTestingDB()
	if err != nil {
		return nil, err
	}
	keyPEM, err := helpers.ReadBytes("testdata/prime256v1.key")
	if err != nil {
		return nil, err
	}
	kp := &fakeKeyProvider{keyPEM}
	ca := &CertificationAuthority{db, kp, nil}

	if cfg != nil {
		cfg.CN = "Fake CA"

		req := cfg.CertificateRequest()
		policy, err := cfg.Signing()
		if err != nil {
			return nil, err
		}
		err = ca.init(req, policy)
		if err != nil {
			return nil, err
		}
	}

	return ca, nil
}

func TestUninitializedCA(t *testing.T) {
	ca, err := newFakeCA(nil)
	if err != nil {
		t.Fatal(err)
	}

	if cert, _ := ca.Certificate(); cert != nil {
		t.Error("non-nil certificate for uninitialized CA")
	}
	if csr, _ := ca.CertificateRequest(); csr != nil {
		t.Error("non-nil csr for uninitialized CA")
	}
	if key, _ := ca.PublicKey(); key != nil {
		t.Error("non-nil key for uninitialized CA")
	}
	if policy, _ := ca.Policy(); policy != nil {
		t.Error("non-nil policy for uninitialized CA")
	}
}

func TestUnsignedCA(t *testing.T) {
	ca, err := newFakeCA(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}

	if cert, _ := ca.Certificate(); cert != nil {
		t.Error("non-nil certificate for unsigned CA")
	}
	if csr, _ := ca.CertificateRequest(); csr == nil {
		t.Error("nil csr for unsigned CA")
	}
	if key, _ := ca.PublicKey(); key == nil {
		t.Error("nil key for unsigned CA")
	}
	if policy, _ := ca.Policy(); policy == nil {
		t.Error("nil policy for unsigned CA")
	}
}

func TestSelfSignedCA(t *testing.T) {
	cfg := DefaultConfig
	cfg.SelfSign = true

	ca, err := newFakeCA(cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = ca.selfSign()
	if err != nil {
		t.Fatal(err)
	}

	if cert, _ := ca.Certificate(); cert == nil {
		t.Error("nil certificate for self-signed CA")
	}
	if csr, _ := ca.CertificateRequest(); csr == nil {
		t.Error("nil csr for self-signed CA")
	}
	if key, _ := ca.PublicKey(); key == nil {
		t.Error("nil key for self-signed CA")
	}
	if policy, _ := ca.Policy(); policy == nil {
		t.Error("nil policy for self-signed CA")
	}

	cert, err := ca.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.String() != cert.Issuer.String() {
		t.Error("self-signed CA cert Subject not equal to Issuer")
	}
	if !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		t.Error("self-signed CA cert SKI not equal to AKI")
	}
}
