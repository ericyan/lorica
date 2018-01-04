package ca

import (
	"io/ioutil"
	"reflect"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	conf, err := ioutil.ReadFile("testdata/root_ca.json")
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(conf)
	if err != nil {
		t.Fatal(err)
	}

	req := cfg.CertificateRequest()
	if req.Name().CommonName != cfg.CN {
		t.Errorf("unexpected common name: got %s, want %s", req.Name().CommonName, cfg.CN)
	}
	if req.Name().Locality[0] != cfg.Name.L {
		t.Errorf("unexpected locality: got %s, want %s", req.Name().Locality[0], cfg.Name.L)
	}
	if req.KeyRequest.Algo() != DefaultConfig.KeyRequest.A {
		t.Errorf("unexpected key request algo: got %s, want %s", req.KeyRequest.Algo(), DefaultConfig.KeyRequest.A)
	}
	if req.KeyRequest.Size() != DefaultConfig.KeyRequest.S {
		t.Errorf("unexpected key request size: got %d, want %d", req.KeyRequest.Size(), DefaultConfig.KeyRequest.S)
	}

	policy, err := cfg.Signing()
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Valid() {
		t.Errorf("signing policy is invalid")
	}
	if !reflect.DeepEqual(policy.Default.Usage, DefaultConfig.Usage) {
		t.Errorf("unexpected usage: got %v, ant %v", policy.Default.Usage, DefaultConfig.Usage)
	}
	if expectedExpiry := 87600 * time.Hour; policy.Default.Expiry != expectedExpiry {
		t.Errorf("unexpected expiry: got %s, ant %s", policy.Default.Expiry, expectedExpiry)
	}
	if !policy.Default.CAConstraint.IsCA {
		t.Errorf("unexpected ca constraint: got %t, ant %t", false, true)
	}
}
