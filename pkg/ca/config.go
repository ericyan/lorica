package ca

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
)

// Config stores configuration information for the CA.
type Config struct {
	CN         string
	Name       csr.Name             `json:"name"`
	KeyRequest *csr.BasicKeyRequest `json:"key"`

	Usage             []string            `json:"usages"`
	CRL               string              `json:"crl_url"`
	ExpiryString      string              `json:"expiry"`
	CAConstraint      config.CAConstraint `json:"ca_constraint"`
	AllowedExtensions []config.OID        `json:"allowed_extensions"`

	SelfSign bool `json:"self_sign"`
}

// DefaultConfig defines the default configuration for a CA.
var DefaultConfig = &Config{
	KeyRequest:   &csr.BasicKeyRequest{"rsa", 4096},
	Usage:        []string{"cert sign", "crl sign"},
	ExpiryString: "43800h",
}

// LoadConfig attempts to load the configuration from a byte slice. On
// error, it returns nil.
func LoadConfig(data []byte) (*Config, error) {
	var cfg = &Config{}
	err := json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %s", err.Error())
	}

	if cfg.CN == "" {
		return nil, errors.New("empty common name in CA config")
	}
	if cfg.KeyRequest == nil {
		cfg.KeyRequest = DefaultConfig.KeyRequest
	}
	if len(cfg.Usage) == 0 {
		cfg.Usage = DefaultConfig.Usage
	}
	if cfg.ExpiryString == "" {
		cfg.ExpiryString = DefaultConfig.ExpiryString
	}

	return cfg, nil
}

// Signing returns a CFSSL signing policy derived from the Config.
func (cfg *Config) Signing() (*config.Signing, error) {
	if cfg.SelfSign {
		cfg.CAConstraint.IsCA = true
		cfg.AllowedExtensions = append(cfg.AllowedExtensions, config.OID([]int{2, 5, 29, 35}))
	}

	cfsslConfig := &config.Config{
		Signing: &config.Signing{
			Default: &config.SigningProfile{
				Usage:             cfg.Usage,
				ExpiryString:      cfg.ExpiryString,
				CAConstraint:      cfg.CAConstraint,
				AllowedExtensions: cfg.AllowedExtensions,
			},
		},
	}

	// CFSSL config.LoadConfig will call the private function populate()
	// for each signing profile.
	buf, err := json.Marshal(cfsslConfig)
	if err != nil {
		return nil, err
	}
	cfsslConfig, err = config.LoadConfig(buf)
	if err != nil {
		return nil, err
	}

	return cfsslConfig.Signing, nil
}

// CertificateRequest returns a CFSSL certificate request for the CA.
func (cfg *Config) CertificateRequest() *csr.CertificateRequest {
	return &csr.CertificateRequest{
		CN:         cfg.CN,
		Names:      []csr.Name{cfg.Name},
		KeyRequest: cfg.KeyRequest,
	}
}
