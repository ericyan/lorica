package ca

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/config"
)

// Config stores configuration information for the CA.
type Config struct {
	Usage        []string            `json:"usages"`
	ExpiryString string              `json:"expiry"`
	CAConstraint config.CAConstraint `json:"ca_constraint"`
}

// DefaultConfig defines the default configuration for a CA.
var DefaultConfig = &Config{
	Usage:        []string{"cert sign", "crl sign"},
	ExpiryString: "43800h",
	CAConstraint: config.CAConstraint{IsCA: true},
}

// LoadConfig attempts to load the configuration from a byte slice. On
// error, it returns nil.
func LoadConfig(data []byte) (*Config, error) {
	var cfg = &Config{}
	err := json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %s", err.Error())
	}

	if len(cfg.Usage) > 0 {
		cfg.Usage = DefaultConfig.Usage
	}
	if cfg.ExpiryString == "" {
		cfg.ExpiryString = DefaultConfig.ExpiryString
	}

	return cfg, nil
}

// Signing returns a CFSSL signing policy derived from the Config.
func (cfg *Config) Signing() (*config.Signing, error) {
	cfsslConfig := &config.Config{
		Signing: &config.Signing{
			Default: &config.SigningProfile{
				Usage:        cfg.Usage,
				ExpiryString: cfg.ExpiryString,
				CAConstraint: cfg.CAConstraint,
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
