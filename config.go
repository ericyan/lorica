package lorica

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// Config stores configuration information for the CA.
type Config struct {
	Profile *config.SigningProfile `json:"profile"`
}

// DefaultProfile defines the default signing profile for a root CA.
var DefaultProfile = &config.SigningProfile{
	Usage:        []string{"cert sign", "crl sign"},
	ExpiryString: "43800h",
	Expiry:       5 * helpers.OneYear,
	CAConstraint: config.CAConstraint{IsCA: true},
}

// LoadConfigFile attempts to load the configuration file at given path
// and returns the parsed configuration information.
func LoadConfigFile(path string) (*Config, error) {
	log.Debugf("loading configuration file from %s", path)
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("unable to read configuration file")
	}

	var cfg = &Config{}
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %s", err.Error())
	}

	if cfg.Profile == nil {
		log.Warning("no profile given: using default profile")
		cfg.Profile = DefaultProfile
	}
	if cfg.Profile.AuthKeyName != "" {
		log.Warning("ignored unsupported field: auth_key")
		cfg.Profile.AuthKeyName = ""
	}
	if cfg.Profile.RemoteName != "" {
		log.Warning("ignored unsupported field: remote")
		cfg.Profile.RemoteName = ""
	}
	if cfg.Profile.AuthRemote.RemoteName != "" || cfg.Profile.AuthRemote.AuthKeyName != "" {
		log.Warning("ignored unsupported field: auth_remote")
		cfg.Profile.AuthRemote.RemoteName = ""
		cfg.Profile.AuthRemote.AuthKeyName = ""
	}
	if err := populateProfile(cfg.Profile); err != nil {
		return nil, err
	}

	p := &config.Signing{Default: cfg.Profile}
	if !p.Valid() {
		return nil, errors.New("invalid configuration")
	}

	log.Debugf("configuration loaded successfully")
	return cfg, nil
}

// populateProfile fills in profile fields that are not in JSON.
func populateProfile(p *config.SigningProfile) error {
	log.Debugf("parse expiry in profile")
	if p.ExpiryString == "" {
		return errors.New("empty expiry string")
	}

	dur, err := time.ParseDuration(p.ExpiryString)
	if err != nil {
		return err
	}

	log.Debugf("expiry is valid")
	p.Expiry = dur

	if p.BackdateString != "" {
		dur, err = time.ParseDuration(p.BackdateString)
		if err != nil {
			return err
		}

		p.Backdate = dur
	}

	if !p.NotBefore.IsZero() && !p.NotAfter.IsZero() && p.NotAfter.Before(p.NotBefore) {
		return err
	}

	if len(p.Policies) > 0 {
		for _, policy := range p.Policies {
			for _, qualifier := range policy.Qualifiers {
				if qualifier.Type != "" && qualifier.Type != "id-qt-unotice" && qualifier.Type != "id-qt-cps" {
					return errors.New("invalid policy qualifier type")
				}
			}
		}
	}

	if p.NameWhitelistString != "" {
		log.Debug("compiling whitelist regular expression")
		rule, err := regexp.Compile(p.NameWhitelistString)
		if err != nil {
			return errors.New("failed to compile name whitelist section")
		}
		p.NameWhitelist = rule
	}

	p.ExtensionWhitelist = map[string]bool{}
	for _, oid := range p.AllowedExtensions {
		p.ExtensionWhitelist[asn1.ObjectIdentifier(oid).String()] = true
	}

	return nil
}
