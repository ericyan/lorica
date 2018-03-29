package procedure

import (
	"github.com/cloudflare/cfssl/helpers"
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Revoke revokes the certificate with unspecified (code 0) reason.
func Revoke(tk *cryptoki.Token, cfg *ca.Config, caPEM []byte, serial string) error {
	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		return err
	}

	key, err := tk.FindKeyPair(caCert.PublicKey)
	if err != nil {
		return err
	}

	ca, err := ca.New(caCert, cfg, key)
	if err != nil {
		return err
	}

	aki := string(caCert.SubjectKeyId)

	return ca.Revoke(serial, aki, 0)
}
