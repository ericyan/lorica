package procedure

import (
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Revoke revokes the certificate with unspecified (code 0) reason.
func Revoke(tk *cryptoki.Token, caFile string, serial string) error {
	ca, err := ca.Open(caFile, tk)
	if err != nil {
		return err
	}

	aki := string(ca.Certificate().SubjectKeyId)

	return ca.Revoke(serial, aki, 0)
}
