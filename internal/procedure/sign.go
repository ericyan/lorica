package procedure

import (
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Sign finds the key pair with the public key in the CA certificate and
// then signs the CSR with that key. The CA certificate, CSR as well as
// the resulting certificate are PEM-encoded.
func Sign(tk *cryptoki.Token, caFile string, csrPEM []byte) ([]byte, error) {
	ca, err := ca.Open(caFile, tk)
	if err != nil {
		return nil, err
	}

	return ca.Issue(csrPEM)
}
