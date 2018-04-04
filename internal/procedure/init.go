package procedure

import (
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Init generates a key pair and CSR for the CA. If selfSign is true, a
// self-signed certificate in PEM-encoding will be returned; otherwise,
// the PEM-encoded CSR will be returned.
func Init(tk *cryptoki.Token, cfg *ca.Config, selfSign bool) (*ca.CertificationAuthority, error) {
	return ca.Init(cfg, tk, selfSign)
}
