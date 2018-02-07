package procedure

import (
	"github.com/cloudflare/cfssl/csr"
	"github.com/ericyan/lorica/internal/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
)

// Init generates a key pair and CSR for the CA. If selfSign is true, a
// self-signed certificate in PEM-encoding will be returned; otherwise,
// the PEM-encoded CSR will be returned.
func Init(tk *cryptoki.Token, cfg *ca.Config, selfSign bool) ([]byte, error) {
	req := cfg.CertificateRequest()
	key, err := tk.GenerateKeyPair(req.CN, req.KeyRequest.Algo(), req.KeyRequest.Size())
	if err != nil {
		return nil, err
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		return nil, err
	}

	if selfSign {
		ca, err := ca.New(nil, cfg, key)
		if err != nil {
			return nil, err
		}

		return ca.Sign(csrPEM)
	}

	return csrPEM, nil
}
