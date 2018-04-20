package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

type KeyProvider interface {
	GenerateKeyPair(label string, algo string, size int) (crypto.Signer, error)
	FindKeyPair(key crypto.PublicKey) (crypto.Signer, error)
}

// CertificationAuthority represents a certification authority.
type CertificationAuthority struct {
	db *database

	cert   *x509.Certificate
	signer signer.Signer
}

// Init creates a CA with given config.
func Init(cfg *Config, kp KeyProvider) (*CertificationAuthority, error) {
	req := cfg.CertificateRequest()
	key, err := kp.GenerateKeyPair(req.CN, req.KeyRequest.Algo(), req.KeyRequest.Size())
	if err != nil {
		return nil, err
	}

	db, err := openDB(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		return nil, err
	}
	err = db.SetMetadata([]byte("csr"), csrPEM)
	if err != nil {
		return nil, err
	}

	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}

	ca, err := newCA(key, nil, policy, db)
	if err != nil {
		return nil, err
	}

	if cfg.SelfSign {
		certPEM, err := ca.Issue(csrPEM)
		if err != nil {
			return nil, err
		}

		err = ca.ImportCertificate(certPEM)
		if err != nil {
			return nil, err
		}
	}

	return ca, nil
}

// Open opens an existing CA.
func Open(caFile string, kp KeyProvider) (*CertificationAuthority, error) {
	db, err := openDB(caFile)
	if err != nil {
		return nil, err
	}

	certPEM, err := db.GetMetadata([]byte("cert"))
	if err != nil {
		return nil, err
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	key, err := kp.FindKeyPair(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	policyJSON, err := db.GetMetadata([]byte("policy"))
	if err != nil {
		return nil, err
	}
	var policy *config.Signing
	err = json.Unmarshal(policyJSON, policy)
	if err != nil {
		return nil, err
	}

	return newCA(key, cert, policy, db)
}

// newCA returns a new CA. If the CA does not have a certificate yet,
// set cert to nil.
func newCA(key crypto.Signer, cert *x509.Certificate, policy *config.Signing, db *database) (*CertificationAuthority, error) {
	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %s", err)
	}
	signer.SetDBAccessor(db.Accessor())

	return &CertificationAuthority{db, cert, signer}, nil
}

// Certificate returns the certificate of the CA.
func (ca *CertificationAuthority) Certificate() (*x509.Certificate, error) {
	if ca.cert == nil {
		return nil, errors.New("ca cert unavailable")
	}

	return ca.cert, nil
}

// Certificate returns the certificate of the CA in PEM encoding.
func (ca *CertificationAuthority) CertificatePEM() ([]byte, error) {
	return ca.db.GetMetadata([]byte("cert"))
}

// ImportCertificate imports the given certificate if the CA does not
// have one.
func (ca *CertificationAuthority) ImportCertificate(certPEM []byte) error {
	if ca.cert != nil {
		return errors.New("ca cert exists")
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	// TODO: Check signature and compare with original CSR.

	err = ca.db.SetMetadata([]byte("cert"), certPEM)
	if err != nil {
		return err
	}

	ca.cert = cert
	return nil
}

// CertificateRequest returns the certificate signing request of the CA.
func (ca *CertificationAuthority) CertificateRequest() (*x509.CertificateRequest, error) {
	csrPEM, err := ca.CertificateRequestPEM()
	if err != nil {
		return nil, err
	}

	return helpers.ParseCSRPEM(csrPEM)
}

// CertificateRequestPEM returns the certificate signing request of the
// CA in PEM encoding.
func (ca *CertificationAuthority) CertificateRequestPEM() ([]byte, error) {
	return ca.db.GetMetadata([]byte("csr"))
}

// KeyID returns the identifier of the signing key, which will also be
// the Authority Key Identifier (AKI) for issued certificates.
func (ca *CertificationAuthority) KeyID() []byte {
	return ca.cert.SubjectKeyId
}

// Issue signs a PEM-encoded CSR and returns the certificate in PEM.
func (ca *CertificationAuthority) Issue(csrPEM []byte) ([]byte, error) {
	var oidExtensionAuthorityKeyId = config.OID([]int{2, 5, 29, 35})

	req := signer.SignRequest{
		Request: string(csrPEM),
		Extensions: []signer.Extension{
			signer.Extension{
				ID:       oidExtensionAuthorityKeyId,
				Critical: false,
				Value:    string(ca.KeyID()),
			},
		},
	}

	return ca.signer.Sign(req)
}

// Revoke marks the certificate identified by its serial number and
// authority key identifier revoked. The reasonCode is defined in
// RFC 5280 5.3.1.
func (ca *CertificationAuthority) Revoke(serial, aki string, reasonCode int) error {
	return ca.db.Accessor().RevokeCertificate(serial, aki, reasonCode)
}

// CRL returns a DER-encoded Certificate Revocation List, signed by the CA.
func (ca *CertificationAuthority) CRL(ttl time.Duration) ([]byte, error) {
	if ca.cert == nil {
		return nil, errors.New("nil ca certificate")
	}

	certs, err := ca.db.Accessor().GetRevokedAndUnexpiredCertificates()
	if err != nil {
		return nil, err
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, certRecord := range certs {
		serialInt := new(big.Int)
		serialInt.SetString(certRecord.Serial, 10)

		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	return ca.cert.CreateCRL(rand.Reader, ca.signer, revokedCerts, time.Now(), time.Now().Add(ttl))
}
