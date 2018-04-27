package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
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
	kp KeyProvider

	signer *local.Signer
}

// Init creates a CA with given config.
func Init(cfg *Config, kp KeyProvider) (*CertificationAuthority, error) {
	db, err := openDB(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	ca := &CertificationAuthority{db, kp, nil}

	csrPEM, err := ca.generateCertificateRequestPEM(cfg.CertificateRequest())
	if err != nil {
		return nil, err
	}

	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}
	err = ca.SetPolicy(policy)
	if err != nil {
		return nil, err
	}

	if cfg.SelfSign {
		err = ca.initSigner(nil)
		if err != nil {
			return nil, err
		}

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
	ca := &CertificationAuthority{db, kp, nil}

	cert, err := ca.Certificate()
	if err != nil {
		return nil, err
	}
	err = ca.initSigner(cert)
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// initSigner initializes a new signer for the CA. If the CA does not
// have a certificate yet, set cert to nil.
func (ca *CertificationAuthority) initSigner(cert *x509.Certificate) error {
	var pub crypto.PublicKey
	if cert != nil {
		pub = cert.PublicKey
	} else {
		var err error
		pub, err = ca.PublicKey()
		if err != nil {
			return err
		}
	}

	key, err := ca.kp.FindKeyPair(pub)
	if err != nil {
		return err
	}

	policy, err := ca.Policy()
	if err != nil {
		return err
	}

	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return err
	}

	signer.SetDBAccessor(ca.db.Accessor())

	ca.signer = signer
	return nil
}

// Certificate returns the certificate of the CA.
func (ca *CertificationAuthority) Certificate() (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, errors.New("signer not initialized")
	}

	return ca.signer.Certificate("", "default")
}

// Certificate returns the certificate of the CA in PEM encoding.
func (ca *CertificationAuthority) CertificatePEM() ([]byte, error) {
	return ca.db.GetMetadata([]byte("cert"))
}

// ImportCertificate imports the given certificate if the CA does not
// have one.
func (ca *CertificationAuthority) ImportCertificate(certPEM []byte) error {
	if cert, _ := ca.Certificate(); cert != nil {
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

	return ca.initSigner(cert)
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

// generateCertificateRequestPEM creates a certificate signing request
// for the CA.
func (ca *CertificationAuthority) generateCertificateRequestPEM(req *csr.CertificateRequest) ([]byte, error) {
	if csrPEM, _ := ca.CertificateRequestPEM(); csrPEM != nil {
		return nil, errors.New("ca csr exists")
	}

	key, err := ca.kp.GenerateKeyPair(req.CN, req.KeyRequest.Algo(), req.KeyRequest.Size())
	if err != nil {
		return nil, err
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		return nil, err
	}
	err = ca.db.SetMetadata([]byte("csr"), csrPEM)
	if err != nil {
		return nil, err
	}

	return csrPEM, nil
}

// PublicKey returns the public key from the CA certificate or CSR.
func (ca *CertificationAuthority) PublicKey() (crypto.PublicKey, error) {
	if cert, _ := ca.Certificate(); cert != nil {
		return cert.PublicKey, nil
	}

	if csr, _ := ca.CertificateRequest(); csr != nil {
		return csr.PublicKey, nil
	}

	return nil, errors.New("no valid csr in db")
}

// KeyID returns the identifier of the signing key, which will also be
// the Authority Key Identifier (AKI) for issued certificates.
func (ca *CertificationAuthority) KeyID() []byte {
	cert, err := ca.Certificate()
	if err != nil {
		return nil
	}

	return cert.SubjectKeyId
}

// Policy returns the signing policy of the CA.
func (ca *CertificationAuthority) Policy() (*config.Signing, error) {
	if ca.signer != nil {
		return ca.signer.Policy(), nil
	}

	policyJSON, err := ca.db.GetMetadata([]byte("policy"))
	if err != nil {
		return nil, err
	}
	var policy *config.Signing
	err = json.Unmarshal(policyJSON, policy)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// SetPolicy sets the signing policy of the CA.
func (ca *CertificationAuthority) SetPolicy(policy *config.Signing) error {
	if !policy.Valid() {
		return errors.New("invalid policy")
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	err = ca.db.SetMetadata([]byte("policy"), policyJSON)
	if err != nil {
		return err
	}

	if ca.signer != nil {
		ca.signer.SetPolicy(policy)
	}

	return nil
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
	cert, err := ca.Certificate()
	if err != nil {
		return nil, err
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

	return cert.CreateCRL(rand.Reader, ca.signer, revokedCerts, time.Now(), time.Now().Add(ttl))
}
