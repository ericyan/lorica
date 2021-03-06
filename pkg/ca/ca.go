package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

type StorageProvider interface {
	GetMetadata(key []byte) ([]byte, error)
	SetMetadata(key, value []byte) error
	Accessor() certdb.Accessor
}

type KeyProvider interface {
	GenerateKeyPair(label string, algo string, size int) (crypto.Signer, error)
	FindKeyPair(key crypto.PublicKey) (crypto.Signer, error)
}

// CertificationAuthority represents a certification authority.
type CertificationAuthority struct {
	sp StorageProvider
	kp KeyProvider

	signer *local.Signer
}

// Init creates a CA with given config.
func Init(cfg *Config, caFile string, kp KeyProvider) (*CertificationAuthority, error) {
	db, err := openDB(caFile)
	if err != nil {
		return nil, err
	}
	ca := &CertificationAuthority{db, kp, nil}

	req := cfg.CertificateRequest()
	policy, err := cfg.Signing()
	if err != nil {
		return nil, err
	}
	err = ca.init(req, policy)
	if err != nil {
		return nil, err
	}

	if cfg.SelfSign {
		err = ca.selfSign()
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

	err = ca.initSigner()
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// init generates a key pair and creates a certificate signing request
// for the CA.
func (ca *CertificationAuthority) init(req *csr.CertificateRequest, policy *config.Signing) error {
	if csrPEM, _ := ca.CertificateRequestPEM(); csrPEM != nil {
		return errors.New("ca csr exists")
	}

	key, err := ca.kp.GenerateKeyPair(req.CN, req.KeyRequest.Algo(), req.KeyRequest.Size())
	if err != nil {
		return err
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		return err
	}
	err = ca.sp.SetMetadata([]byte("csr"), csrPEM)
	if err != nil {
		return err
	}

	err = ca.SetPolicy(policy)
	if err != nil {
		return err
	}

	err = ca.initSigner()
	if err != nil {
		return err
	}

	return nil
}

// initSigner initializes a new signer for the CA.
func (ca *CertificationAuthority) initSigner() error {
	key, err := ca.privateKey()
	if err != nil {
		return err
	}

	cert, _ := ca.Certificate()

	policy, err := ca.Policy()
	if err != nil {
		return err
	}

	signer, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
	if err != nil {
		return err
	}

	signer.SetDBAccessor(ca.sp.Accessor())

	ca.signer = signer
	return nil
}

// Certificate returns the certificate of the CA.
func (ca *CertificationAuthority) Certificate() (*x509.Certificate, error) {
	certPEM, err := ca.CertificatePEM()
	if err != nil {
		return nil, err
	}

	return helpers.ParseCertificatePEM(certPEM)
}

// Certificate returns the certificate of the CA in PEM encoding.
func (ca *CertificationAuthority) CertificatePEM() ([]byte, error) {
	return ca.sp.GetMetadata([]byte("cert"))
}

// selfSign creates a self-signed certificate for the CA.
func (ca *CertificationAuthority) selfSign() error {
	csrPEM, err := ca.CertificateRequestPEM()
	if err != nil {
		return err
	}

	var oidExtensionAuthorityKeyId = config.OID([]int{2, 5, 29, 35})

	keyID, err := ca.KeyID()
	if err != nil {
		return err
	}

	type authKeyId struct {
		KeyIdentifier []byte `asn1:"tag:0"`
	}
	aki, err := asn1.Marshal(authKeyId{keyID})
	if err != nil {
		return err
	}

	akiExt := signer.Extension{
		ID:       oidExtensionAuthorityKeyId,
		Critical: false,
		Value:    hex.EncodeToString(aki),
	}

	certPEM, err := ca.Issue(csrPEM, akiExt)
	if err != nil {
		return err
	}

	return ca.ImportCertificate(certPEM)
}

// ImportCertificate imports the given certificate if the CA does not
// have one.
func (ca *CertificationAuthority) ImportCertificate(certPEM []byte) error {
	if cert, _ := ca.Certificate(); cert != nil {
		return errors.New("ca cert exists")
	}

	_, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}

	// TODO: Check signature and compare with original CSR.

	err = ca.sp.SetMetadata([]byte("cert"), certPEM)
	if err != nil {
		return err
	}

	return ca.initSigner()
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
	return ca.sp.GetMetadata([]byte("csr"))
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

// privateKey returns the private key as a crypto.Signer.
func (ca *CertificationAuthority) privateKey() (crypto.Signer, error) {
	pub, err := ca.PublicKey()
	if err != nil {
		return nil, err
	}

	return ca.kp.FindKeyPair(pub)
}

// KeyID returns the identifier of the signing key, which will also be
// the Authority Key Identifier (AKI) for issued certificates.
func (ca *CertificationAuthority) KeyID() ([]byte, error) {
	if cert, _ := ca.Certificate(); cert != nil {
		return cert.SubjectKeyId, nil
	}

	pub, err := ca.PublicKey()
	if err != nil {
		return nil, err
	}

	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var pubKeyInfo struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	_, err = asn1.Unmarshal(pkixPub, &pubKeyInfo)
	if err != nil {
		return nil, err
	}

	hash := sha1.New()
	hash.Write(pubKeyInfo.BitString.Bytes)
	return hash.Sum(nil), nil
}

// Policy returns the signing policy of the CA.
func (ca *CertificationAuthority) Policy() (*config.Signing, error) {
	if ca.signer != nil {
		return ca.signer.Policy(), nil
	}

	policyJSON, err := ca.sp.GetMetadata([]byte("policy"))
	if err != nil {
		return nil, err
	}
	var policy *config.Signing
	err = json.Unmarshal(policyJSON, &policy)
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
	err = ca.sp.SetMetadata([]byte("policy"), policyJSON)
	if err != nil {
		return err
	}

	if ca.signer != nil {
		ca.signer.SetPolicy(policy)
	}

	return nil
}

// Issue signs a PEM-encoded CSR and returns the certificate in PEM.
func (ca *CertificationAuthority) Issue(csrPEM []byte, exts ...signer.Extension) ([]byte, error) {
	req := signer.SignRequest{
		Request:    string(csrPEM),
		Extensions: exts,
	}

	return ca.signer.Sign(req)
}

// Revoke marks the certificate identified by its serial number revoked.
// The reasonCode is defined in RFC 5280 5.3.1.
func (ca *CertificationAuthority) Revoke(serial string, reasonCode int) error {
	keyID, err := ca.KeyID()
	if err != nil {
		return err
	}
	aki := hex.EncodeToString(keyID)

	return ca.sp.Accessor().RevokeCertificate(serial, aki, reasonCode)
}

// CRL returns a DER-encoded Certificate Revocation List, signed by the CA.
func (ca *CertificationAuthority) CRL(ttl time.Duration) ([]byte, error) {
	certs, err := ca.sp.Accessor().GetRevokedAndUnexpiredCertificates()
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

	cert, err := ca.Certificate()
	if err != nil {
		return nil, err
	}

	key, err := ca.privateKey()
	if err != nil {
		return nil, err
	}

	return cert.CreateCRL(rand.Reader, key, revokedCerts, time.Now(), time.Now().Add(ttl))
}
