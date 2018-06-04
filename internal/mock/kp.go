package mock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
)

type KeyProvider struct {
	KeyDir string
}

func NewKeyProvider(dir string) *KeyProvider {
	return &KeyProvider{strings.TrimSuffix(dir, "/")}
}

func (kp *KeyProvider) findKeyPair(algo string, size int) (crypto.Signer, error) {
	keyPEM, err := helpers.ReadBytes(kp.KeyDir + "/" + algo + "_" + strconv.Itoa(size) + ".key")
	if err != nil {
		return nil, err
	}

	return helpers.ParsePrivateKeyPEM(keyPEM)
}

func (kp *KeyProvider) GenerateKeyPair(label string, algo string, size int) (crypto.Signer, error) {
	return kp.findKeyPair(algo, size)
}

func (kp *KeyProvider) FindKeyPair(key crypto.PublicKey) (crypto.Signer, error) {
	var (
		algo string
		size int
	)

	switch pub := key.(type) {
	case *rsa.PublicKey:
		algo = "rsa"
		size = pub.N.BitLen()
	case *ecdsa.PublicKey:
		algo = "ecdsa"
		size = pub.Curve.Params().BitSize
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	return kp.findKeyPair(algo, size)
}
