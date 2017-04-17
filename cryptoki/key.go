package cryptoki

// A KeyRequest is a generic request for a new key pair.
type KeyRequest interface {
	Algo() string
	Size() int
}

// A keyRequest contains the algorithm and key size for a new key pair.
type keyRequest struct {
	algo string
	size int
}

// Algo returns the requested key algorithm represented as a string.
func (kr *keyRequest) Algo() string {
	return kr.algo
}

// Size returns the requested key size.
func (kr *keyRequest) Size() int {
	return kr.size
}

// NewRSAKeyRequest returns a 2048-bit RSA key request.
func NewRSAKeyRequest() KeyRequest {
	return &keyRequest{"rsa", 2048}
}

// NewECKeyRequest returns a prime256v1 EC(DSA) key request.
func NewECKeyRequest() KeyRequest {
	return &keyRequest{"ecdsa", 256}
}
