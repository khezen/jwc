package jwc

import "errors"

// Algorithm -
type Algorithm string

// Usage -
type Usage string

const (
	// Signing - JWK is intended to be used for signature
	Signing Usage = "sig"
	// RS256 - RSASSA-PKCS1-v1_5 + SHA256
	RS256 Algorithm = "RS256"
	// PS256 - RSASSA-PSS + SHA256
	PS256 Algorithm = "PS256"
)

const (
	// Encryption - JWK is intended to be used for encryption
	Encryption Usage = "enc"
	// ROAEP - RSAES OAEP
	ROAEP Algorithm = "RSA-OAEP"
	// RSA15 - RSAES-PKCS1-v1_5
	RSA15 Algorithm = "RSA1_5"
)

var (
	// ErrUnsupportedAlgorithm -
	ErrUnsupportedAlgorithm = errors.New("ErrUnsupportedAlgorithm")
)
