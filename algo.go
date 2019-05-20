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

// ContentEncryptAlgorithm -
type ContentEncryptAlgorithm string

var (
	// ErrUnsupportedAlgorithm -
	ErrUnsupportedAlgorithm = errors.New("ErrUnsupportedAlgorithm")
	// ErrUnsupportedEncryption -
	ErrUnsupportedEncryption = errors.New("ErrUnsupportedEncryption")
)

const (
	// A128CBCHS256 - A128CBC-HS256
	A128CBCHS256 ContentEncryptAlgorithm = "A128CBC-HS256"
	// A192CBCHS384 - A192CBC-HS384
	A192CBCHS384 ContentEncryptAlgorithm = "A192CBC-HS384"
	// A256CBCHS512 - A256CBC-HS512
	A256CBCHS512 ContentEncryptAlgorithm = "A256CBC-HS512"
	// A128GCM - A128GCM
	A128GCM ContentEncryptAlgorithm = "A128GCM"
	// A256GCM - A256GCM
	A256GCM ContentEncryptAlgorithm = "A256GCM"
	// A512GCM - A512GCM
	// A512GCM ContentEncryptAlgorithm = "A512GCM"
)
