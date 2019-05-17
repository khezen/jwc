package jwc

import (
	"crypto/rsa"
)

// https://tools.ietf.org/html/rfc7516

// JWE - json web encrypted content
type JWE struct {
	JOSEHeaders
	EncryptedKey         []byte
	InitializationVector []byte
	CipherText           []byte
	AuthenticationTag    []byte
}

// JOSEHeaders JWE header
type JOSEHeaders struct {
	Algorithm   Algorithm               `json:"alg"`
	Encryption  ContentEncryptAlgorithm `json:"enc"`
	Type        string                  `json:"typ,omitempty"`
	ContentType string                  `json:"cty,omitempty"`
	EncKeyID    JWKID                   `json:"kid,omitempty"`
}

// ParseJWE -
func ParseJWE(jwe []byte, privKey *rsa.PrivateKey) (*JWE, error) {
	return nil, nil
}
