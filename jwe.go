package jwc

import "errors"

var (
	// ErrJWEUnparsable -
	ErrJWEUnparsable = errors.New("ErrJWEUnparsable")
)

// https://tools.ietf.org/html/rfc7516

// JOSEHeaders JWE header
type JOSEHeaders struct {
	Algorithm   Algorithm               `json:"alg"`
	Encryption  ContentEncryptAlgorithm `json:"enc"`
	Type        string                  `json:"typ,omitempty"`
	ContentType string                  `json:"cty,omitempty"`
	EncKeyID    JWKID                   `json:"kid,omitempty"`
}
