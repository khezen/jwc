package jwc

// https://tools.ietf.org/html/rfc7516

// JWE - json web encrypted content
type JWE struct {
	JWEHeader
	EncryptedKey         []byte
	InitializationVector []byte
	CipherText           []byte
	AuthenticationTag    []byte
}

// JWEHeader JWE header
type JWEHeader struct {
	Algorithm   Algorithm `json:"alg"`
	Encryption  string    `json:"enc"`
	Type        string    `json:"typ,omitempty"`
	ContentType string    `json:"cty,omitempty"`
	EncKeyID    JWKID     `json:"kid"`
}
