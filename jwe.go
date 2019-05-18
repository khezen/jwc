package jwc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrCompactJWEUnparsable -
	ErrCompactJWEUnparsable = errors.New("ErrCompactJWEUnparsable")
)

// https://tools.ietf.org/html/rfc7516

// JOSEHeaders JWE header
type JOSEHeaders struct {
	Algorithm   Algorithm               `json:"alg"`
	Encryption  ContentEncryptAlgorithm `json:"enc"`
	Type        string                  `json:"typ,omitempty"`
	ContentType string                  `json:"cty,omitempty"`
	KeyID       JWKID                   `json:"kid,omitempty"`
	JWKURI      string                  `json:"jku,omitempty"`
	JWK         *JWK                    `json:"jwk,omitmepty"`
	Zip         string                  `json:"zip,omitempty"`
	Critical    []string                `jon:"crit,omitempty"`
}

// JWE -
type JWE struct {
	ProtectedB64                string `json:"protected"`
	UnprotectedB64              string `json:"unprotected,omitmepty"`
	AdditionalAuthenticatedData string `json:"add,omitempty"`
	CipherCEKB64                string `json:"encrypted_key"`
	InitVectorB64               string `json:"iv"`
	CiphertextB64               string `json:"ciphertext"`
	TagB64                      string `json:"tag"`
}

// Compact formats to the JWE compact serialisation
func (jwe *JWE) Compact() []byte {
	return []byte(
		fmt.Sprintf(
			"%s.%s.%s.%s.%s",
			jwe.ProtectedB64,
			jwe.CipherCEKB64,
			jwe.InitVectorB64,
			jwe.CiphertextB64,
			jwe.TagB64,
		),
	)
}

// Plaintext returns deciphered content
func (jwe *JWE) Plaintext(privKey *rsa.PrivateKey) (plaintext []byte, err error) {
	headersBytes, err := base64.RawURLEncoding.DecodeString(jwe.ProtectedB64)
	var headers JOSEHeaders
	err = json.Unmarshal(headersBytes, &headers)
	if err != nil {
		return nil, err
	}
	cek, err := decipherCEK(headers.Algorithm, jwe.CipherCEKB64, privKey)
	if err != nil {
		return nil, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(jwe.InitVectorB64)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(jwe.CiphertextB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	switch headers.Encryption {
	case A128CBCHS256, A192CBCHS384, A256CBCHS512:
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, ciphertext[aes.BlockSize:])
	case A128GCM, A256GCM, A512GCM:
		mode, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		authTag, err := base64.RawURLEncoding.DecodeString(jwe.TagB64)
		if err != nil {
			return nil, err
		}
		plaintext, err = mode.Open(nil, iv, ciphertext, authTag)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedEncryption
	}
	return plaintext, nil
}

func decipherCEK(alg Algorithm, cipherCEKB64 string, privKey *rsa.PrivateKey) (cek []byte, err error) {
	cipherCEK, err := base64.RawURLEncoding.DecodeString(cipherCEKB64)
	if err != nil {
		return nil, err
	}
	rng := rand.Reader
	switch alg {
	case RSA15:
		return rsa.DecryptPKCS1v15(rng, privKey, cipherCEK)
	case ROAEP:
		return rsa.DecryptOAEP(sha256.New(), rng, privKey, cipherCEK, nil)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}
