package jwc

import (
	"crypto"
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
	Algorithm                      Algorithm               `json:"alg"`
	Encryption                     ContentEncryptAlgorithm `json:"enc"`
	AdditionalAuthenticatedDataB64 string                  `json:"aad,omitempty"`
	Type                           string                  `json:"typ,omitempty"`
	ContentType                    string                  `json:"cty,omitempty"`
	KeyID                          JWKID                   `json:"kid,omitempty"`
	JWKURI                         string                  `json:"jku,omitempty"`
	JWK                            *JWK                    `json:"jwk,omitmepty"`
	Zip                            string                  `json:"zip,omitempty"`
	Critical                       []string                `jon:"crit,omitempty"`
}

// JWE -
type JWE struct {
	ProtectedB64                string `json:"protected"`
	UnprotectedB64              string `json:"unprotected,omitmepty"`
	AdditionalAuthenticatedData string `json:"add,omitempty"`
	CipherCEKB64                string `json:"encrypted_key"`
	InitVectorB64               string `json:"iv"`
	CiphertextB64               string `json:"ciphertext"`
	TagB64                      string `json:"tag,omitempty"`
}

// Compact formats to the JWE compact serialisation
func (jwe *JWE) Compact() ([]byte, error) {
	if len(jwe.TagB64) > 0 {
		protectedHeadersBytes, err := base64.RawURLEncoding.DecodeString(jwe.ProtectedB64)
		if err != nil {
			return nil, err
		}
		var protectedHeaders JOSEHeaders
		err = json.Unmarshal(protectedHeadersBytes, &protectedHeaders)
		if err != nil {
			return nil, err
		}
		protectedHeaders.AdditionalAuthenticatedDataB64 = base64.RawURLEncoding.EncodeToString([]byte(jwe.AdditionalAuthenticatedData))
		protectedHeadersBytes, err = json.Marshal(protectedHeaders)
		if err != nil {
			return nil, err
		}
		jwe.ProtectedB64 = base64.RawURLEncoding.EncodeToString(protectedHeadersBytes)
		return []byte(fmt.Sprintf(
			"%s.%s.%s.%s.%s",
			jwe.ProtectedB64,
			jwe.CipherCEKB64,
			jwe.InitVectorB64,
			jwe.CiphertextB64,
			jwe.TagB64,
		)), nil
	}
	return []byte(fmt.Sprintf(
		"%s.%s.%s.%s",
		jwe.ProtectedB64,
		jwe.CipherCEKB64,
		jwe.InitVectorB64,
		jwe.CiphertextB64,
	)), nil
}

// Plaintext returns deciphered content
func (jwe *JWE) Plaintext(privKey crypto.PrivateKey) (plaintext []byte, err error) {
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
	plaintext = ciphertext
	switch headers.Encryption {
	case A128CBCHS256, A192CBCHS384, A256CBCHS512:
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, ciphertext)
		plaintext, err = Unpad(plaintext)
		if err != nil {
			return nil, err
		}
	case A128GCM, A192GCM, A256GCM:
		mode, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		authTag, err := base64.RawURLEncoding.DecodeString(jwe.TagB64)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, authTag...)
		additionalAuthenticatedData, err := base64.RawURLEncoding.DecodeString(headers.AdditionalAuthenticatedDataB64)
		if err != nil {
			return nil, err
		}
		plaintext, err = mode.Open(nil, iv, ciphertext, additionalAuthenticatedData)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedEncryption
	}
	return plaintext, nil
}

func decipherCEK(alg Algorithm, cipherCEKB64 string, privKey crypto.PrivateKey) (cek []byte, err error) {
	cipherCEK, err := base64.RawURLEncoding.DecodeString(cipherCEKB64)
	if err != nil {
		return nil, err
	}
	rng := rand.Reader
	switch alg {
	case RSA15:
		return rsa.DecryptPKCS1v15(rng, privKey.(*rsa.PrivateKey), cipherCEK)
	case ROAEP:
		return rsa.DecryptOAEP(sha256.New(), rng, privKey.(*rsa.PrivateKey), cipherCEK, nil)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}
