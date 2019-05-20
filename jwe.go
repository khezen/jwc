package jwc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
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

// ParseCompactJWE -
func ParseCompactJWE(compact []byte) (jwe *JWE, err error) {
	var (
		jweFragments = strings.Split(string(compact), ".")
	)
	headersBytes, err := base64.RawURLEncoding.DecodeString(jweFragments[0])
	if err != nil {
		return nil, err
	}
	var headers JOSEHeaders
	err = json.Unmarshal(headersBytes, &headers)
	if err != nil {
		return nil, err
	}
	additionalAuthenticatedData, err := base64.RawURLEncoding.DecodeString(headers.AdditionalAuthenticatedDataB64)
	if err != nil {
		return nil, err
	}
	return &JWE{
		ProtectedB64:                jweFragments[0],
		AdditionalAuthenticatedData: string(additionalAuthenticatedData),
		CipherCEKB64:                jweFragments[1],
		InitVectorB64:               jweFragments[2],
		CiphertextB64:               jweFragments[3],
		TagB64:                      jweFragments[4],
	}, nil
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

	authTag, err := base64.RawURLEncoding.DecodeString(jwe.TagB64)
	if err != nil {
		return nil, err
	}
	plaintext = ciphertext
	switch headers.Encryption {
	case A128CBCHS256:
		return plaintextCBC(cek, iv, ciphertext, authTag, []byte(jwe.AdditionalAuthenticatedData), sha256.New)
	case A192CBCHS384:
		return plaintextCBC(cek, iv, ciphertext, authTag, []byte(jwe.AdditionalAuthenticatedData), sha512.New384)
	case A256CBCHS512:
		return plaintextCBC(cek, iv, ciphertext, authTag, []byte(jwe.AdditionalAuthenticatedData), sha512.New)
	case A128GCM, A192GCM, A256GCM:
		return plaintextGCM(cek, iv, ciphertext, authTag, []byte(jwe.AdditionalAuthenticatedData))
	default:
		return nil, ErrUnsupportedEncryption
	}
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

// NewJWE -
func NewJWE(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	switch protectedHeaders.Encryption {
	case A128CBCHS256:
		return newJWEA128CBCHS256(protectedHeaders, pubKey, plaintext)
	case A192CBCHS384:
		return newJWEA192CBCHS384(protectedHeaders, pubKey, plaintext)
	case A256CBCHS512:
		return newJWEA256CBCHS512(protectedHeaders, pubKey, plaintext)
	case A128GCM:
		return newJWEA128GCM(protectedHeaders, pubKey, plaintext)
	case A192GCM:
		return newJWEA192GCM(protectedHeaders, pubKey, plaintext)
	case A256GCM:
		return newJWEA256GCM(protectedHeaders, pubKey, plaintext)
	default:
		return nil, ErrUnsupportedEncryption
	}
}

// GenerateCEK - generate plaintext encryption key
func GenerateCEK(byteLength int, alg Algorithm, pubKey crypto.PublicKey) (cek []byte, cipherCEK []byte, cipherCEKB64 string, err error) {
	cek = make([]byte, byteLength)
	_, err = rand.Read(cek)
	if err != nil {
		return nil, nil, "", err
	}
	rng := rand.Reader
	switch alg {
	case ROAEP:
		cipherCEK, err = rsa.EncryptOAEP(sha256.New(), rng, pubKey.(*rsa.PublicKey), cek, nil)
		break
	case RSA15:
		cipherCEK, err = rsa.EncryptPKCS1v15(rng, pubKey.(*rsa.PublicKey), cek)
		break
	default:
		return nil, nil, "", ErrUnsupportedAlgorithm
	}
	cipherCEKB64 = base64.RawURLEncoding.EncodeToString(cipherCEK)
	return cek, cipherCEK, cipherCEKB64, nil
}

// GenerateInitVector -
func GenerateInitVector(ivLen int) (iv []byte, ivB64 string, err error) {
	iv = make([]byte, ivLen)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, "", err
	}
	ivB64 = base64.RawURLEncoding.EncodeToString(iv)
	return iv, ivB64, err
}

// String2ASCII - ensure ASCII encoding
func String2ASCII(s string) string {
	var (
		buf = new(bytes.Buffer)
		r   rune
	)
	for _, r = range s {
		buf.WriteRune(Rune2ASCII(r))
	}
	return buf.String()
}

// Rune2ASCII - ensure ASCII encoding
func Rune2ASCII(r rune) rune {
	switch {
	case 97 <= r && r <= 122:
		return r - 32
	case 65 <= r && r <= 90:
		return r + 32
	default:
		return r
	}
}
