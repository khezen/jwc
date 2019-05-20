package jwc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
)

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
		pk := pubKey.(rsa.PublicKey)
		cipherCEK, err = rsa.EncryptOAEP(sha256.New(), rng, &pk, cek, nil)
		break
	case RSA15:
		pk := pubKey.(rsa.PublicKey)
		cipherCEK, err = rsa.EncryptPKCS1v15(rng, &pk, cek)
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
