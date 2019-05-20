package jwc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
)

func plaintextGCM(cek, iv, ciphertext, authTag, additionalAuthenticatedData []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext = append(ciphertext, authTag...)
	plaintext, err = mode.Open(nil, iv, ciphertext, additionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func newJWEA128GCM(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(16, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, protectedHeaders, pubKey, plaintext)
}

func newJWEA192GCM(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(24, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, protectedHeaders, pubKey, plaintext)
}

func newJWEA256GCM(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(32, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, protectedHeaders, pubKey, plaintext)
}

func newGCM(
	cek []byte,
	cipherCEK []byte,
	cipherCEKB64 string,
	protectedHeaders *JOSEHeaders,
	pubKey crypto.PublicKey,
	plaintext []byte,
) (*JWE, error) {
	headersBytes, err := json.Marshal(protectedHeaders)
	if err != nil {
		return nil, err
	}
	headersB64 := base64.RawURLEncoding.EncodeToString(headersBytes)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv, ivB64, err := GenerateInitVector(mode.NonceSize())
	if err != nil {
		return nil, err
	}
	additionalAuthenticatedData := []byte(String2ASCII(headersB64))
	ciphertext := mode.Seal(nil, iv, plaintext, additionalAuthenticatedData)
	pivot := len(ciphertext) - aes.BlockSize
	authTag := ciphertext[pivot:]
	authTagB64 := base64.RawURLEncoding.EncodeToString(authTag)
	ciphertext = ciphertext[:pivot]
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	jwe := JWE{
		ProtectedB64:                headersB64,
		AdditionalAuthenticatedData: string(additionalAuthenticatedData),
		CipherCEKB64:                cipherCEKB64,
		InitVectorB64:               ivB64,
		CiphertextB64:               ciphertextB64,
		TagB64:                      authTagB64,
	}
	return &jwe, nil
}
