package jwc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func newJWEA128GCM(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(16, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, headers, pubKey, plaintext)
}

func newJWEA256GCM(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(32, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, headers, pubKey, plaintext)
}

func newJWEA512GCM(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(64, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	return newGCM(cek, cipherCEK, cipherCEKB64, headers, pubKey, plaintext)
}

func newGCM(
	cek []byte,
	cipherCEK []byte,
	cipherCEKB64 string,
	headerss *JOSEHeaders,
	pubKey *rsa.PublicKey,
	plaintext []byte,
) ([]byte, error) {
	headerssBytes, err := json.Marshal(headerss)
	if err != nil {
		return nil, err
	}
	headerssB64 := base64.URLEncoding.EncodeToString(headerssBytes)
	iv, ivB64, err := GenerateInitVector(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	authTag := []byte(String2ASCII(headerssB64))
	authTagB64 := base64.URLEncoding.EncodeToString(authTag)
	ciphertext := mode.Seal(nil, iv, plaintext, authTag)
	ciphetextB64 := base64.URLEncoding.EncodeToString(ciphertext)
	jwe := fmt.Sprintf("%s.%s.%s.%s.%s", headerssB64, cipherCEKB64, ivB64, ciphetextB64, authTagB64)
	return []byte(jwe), nil
}
