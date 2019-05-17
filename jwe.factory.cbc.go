package jwc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
)

func newJWEA128CBCHS256(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(16, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha256.New()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, headers, pubKey, plaintext)
}

func newJWEA192CBCHS384(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(24, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha512.New384()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, headers, pubKey, plaintext)
}
func newJWEA256CBCHS512(headers *JOSEHeaders, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(32, headers.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha512.New()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, headers, pubKey, plaintext)
}

func newCBC(
	cek []byte,
	cipherCEK []byte,
	cipherCEKB64 string,
	hash hash.Hash,
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
	ciphertext := make([]byte, 0, aes.BlockSize+len(plaintext))
	ciphertext = append(ciphertext, iv...)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	ciphetextB64 := base64.URLEncoding.EncodeToString(ciphertext)
	authTag := String2ASCII(headerssB64)
	authTagB64 := base64.URLEncoding.EncodeToString([]byte(authTag))
	jwe := fmt.Sprintf("%s.%s.%s.%s.%s", headerssB64, cipherCEKB64, ivB64, ciphetextB64, authTagB64)
	return []byte(jwe), nil
}
