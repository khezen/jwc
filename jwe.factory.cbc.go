package jwc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
)

func newJWEA128CBCHS256(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(16, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha256.New()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, protectedHeaders, pubKey, plaintext)
}

func newJWEA192CBCHS384(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(24, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha512.New384()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, protectedHeaders, pubKey, plaintext)
}
func newJWEA256CBCHS512(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := GenerateCEK(32, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashAlg := sha512.New()
	return newCBC(cek, cipherCEK, cipherCEKB64, hashAlg, protectedHeaders, pubKey, plaintext)
}

func newCBC(
	cek []byte,
	cipherCEK []byte,
	cipherCEKB64 string,
	hash hash.Hash,
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
	iv, ivB64, err := GenerateInitVector(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	jwe := JWE{
		ProtectedB64:  headersB64,
		CipherCEKB64:  cipherCEKB64,
		InitVectorB64: ivB64,
		CiphertextB64: ciphertextB64,
	}
	return &jwe, nil
}
