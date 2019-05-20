package jwc

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
)

func plaintextCBC(K, iv, ciphertext, authTag, additionalAuthenticatedData []byte, hashFactory func() hash.Hash) (plaintext []byte, err error) {
	hmacKey := K[:16]
	authTagVerifier := renderCBCAuthTag(additionalAuthenticatedData, iv, ciphertext, hmacKey, hashFactory)
	if !bytes.EqualFold(authTagVerifier, authTag) {
		return nil, fmt.Errorf("unable to authenticate data")
	}
	cek := K[16:]
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext = make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext, err = UnpadPKCS7(plaintext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func newJWEA128CBCHS256(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := generateCEK(32, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashFactory := sha256.New
	return newCBC(cek, cipherCEK, cipherCEKB64, hashFactory, protectedHeaders, pubKey, plaintext)
}

func newJWEA192CBCHS384(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := generateCEK(40, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashFactory := sha512.New384
	return newCBC(cek, cipherCEK, cipherCEKB64, hashFactory, protectedHeaders, pubKey, plaintext)
}
func newJWEA256CBCHS512(protectedHeaders *JOSEHeaders, pubKey crypto.PublicKey, plaintext []byte) (*JWE, error) {
	cek, cipherCEK, cipherCEKB64, err := generateCEK(48, protectedHeaders.Algorithm, pubKey)
	if err != nil {
		return nil, err
	}
	hashFactory := sha512.New
	return newCBC(cek, cipherCEK, cipherCEKB64, hashFactory, protectedHeaders, pubKey, plaintext)
}

func newCBC(
	K []byte,
	cipherCEK []byte,
	cipherCEKB64 string,
	hashFactory func() hash.Hash,
	protectedHeaders *JOSEHeaders,
	pubKey crypto.PublicKey,
	plaintext []byte,
) (*JWE, error) {
	headersBytes, err := json.Marshal(protectedHeaders)
	if err != nil {
		return nil, err
	}
	headersB64 := base64.RawURLEncoding.EncodeToString(headersBytes)
	iv, ivB64, err := generateInitVector(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	hmacKey := K[:16]
	cek := K[16:]
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = PadPKCS7(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	ciphertextB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	additionalAuthenticatedData := []byte(string2ASCII(headersB64))
	authTag := renderCBCAuthTag(additionalAuthenticatedData, iv, ciphertext, hmacKey, hashFactory)
	authTagB64 := base64.RawURLEncoding.EncodeToString(authTag)
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

func renderCBCAuthTag(additionalAuthenticatedData, iv, ciphertext, hmacKey []byte, hashFactory func() hash.Hash) (authTag []byte) {
	additionalAuthenticatedDataLen := len(additionalAuthenticatedData)
	additionalAuthenticatedDataLenBigEndian := make([]byte, 32)
	binary.BigEndian.PutUint32(additionalAuthenticatedDataLenBigEndian, uint32(additionalAuthenticatedDataLen))
	authTag = hmac.New(hashFactory, hmacKey).Sum(append(append(append(additionalAuthenticatedData, iv...), ciphertext...), additionalAuthenticatedDataLenBigEndian...))[:16]
	return authTag
}

// PadPKCS7 -
func PadPKCS7(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// UnpadPKCS7 -
func UnpadPKCS7(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, errors.New("PKCS#7: error while unpadding")
	}
	return src[:(length - unpadding)], nil
}
