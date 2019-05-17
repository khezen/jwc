package jwc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ParseJWE -
func ParseJWE(jwe []byte, privKey *rsa.PrivateKey) (plaintext []byte, err error) {
	jweFragments := strings.Split(string(jwe), ".")
	if len(jweFragments) < 4 {
		return nil, ErrJWEUnparsable
	}
	var headers JOSEHeaders
	err = json.Unmarshal([]byte(jweFragments[0]), &headers)
	if err != nil {
		return nil, err
	}
	cek, err := parseCipherCEKb64(headers.Algorithm, jweFragments[1], privKey)
	if err != nil {
		return nil, err
	}
	iv, err := base64.URLEncoding.DecodeString(jweFragments[2])
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.URLEncoding.DecodeString(jweFragments[3])
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
		plaintext, err = mode.Open(nil, iv, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedEncryption
	}
	return plaintext, nil
}

func parseCipherCEKb64(alg Algorithm, cipherCEKB64 string, privKey *rsa.PrivateKey) (cek []byte, err error) {
	cipherCEK, err := base64.URLEncoding.DecodeString(cipherCEKB64)
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
