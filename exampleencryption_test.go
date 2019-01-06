package jwc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/khezen/jwc"
)

func ExampleROAEP() {
	var (
		privateKey, _     = rsa.GenerateKey(rand.Reader, 2042)
		uid               = uuid.New()
		jwkid             = jwc.JWKID(uid.String())
		publicJWK, _      = jwc.RSAToPublicJWK(&privateKey.PublicKey, jwkid, jwc.ROAEP, nil)
		publicJWKBytes, _ = json.Marshal(publicJWK)
		plain             = []byte("lorem ipsum ipsa occaecati aut velit facilis enim dolorum id eius magni ducimus sed illum similique cupiditate sit id perferendis alias sint")
	)
	cipher := encrypt(plain, publicJWKBytes)
	deciphered := decrypt(cipher, privateKey)
	cmp := bytes.Compare(plain, deciphered)
	fmt.Println(cmp == 0)
}

func encrypt(plain, jwkBytes []byte) []byte {
	var jwk jwc.RSAPublicJWK
	err := json.Unmarshal(jwkBytes, &jwk)
	if err != nil {
		panic(err)
	}
	pubKey, err := jwk.PublicRSA()
	if err != nil {
		panic(err)
	}
	hash := sha256.New()
	label := []byte{}
	cipher, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, plain, label)
	if err != nil {
		panic(err)
	}
	return cipher
}

func decrypt(cipher []byte, privateKey *rsa.PrivateKey) []byte {
	hash := sha256.New()
	label := []byte{}
	plain, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, cipher, label)
	if err != nil {
		panic(err)
	}
	return plain
}
