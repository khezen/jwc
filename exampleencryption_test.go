package jwc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/khezen/jwc"
)

func ExampleJWE() {
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
	fmt.Println(bytes.EqualFold(plain, deciphered))
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
	jwe, err := jwc.NewJWE(
		&jwc.JOSEHeaders{Algorithm: jwc.ROAEP, Encryption: jwc.A256GCM},
		pubKey,
		plain,
	)
	jweString, err := jwe.Compact()
	if err != nil {
		panic(err)
	}
	return jweString
}

func decrypt(compactJWE []byte, privateKey *rsa.PrivateKey) []byte {
	jwe, err := jwc.ParseCompactJWE(compactJWE)
	if err != nil {
		panic(err)
	}
	plain, err := jwe.Plaintext(privateKey)
	if err != nil {
		panic(err)
	}
	return plain
}
