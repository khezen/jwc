package jwc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/khezen/jwc"
)

func ExampleJWE() {
	var (
		privateKey, _     = rsa.GenerateKey(rand.Reader, 2042)
		jwkid             = jwc.JWKID("52d510e3-8d0a-4ef8-a81a-c8cd7ce06472")
		publicJWK, _      = jwc.RSAToPublicJWK(&privateKey.PublicKey, jwkid, jwc.ROAEP, nil)
		publicJWKBytes, _ = json.Marshal(publicJWK)
		message           = []byte("lorem ipsum ipsa occaecati aut velit facilis enim dolorum id eius magni ducimus sed illum similique cupiditate sit id perferendis alias sint")
	)
	compactJWE := encrypt(message, publicJWKBytes)
	plaintext := decrypt(compactJWE, privateKey)
	fmt.Println(bytes.EqualFold(message, plaintext))
}

func encrypt(plaintext, jwkBytes []byte) []byte {
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
		plaintext,
	)
	if err != nil {
		panic(err)
	}
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
	plaintext, err := jwe.Plaintext(privateKey)
	if err != nil {
		panic(err)
	}
	return plaintext
}
