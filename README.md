# jwc

[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://godoc.org/github.com/khezen/jwc)
[![Build Status](http://img.shields.io/travis/khezen/jwc.svg?style=flat-square)](https://travis-ci.org/khezen/jwc) [![codecov](https://img.shields.io/codecov/c/github/khezen/jwc/master.svg?style=flat-square)](https://codecov.io/gh/khezen/jwc)
[![Go Report Card](https://goreportcard.com/badge/github.com/khezen/jwc?style=flat-square)](https://goreportcard.com/report/github.com/khezen/jwc)

JSON Web Cryptography

* jws - JSON Web Signature
  * RSASSA-PSS + SHA256, recommended +
  * RSASSA-PKCS1-v1_5 + SHA256, recommended -
  
* jwe - JSON Web Encryption
  * RSA-OAEP, recommended +
  * RSAES-PKCS1-v1_5, recommended -

## Example

### Signature

```golang
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/khezen/jwc"
)

var (
	privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
	uid           = uuid.New()
	jwkid         = jwc.JWKID(uid.String())
	jwk, _        = jwc.RSAToPrivateJWK(privateKey, jwkid, jwc.PS256, nil)
	jwkBytes, _   = json.Marshal(jwk)
	jwtStr        string
	err           error
)

// ExampleNewJWT - issue a JSON Web Token
func ExampleNewJWT() {
	now := time.Now().UTC()
	nowUnix := now.Unix()
	exp := now.Add(time.Minute)
	expUnix := exp.Unix()
	jwt, err := jwc.NewJWT(
		jwc.JWTPayload{
			RegisteredClaims: jwc.RegisteredClaims{
				IssuedAtTimestamp:   nowUnix,
				ExpirationTimestamp: expUnix,
				Issuer:              "github.com/khezen/jwc/jwt_test.go",
				Subject:             "test",
			},
			PrivateClaims: jwc.PrivateClaims{
				"tid": uuid.New(),
				"cid": uuid.New(),
				"aud": "android.myapp.com",
				"did": "deviceID",
				"sco": "offline",
				"cc":  "dummyCodeChallenge",
				"ccm": "S256",
			},
		},
		jwc.PS256,
	)
	if err != nil {
		panic(err)
	}
	jwtStr, err = jwt.Encode(jwkid, privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(jwtStr)
}

// ExampleDecodeVerifyJWT -
func ExampleDecodeVerifyJWT() {
	var pubJWK jwc.RSAPublicJWK
	err = json.Unmarshal(jwkBytes, &pubJWK)
	if err != nil {
		panic(err)
	}
	pubKey, err := jwc.JWKToPublicRSA(&pubJWK)
	if err != nil {
		panic(err)
	}
	token, err := jwc.DecodeVerifyJWT(jwtStr, pubKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("token signature is verified")
	fmt.Println(token)
}

func main() {
	ExampleNewJWT()
	fmt.Println()
	ExampleDecodeVerifyJWT()
}
```

#### output

```sh
eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkYjY2NzgwLWYzNjMtNDdmZC05MDlkLTQ0MWM1ZmUyM2Q2MSJ9.eyJleHAiOjE1NDYzNjk0NTIsImlhdCI6MTU0NjM2OTM5MiwiaXNzIjoiZ2l0aHViLmNvbS9raGV6ZW4vandjL2p3dF90ZXN0LmdvIiwic3ViIjoidGVzdCIsInByaXYiOnsiYXVkIjoiYW5kcm9pZC5teWFwcC5jb20iLCJjYyI6ImR1bW15Q29kZUNoYWxsZW5nZSIsImNjbSI6IlMyNTYiLCJjaWQiOiIwMTA4YmZiZC0yZjc2LTQyMmEtYTNiZC0yNjMxZmVhYWNiZWUiLCJkaWQiOiJkZXZpY2VJRCIsInNjbyI6Im9mZmxpbmUiLCJ0aWQiOiJiMGIwZWM5Mi1jZTNjLTQ3ZjUtODQ5Ny03Y2FiMjkxNDcyZDAifX0.WktA5tt_Tt6R-qZuTqpSB7xnYDrMlJXjz7aTzQys1UjMAEjLFHCWqmLp33DRlUboZiZQWa_6D4c6fzS-UHFQ9pQ_73s_Rg83i6XEMJIlr2k420g_cO-N_y425gnoJ2GDOpVSGxMS5uofh8JoE6OZpPNauJo_Z5MNpEKp5XZDEAE

token signature is verified
&{{PS256 JWT 4db66780-f363-47fd-909d-441c5fe23d61} {{1546369452 1546369392 github.com/khezen/jwc/jwt_test.go test } map[tid:b0b0ec92-ce3c-47f5-8497-7cab291472d0 aud:android.myapp.com cc:dummyCodeChallenge ccm:S256 cid:0108bfbd-2f76-422a-a3bd-2631feaacbee did:deviceID sco:offline]}}
```