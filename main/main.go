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

// ExampleNewJWT -
func ExampleNewJWT() {
	fmt.Println("issuing token...")
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
	fmt.Println("token:")
	fmt.Println(jwtStr)
	fmt.Println("signed with private key:")
	fmt.Println(string(jwkBytes))
}

// ExampleDecodeVerifyJWT -
func ExampleDecodeVerifyJWT() {
	fmt.Println("verifying token...")
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
	fmt.Println("token signature is verified with public key:")
	pubJWKBytes, _ := json.Marshal(pubJWK)
	fmt.Println(string(pubJWKBytes))
	fmt.Println("obtained a token with header:")
	headerBytes, _ := json.Marshal(token.Header)
	fmt.Println(string(headerBytes))
	fmt.Println("and payload:")
	payloadBytes, _ := json.Marshal(token.Payload)
	fmt.Println(string(payloadBytes))
}

func main() {
	ExampleNewJWT()
	fmt.Println()
	ExampleDecodeVerifyJWT()
}
