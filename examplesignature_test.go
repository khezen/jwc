package jwc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/khezen/jwc"
)

func ExampleJWT() {
	var (
		privateKey, _ = rsa.GenerateKey(rand.Reader, 1024)
		jwkid         = jwc.JWKID("52d510e3-8d0a-4ef8-a81a-c8cd7ce06472")
		jwk, _        = jwc.RSAToPublicJWK(&privateKey.PublicKey, jwkid, jwc.PS256, nil)
		jwkBytes, _   = json.Marshal(jwk)
	)
	jwtStr := issueJWT(jwkid, privateKey)
	token := verify(jwtStr, jwkBytes)
	fmt.Println(jwtStr)
	fmt.Println()
	fmt.Println(token)
	// eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkYjY2NzgwLWYzNjMtNDdmZC05MDlkLTQ0MWM1ZmUyM2Q2MSJ9.eyJleHAiOjE1NDYzNjk0NTIsImlhdCI6MTU0NjM2OTM5MiwiaXNzIjoiZ2l0aHViLmNvbS9raGV6ZW4vandjL2p3dF90ZXN0LmdvIiwic3ViIjoidGVzdCIsInByaXYiOnsiYXVkIjoiYW5kcm9pZC5teWFwcC5jb20iLCJjYyI6ImR1bW15Q29kZUNoYWxsZW5nZSIsImNjbSI6IlMyNTYiLCJjaWQiOiIwMTA4YmZiZC0yZjc2LTQyMmEtYTNiZC0yNjMxZmVhYWNiZWUiLCJkaWQiOiJkZXZpY2VJRCIsInNjbyI6Im9mZmxpbmUiLCJ0aWQiOiJiMGIwZWM5Mi1jZTNjLTQ3ZjUtODQ5Ny03Y2FiMjkxNDcyZDAifX0.WktA5tt_Tt6R-qZuTqpSB7xnYDrMlJXjz7aTzQys1UjMAEjLFHCWqmLp33DRlUboZiZQWa_6D4c6fzS-UHFQ9pQ_73s_Rg83i6XEMJIlr2k420g_cO-N_y425gnoJ2GDOpVSGxMS5uofh8JoE6OZpPNauJo_Z5MNpEKp5XZDEAE
	//
	// &{{PS256 JWT 4db66780-f363-47fd-909d-441c5fe23d61} {{1546369452 1546369392 github.com/khezen/jwc/jwt_test.go test } map[tid:b0b0ec92-ce3c-47f5-8497-7cab291472d0 aud:android.myapp.com cc:dummyCodeChallenge ccm:S256 cid:0108bfbd-2f76-422a-a3bd-2631feaacbee did:deviceID sco:offline]}}
}

func issueJWT(keyID jwc.JWKID, privateKey *rsa.PrivateKey) string {
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
				Subject:             "customer_id",
				Audiance:            "android.myapp.com",
			},
			PrivateClaims: jwc.PrivateClaims{
				"id":  "token_id",
				"did": "device_id",
				"sco": "offline",
				"cc":  "dummy_code_challenge",
				"ccm": "S256",
			},
		},
		jwc.PS256,
	)
	if err != nil {
		panic(err)
	}
	jwtStr, err := jwt.Encode(keyID, privateKey)
	if err != nil {
		panic(err)
	}
	return jwtStr
}

func verify(jwtStr string, jwkBytes []byte) *jwc.JWT {
	var pubJWK jwc.RSAPublicJWK
	err := json.Unmarshal(jwkBytes, &pubJWK)
	if err != nil {
		panic(err)
	}
	pubKey, err := pubJWK.PublicRSA()
	if err != nil {
		panic(err)
	}
	token, err := jwc.DecodeVerifyJWT(jwtStr, pubKey)
	if err != nil {
		panic(err)
	}
	return token
}
