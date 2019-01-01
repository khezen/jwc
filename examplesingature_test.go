package jwc_test

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
	jwt := jwc.NewJWT(
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

	jwtStr, err = jwt.Encode(jwkid, privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("token:")
	fmt.Println(jwtStr)
	fmt.Println("signed with private key:")
	fmt.Println(string(jwkBytes))

	// issuing token...
	// token:
	// eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZkYzI4YTY4LTQwMjEtNGE5OS04ZDNlLTU2NWZlY2IwYTlmNyJ9.eyJleHAiOjE1NDYzNjY5MjIsImlhdCI6MTU0NjM2Njg2MiwiaXNzIjoiZ2l0aHViLmNvbS9raGV6ZW4vandjL2p3dF90ZXN0LmdvIiwic3ViIjoidGVzdCIsInByaXYiOnsiYXVkIjoiYW5kcm9pZC5teWFwcC5jb20iLCJjYyI6ImR1bW15Q29kZUNoYWxsZW5nZSIsImNjbSI6IlMyNTYiLCJjaWQiOiJkMjdiMDk2Yy1hM2NiLTQxZWItYTgyZC0wNGQ0Y2ZmYzE2OTAiLCJkaWQiOiJkZXZpY2VJRCIsInNjbyI6Im9mZmxpbmUiLCJ0aWQiOiIzZWMyZTE0Yy00ODIwLTQ3ZDUtOTZlOS02ODgyNTc0YzAxYWMifX0.ALLfesyvSLWcEhxQNzCYJvIoGr-Q9P8lwK-0OYbPijzJhqo010JWM2gObjqytIP6bTfy6yu7FjoF2OuklZ5BEiDYxrW9CKgDeCu4Kp-kmEgFdorf-VmNM64xm7oxJUePkhvDR92Wi7tgjsrFNt9Sxg6v7ZQdcfgVxG6H4lcV3tA
	// signed with private key:
	// {
	//     "kty":"RSA",
	//     "kid":"fdc28a68-4021-4a99-8d3e-565fecb0a9f7",
	//     "use":"sig",
	//     "alg":"PS256",
	//     "x5c":[
	//             "MIICXwIBAAKBgQDNpRE+xs193Yxlg1QROa7VUVkyVtNDSWZHER2iSkIWpz3Kw0nD8h6COBOho8062IVCWM7byGnpzI+4NerTT6ZcURHXhiKaIMT7mKM9RK1Rw9LMY0J7VTTxCJ1V6GDS+/aIulql4NcKhoZFe6q8i6xfX++76vemAybEzN7uGIiGbQIDAQABAoGBAJt+7EpOosVAh8+efSvFNSkBqPOCaZ6gWqD0FTdI9S4R6YxvHFD4vA70/gskQ6PyYtknM8tGgKeT0TyWMGj1+jDK8YpvgxU4csij1DCB7GQrEsBApQZzGMUs8WPpUlFydD2fMb25Xws4UyFEDIGBGODuF2sTx0wkU28G+0BaN1AhAkEA5rYz2ZcDvQ8JZE4dgiw/tlIFbr2XPuz1Ji1PJ5J5mcTR2L/xmE4TrSh/ZN2rx9yelut6A6lMe+n0sw4UcgFA+QJBAOQve9lmFXbxkkThSR42DLq5TTYxV1Q6/si747a8gyGJ1yP65nsF968fTxRb1F8an5lhHXDpBk+93MKwr2KeQhUCQQCN4+0Lm3bvJXpPOEOptXERvmwc6XlFeBJlgmQ2ID2tNoEg3xvE4e/0BP4kmLh3WNYoV3ZZHhwt8XtPTA+C9gZxAkEAxTVElF7lriaZg24xAyszVS1QzcVW9DUIffPkmcnSiunWRgJRr4E4zuEAN1gl8wvPY3/LMgoyqjgs0xZgfZrJAQJBAKZDvEDvyHQuLLygFuA147we9YO6uy0aPQW90+WtL6RGatE/5EEC8hV+MBASlJ+dp1Hv4N4BUfmcpB5YaKzf4mg="
	//     ],
	//     "x5t":"5RZT3e1f7Mdpv4q+cgjXWcIyTnQ=",
	//     "n":"zaURPsbNfd2MZYNUETmu1VFZMlbTQ0lmRxEdokpCFqc9ysNJw/IegjgToaPNOtiFQljO28hp6cyPuDXq00+mXFER14YimiDE                                  +5ijPUStUcPSzGNCe1U08QidVehg0vv2iLpapeDXCoaGRXuqvIusX1/vu+r3pgMmxMze7hiIhm0=",
	//     "e":"NjU1Mzc=",
	//     "d":"m37sSk6ixUCHz559K8U1KQGo84JpnqBaoPQVN0j1LhHpjG8cUPi8DvT+CyRDo/Ji2Sczy0aAp5PRPJYwaPX6MMrxim+DFThyyKPUMIHsZCsSwEClBnMYxSzxY          +lSUXJ0PZ8xvblfCzhTIUQMgYEY4O4XaxPHTCRTbwb7QFo3UCE=",
	//     "p":"5rYz2ZcDvQ8JZE4dgiw/tlIFbr2XPuz1Ji1PJ5J5mcTR2L/xmE4TrSh/ZN2rx9yelut6A6lMe+n0sw4UcgFA+Q==",
	//     "q":"5C972WYVdvGSROFJHjYMurlNNjFXVDr+yLvjtryDIYnXI/rmewX3rx9PFFvUXxqfmWEdcOkGT73cwrCvYp5CFQ==",
	//     "dp":"jePtC5t27yV6TzhDqbVxEb5sHOl5RXgSZYJkNiA9rTaBIN8bxOHv9AT+JJi4d1jWKFd2WR4cLfF7T0wPgvYGcQ==",
	//     "dq":"xTVElF7lriaZg24xAyszVS1QzcVW9DUIffPkmcnSiunWRgJRr4E4zuEAN1gl8wvPY3/LMgoyqjgs0xZgfZrJAQ==",
	//     "qi":"pkO8QO/IdC4svKAW4DXjvB71g7q7LRo9Bb3T5a0vpEZq0T/kQQLyFX4wEBKUn52nUe/g3gFR+ZykHlhorN/iaA=="
	// }
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

	// verifying token...
	// token signature is verified with public key:
	// {
	//     "kty":"RSA",
	//     "kid":"fdc28a68-4021-4a99-8d3e-565fecb0a9f7",
	//     "use":"sig",
	//     "alg":"PS256",
	//     "x5c":[
	//             "MIICXwIBAAKBgQDNpRE+xs193Yxlg1QROa7VUVkyVtNDSWZHER2iSkIWpz3Kw0nD8h6COBOho8062IVCWM7byGnpzI+4NerTT6ZcURHXhiKaIMT7mKM9RK1Rw9LMY0J7VTTxCJ1V6GDS+/aIulql4NcKhoZFe6q8i6xfX++76vemAybEzN7uGIiGbQIDAQABAoGBAJt+7EpOosVAh8+efSvFNSkBqPOCaZ6gWqD0FTdI9S4R6YxvHFD4vA70/gskQ6PyYtknM8tGgKeT0TyWMGj1+jDK8YpvgxU4csij1DCB7GQrEsBApQZzGMUs8WPpUlFydD2fMb25Xws4UyFEDIGBGODuF2sTx0wkU28G+0BaN1AhAkEA5rYz2ZcDvQ8JZE4dgiw/tlIFbr2XPuz1Ji1PJ5J5mcTR2L/xmE4TrSh/ZN2rx9yelut6A6lMe+n0sw4UcgFA+QJBAOQve9lmFXbxkkThSR42DLq5TTYxV1Q6/si747a8gyGJ1yP65nsF968fTxRb1F8an5lhHXDpBk+93MKwr2KeQhUCQQCN4+0Lm3bvJXpPOEOptXERvmwc6XlFeBJlgmQ2ID2tNoEg3xvE4e/0BP4kmLh3WNYoV3ZZHhwt8XtPTA+C9gZxAkEAxTVElF7lriaZg24xAyszVS1QzcVW9DUIffPkmcnSiunWRgJRr4E4zuEAN1gl8wvPY3/LMgoyqjgs0xZgfZrJAQJBAKZDvEDvyHQuLLygFuA147we9YO6uy0aPQW90+WtL6RGatE/5EEC8hV+MBASlJ+dp1Hv4N4BUfmcpB5YaKzf4mg="
	//		],
	//     "x5t":"5RZT3e1f7Mdpv4q+cgjXWcIyTnQ=",
	//     "n":"zaURPsbNfd2MZYNUETmu1VFZMlbTQ0lmRxEdokpCFqc9ysNJw/IegjgToaPNOtiFQljO28hp6cyPuDXq00+mXFER14YimiDE                                   +5ijPUStUcPSzGNCe1U08QidVehg0vv2iLpapeDXCoaGRXuqvIusX1/vu+r3pgMmxMze7hiIhm0=",
	//     "e":"NjU1Mzc="
	// }
	// obtained a token with header:
	// {
	//     "alg":"PS256",
	//     "typ":"JWT",
	//     "kid":"fdc28a68-4021-4a99-8d3e-565fecb0a9f7"
	// }
	// and payload:
	// {
	//     "exp":1546366922,
	//     "iat":1546366862,
	//     "iss":"github.com/khezen/jwc/jwt_test.go",
	//     "sub":"test",
	//     "priv":{
	//         "aud":"android.myapp.com",
	//         "cc":"dummyCodeChallenge",
	//         "ccm":"S256",
	//         "cid":"d27b096c-a3cb-41eb-a82d-04d4cffc1690",
	//         "did":"deviceID",
	//         "sco":"offline",
	//         "tid":"3ec2e14c-4820-47d5-96e9-6882574c01ac"
	//     }
	// }
}
