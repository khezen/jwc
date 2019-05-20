package jwc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	fakePrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	fakePublicKey := fakePrivateKey.PublicKey
	now := time.Now().UTC()
	nowUnix := now.Unix()
	exp := now.Add(time.Minute)
	expUnix := exp.Unix()
	cases := []struct {
		payload JWTPayload
		alg     Algorithm
	}{
		{
			JWTPayload{
				RegisteredClaims{
					IssuedAtTimestamp:   nowUnix,
					ExpirationTimestamp: expUnix,
					Issuer:              "github.com/khezen/jwc/jwt_test.go",
					Subject:             "customer_id",
					Audiance:            "android.myapp.com",
				},
				PrivateClaims{
					"id":  "token_id",
					"did": "device_id",
					"sco": "offline",
					"cc":  "dummy_code_challenge",
					"ccm": "S256",
				},
			},
			RS256,
		},
		{
			JWTPayload{
				RegisteredClaims{
					IssuedAtTimestamp:   nowUnix,
					ExpirationTimestamp: expUnix,
					Issuer:              "github.com/khezen/jwc/jwt_test.go",
					Subject:             "customer_id",
					Audiance:            "ios.myapp.com",
				},
				PrivateClaims{
					"id":  "token_id",
					"did": "device_id",
					"sco": "offline",
					"cc":  "du,,y_code_challenge",
					"ccm": "S256",
				},
			},
			RS256,
		},
		{
			JWTPayload{
				RegisteredClaims{
					IssuedAtTimestamp:   nowUnix,
					ExpirationTimestamp: expUnix,
					Issuer:              "github.com/khezen/jwc/jwt_test.go",
					Subject:             "customer_id",
					Audiance:            "android.myapp.com",
				},
				PrivateClaims{
					"id":  "token_id",
					"did": "device_id",
					"sco": "offline",
					"cc":  "dummy_code_challenge",
					"ccm": "S256",
				},
			},
			PS256,
		},
		{
			JWTPayload{
				RegisteredClaims{
					IssuedAtTimestamp:   nowUnix,
					ExpirationTimestamp: expUnix,
					Issuer:              "github.com/khezen/jwc/jwt_test.go",
					Subject:             "customer_id",
					Audiance:            "ios.myapp.com",
				},
				PrivateClaims{
					"id":  "token_id",
					"did": "device_id",
					"sco": "offline",
					"cc":  "dummy_code_challenge",
					"ccm": "S256",
				},
			},
			PS256,
		},
	}
	for _, testCase := range cases {
		jwt, err := NewJWT(testCase.payload, testCase.alg)
		if err != nil {
			panic(err)
		}
		encoded, err := jwt.Encode("test", privateKey)
		if err != nil {
			panic(err)
		}
		err = VerifyJWT(encoded, &fakePublicKey)
		if err == nil {
			t.Errorf("expecting err != nil")
		}
		err = VerifyJWT(encoded, &publicKey)
		if err != nil {
			panic(err)
		}
		_, err = DecodeVerifyJWT(encoded, &fakePublicKey)
		if err == nil {
			t.Errorf("expecting err != nil")
		}
		decoded, err := DecodeVerifyJWT(encoded, &publicKey)
		if err != nil {
			panic(err)
		}
		testCompareJWT(*jwt, *decoded, t)
		decoded, err = DecodeJWT(encoded)
		if err != nil {
			panic(err)
		}
		testCompareJWT(*jwt, *decoded, t)
	}
}

func testCompareJWT(input, decoded JWT, t *testing.T) {
	if input.Header.Algorithm != decoded.Header.Algorithm {
		t.Errorf("expected %v got %v", input.Header.Algorithm, decoded.Header.Algorithm)
	}
	if input.Header.Type != decoded.Header.Type {
		t.Errorf("expected %v got %v", input.Header.Type, decoded.Header.Type)
	}
	if input.Header.SignKeyID != decoded.Header.SignKeyID {
		t.Errorf("expected %v got %v", input.Header.SignKeyID, decoded.Header.SignKeyID)
	}
	if input.Payload.Audiance != decoded.Payload.Audiance {
		t.Errorf("expected %v got %v", input.Payload.Audiance, decoded.Payload.Audiance)
	}
	if input.Payload.ExpirationTimestamp != decoded.Payload.ExpirationTimestamp {
		t.Errorf("expected %v got %v", input.Payload.ExpirationTimestamp, decoded.Payload.ExpirationTimestamp)
	}
	if input.Payload.IssuedAtTimestamp != decoded.Payload.IssuedAtTimestamp {
		t.Errorf("expected %v got %v", input.Payload.IssuedAtTimestamp, decoded.Payload.IssuedAtTimestamp)
	}
	if input.Payload.Issuer != decoded.Payload.Issuer {
		t.Errorf("expected %v got %v", input.Payload.Issuer, decoded.Payload.Issuer)
	}
	for k := range input.Payload.PrivateClaims {
		if input.Payload.PrivateClaims[k] != decoded.Payload.PrivateClaims[k] {
			t.Errorf("Expected %v, got %v", input.Payload.PrivateClaims[k], decoded.Payload.PrivateClaims[k])
		}
	}
	for k := range decoded.Payload.PrivateClaims {
		if input.Payload.PrivateClaims[k] != decoded.Payload.PrivateClaims[k] {
			t.Errorf("Expected %v, got %v", decoded.Payload.PrivateClaims[k], input.Payload.PrivateClaims[k])
		}
	}
}

func TestJWTErrCases(t *testing.T) {
	_, _, _, err := ExtractJWTParts("abcdefjhijklmnopqrstuvwxyz")
	if err == nil {
		t.Errorf("expected %v, got nil", ErrJWTUnparsable)
	}
	_, err = NewJWT(
		JWTPayload{
			RegisteredClaims{
				IssuedAtTimestamp: time.Now().UTC().Unix(),
				Issuer:            "github.com/khezen/jws/jwt_test.go",
				Subject:           "test",
			},
			PrivateClaims{
				"tid":  "tokenID",
				"cid":  "customerID",
				"clid": "ios.myapp.com",
				"did":  "deviceID",
				"sco":  "offline",
				"cc":   "dummyCodeChallenge",
				"ccm":  "S256",
			},
		},
		"UnsupportedAlgo",
	)
	if err == nil {
		t.Errorf("expected %v, got nil", ErrUnsupportedAlgorithm)
	}
	jwt, err := NewJWT(
		JWTPayload{
			RegisteredClaims{
				IssuedAtTimestamp: time.Now().UTC().Unix(),
				Issuer:            "github.com/khezen/jws/jwt_test.go",
				Subject:           "test",
			},
			PrivateClaims{
				"tid":  "tokenID",
				"cid":  "customerID",
				"clid": "ios.myapp.com",
				"did":  "deviceID",
				"sco":  "offline",
				"cc":   "dummyCodeChallenge",
				"ccm":  "S256",
			},
		},
		PS256,
	)
	if err != nil {
		panic(err)
	}
	jwt.Header.Algorithm = "UnsupportedAlgo"
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	jwtStr, err := jwt.Encode("test", privateKey)
	if err != nil {
		panic(err)
	}
	_, err = DecodeVerifyJWT(jwtStr, &privateKey.PublicKey)
	if err == nil {
		t.Errorf("expected %v, got nil", ErrUnsupportedAlgorithm)
	}
}
