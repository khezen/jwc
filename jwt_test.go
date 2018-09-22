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
	}{
		{JWTPayload{
			RegisteredClaims{
				IssuedAtTimestamp:   nowUnix,
				ExpirationTimestamp: expUnix,
				Issuer:              "github.com/khezen/jws/jwt_test.go",
				Subject:             "test",
			},
			PrivateClaims{
				"tid":  "tokenID",
				"cid":  "customerID",
				"clid": "android.myapp.com",
				"did":  "deviceID",
				"sco":  "offline",
				"cc":   "dummyCodeChallenge",
				"ccm":  "S256",
			},
		}},
		{JWTPayload{
			RegisteredClaims{
				IssuedAtTimestamp:   nowUnix,
				ExpirationTimestamp: expUnix,
				Issuer:              "github.com/khezen/jws/jwt_test.go",
				Subject:             "test",
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
		}},
	}
	for _, testCase := range cases {
		jwt := NewJWT(testCase.payload, RS256)
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
		_, err = DecodeAndVerifyJWT(encoded, &fakePublicKey)
		if err == nil {
			t.Errorf("expecting err != nil")
		}
		decoded, err := DecodeAndVerifyJWT(encoded, &publicKey)
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
