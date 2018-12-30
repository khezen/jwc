package jwc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

func TestRSAPublicJWK(t *testing.T) {
	now := time.Now().UTC()
	expirationTime := now.Add(time.Hour)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	publicKey := privateKey.PublicKey
	publicJWK, err := RSAToPublicJWK(&publicKey, JWKID("valid"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	publicJWKBytes, err := json.Marshal(publicJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePublicKey := fakePrivateKey.PublicKey
	fakePublicJWK, err := RSAToPublicJWK(&fakePublicKey, JWKID("fake"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePublicJWKBytes, err := json.Marshal(fakePublicJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	cases := []struct {
		rsaPrivateKey  *rsa.PrivateKey
		publicJWKBytes []byte
		plain          []byte
		isErrCase      bool
	}{
		{privateKey, publicJWKBytes, []byte("things"), false},
		{privateKey, fakePublicJWKBytes, []byte("stuff"), true},
		{fakePrivateKey, publicJWKBytes, []byte("my pin code is ..."), true},
	}
	for _, testCase := range cases {
		var publicJWK RSAPublicJWK
		err = json.Unmarshal(testCase.publicJWKBytes, &publicJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		rsaPublicKey, err := JWKToPublicRSA(&publicJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		testRSAKeyPair(testCase.rsaPrivateKey, rsaPublicKey, testCase.plain, testCase.isErrCase, t)
	}
}

func TestRSAPrivateJWK(t *testing.T) {
	now := time.Now().UTC()
	expirationTime := now.Add(time.Hour)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	publicKey := privateKey.PublicKey
	privateJWK, err := RSAToPrivateJWK(privateKey, JWKID("test"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	privateJWKBytes, err := json.Marshal(privateJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePublicKey := fakePrivateKey.PublicKey
	fakePrivateJWK, err := RSAToPrivateJWK(fakePrivateKey, JWKID("test"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePrivateJWKBytes, err := json.Marshal(fakePrivateJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	cases := []struct {
		privateJWKBytes []byte
		rsaPublicKey    rsa.PublicKey
		plain           []byte
		isErrCase       bool
	}{
		{privateJWKBytes, publicKey, []byte("things"), false},
		{privateJWKBytes, fakePublicKey, []byte("stuff"), true},
		{fakePrivateJWKBytes, publicKey, []byte("my pin code is ..."), true},
	}
	for _, testCase := range cases {
		var privateJWK RSAPrivateJWK
		err = json.Unmarshal(testCase.privateJWKBytes, &privateJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		rsaPrivateKey, err := JWKToPrivateRSA(&privateJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		testRSAKeyPair(rsaPrivateKey, &testCase.rsaPublicKey, testCase.plain, testCase.isErrCase, t)
	}
}

func TestRSAPrivateJWKPublickKey(t *testing.T) {
	now := time.Now().UTC()
	expirationTime := now.Add(time.Hour)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	privateKeyJWK, err := RSAToPrivateJWK(privateKey, JWKID("test"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	publicJWK := privateKeyJWK.PublicKey()
	publicJWKBytes, err := json.Marshal(publicJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePublicKey := fakePrivateKey.PublicKey
	fakePublicJWK, err := RSAToPublicJWK(&fakePublicKey, JWKID("fake"), RSA15, &expirationTime)
	if err != nil {
		t.Errorf("%v", err)
	}
	fakePublicJWKBytes, err := json.Marshal(fakePublicJWK)
	if err != nil {
		t.Errorf("%v", err)
	}
	cases := []struct {
		rsaPrivateKey  *rsa.PrivateKey
		publicJWKBytes []byte
		plain          []byte
		isErrCase      bool
	}{
		{privateKey, publicJWKBytes, []byte("things"), false},
		{privateKey, fakePublicJWKBytes, []byte("stuff"), true},
		{fakePrivateKey, publicJWKBytes, []byte("my pin code is ..."), true},
	}
	for _, testCase := range cases {
		var publicJWK RSAPublicJWK
		err = json.Unmarshal(testCase.publicJWKBytes, &publicJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		rsaPublicKey, err := JWKToPublicRSA(&publicJWK)
		if err != nil {
			t.Errorf("%v", err)
		}
		testRSAKeyPair(testCase.rsaPrivateKey, rsaPublicKey, testCase.plain, testCase.isErrCase, t)
	}
}

func testRSAKeyPair(rsaPrivateKey *rsa.PrivateKey, rsaPublicKey *rsa.PublicKey, plain []byte, isErrCase bool, t *testing.T) {
	// test signature
	hash := sha256.Sum256([]byte(plain))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Errorf("%v", err)
	}
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
	switch {
	case err == nil && isErrCase:
		t.Error("expected err != nil")
	case err != nil && !isErrCase:
		t.Errorf("%v", err)
	}
	// test encryption
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, plain)
	if err != nil {
		t.Errorf("%v", err)
	}
	deciphered, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, cipher)
	switch {
	case err == nil && isErrCase:
		t.Error("expected err != nil")
	case err != nil && !isErrCase:
		t.Errorf("%v", err)
	}
	if !isErrCase && string(plain) != string(deciphered) {
		t.Errorf("expected %v got %v", string(plain), string(deciphered))
	}
}
