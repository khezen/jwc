package jwc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestJWE(t *testing.T) {
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
	cases := []struct {
		plaintext   []byte
		JOSE        JOSEHeaders
		pubKey      crypto.PublicKey
		privKey     crypto.PrivateKey
		isErrorCase bool
	}{
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A128CBCHS256},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A192CBCHS384},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A256CBCHS512},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: RSA15, Encryption: A128CBCHS256},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A128GCM},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A192GCM},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A256GCM},
			publicKey,
			privateKey,
			false,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: PS256, Encryption: A128CBCHS256},
			publicKey,
			privateKey,
			true,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: PS256, Encryption: "POOP"},
			publicKey,
			privateKey,
			true,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A128CBCHS256},
			fakePublicKey,
			privateKey,
			true,
		},
		{
			[]byte("I have a message for you."),
			JOSEHeaders{Algorithm: ROAEP, Encryption: A128CBCHS256},
			publicKey,
			fakePrivateKey,
			true,
		},
	}
	for _, c := range cases {
		generatedJWE, err := NewJWE(&c.JOSE, c.pubKey, c.plaintext)
		switch {
		case err != nil && !c.isErrorCase:
			t.Error(err)
			continue
		case err != nil && c.isErrorCase:
			continue
		}
		compactJWE := generatedJWE.Compact()
		receivedJWE, err := ParseCompactJWE(compactJWE)
		switch {
		case err != nil && !c.isErrorCase:
			t.Error(err)
			continue
		case err != nil && c.isErrorCase:
			continue
		}
		plaintext, err := receivedJWE.Plaintext(c.privKey)
		switch {
		case err != nil && !c.isErrorCase:
			t.Error(err)
			continue
		case err != nil && c.isErrorCase:
			continue
		}
		if !bytes.EqualFold(c.plaintext, plaintext) {
			t.Errorf("expected %v, got %v", string(c.plaintext), string(plaintext))
		}
	}
}
