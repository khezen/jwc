package jwc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

// https://tools.ietf.org/html/rfc7516

// JWE - json web encrypted content
type JWE struct {
	JWEHeader
	EncryptedKey         []byte
	InitializationVector []byte
	CipherText           []byte
	AuthenticationTag    []byte
}

// JWEHeader JWE header
type JWEHeader struct {
	Algorithm   Algorithm `json:"alg"`
	Encryption  string    `json:"enc"`
	Type        string    `json:"typ,omitempty"`
	ContentType string    `json:"cty,omitempty"`
	EncKeyID    JWKID     `json:"kid,omitempty"`
}

// NewJWE -
func NewJWE(header *JWEHeader, pubKey *rsa.PublicKey) ([]byte, error) {
	cek := make([]byte, 64)
	_, err := rand.Read(cek)
	if err != nil {
		return nil, err
	}
	var (
		encryptedKey []byte
		rng          = rand.Reader
	)
	switch header.Algorithm {
	case ROAEP:
		encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rng, pubKey, cek, nil)
		break
	case RSA15:
		encryptedKey, err = rsa.EncryptPKCS1v15(rng, pubKey, cek)
		break
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	encryptedKeyBase64 := base64.URLEncoding.EncodeToString(encryptedKey)
	initVector := make([]byte, 12)
	_, err = rand.Read(initVector)
	if err != nil {
		return nil, err
	}
	initVectorBase64 = base64.URLEncoding.EncodeToString(initVector)
	switch header.Encryption {
	default:
		return nil, ErrUnsupportedEncryption
	}
	return nil, nil
}

// ParseJWE -
func ParseJWE(jwe []byte, privKey *rsa.PrivateKey) (*JWE, error) {
	return nil, nil
}

// This example encrypts the plaintext "The true sign of intelligence is
//    not knowledge but imagination." to the recipient.

//    The following example JWE Protected Header declares that:

//    o  The Content Encryption Key is encrypted to the recipient using the
//       RSAES-OAEP [RFC3447] algorithm to produce the JWE Encrypted Key.

//    o  Authenticated encryption is performed on the plaintext using the
//       AES GCM [AES] [NIST.800-38D] algorithm with a 256-bit key to
//       produce the ciphertext and the Authentication Tag.

//      {"alg":"RSA-OAEP","enc":"A256GCM"}

//    Encoding this JWE Protected Header as BASE64URL(UTF8(JWE Protected
//    Header)) gives this value:

//      eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ

//    The remaining steps to finish creating this JWE are:

//    o  Generate a random Content Encryption Key (CEK).

//    o  Encrypt the CEK with the recipient's public key using the RSAES-
//       OAEP algorithm to produce the JWE Encrypted Key.

//    o  Base64url-encode the JWE Encrypted Key.

//    o  Generate a random JWE Initialization Vector.

//    o  Base64url-encode the JWE Initialization Vector.

//    o  Let the Additional Authenticated Data encryption parameter be
//       ASCII(BASE64URL(UTF8(JWE Protected Header))).

//    o  Perform authenticated encryption on the plaintext with the AES GCM
//       algorithm using the CEK as the encryption key, the JWE
//       Initialization Vector, and the Additional Authenticated Data
//       value, requesting a 128-bit Authentication Tag output.

//    o  Base64url-encode the ciphertext.

//    o  Base64url-encode the Authentication Tag.

//    o  Assemble the final representation: The Compact Serialization of
//       this result is the string BASE64URL(UTF8(JWE Protected Header)) ||
//       '.' || BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE
//       Initialization Vector) || '.' || BASE64URL(JWE Ciphertext) || '.'
//       || BASE64URL(JWE Authentication Tag).

//    The final result in this example (with line breaks for display
//    purposes only) is:

//      eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
//      OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
//      ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
//      Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
//      mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
//      1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
//      6UklfCpIMfIjf7iGdXKHzg.
//      48V1_ALb6US04U3b.
//      5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
//      SdiwkIr3ajwQzaBtQD_A.
//      XFBoMYUZodetZdvTiFvSkQ
