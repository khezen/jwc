package jwc

// https://tools.ietf.org/html/rfc7519

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// JWTType - jwt type
	jwtType = "JWT"
)

var (
	// JWTBase64Encoding - encoding used to encode and decode tokens
	JWTBase64Encoding = base64.URLEncoding.WithPadding(base64.NoPadding)
	// ErrJWTUnparsable -
	ErrJWTUnparsable = errors.New("ErrJWTUnparsable")
)

// NewJWT - creates a new JWT from the payload
func NewJWT(payload JWTPayload, signAlgo Algorithm) (*JWT, error) {
	if signAlgo != RS256 && signAlgo != PS256 {
		return nil, ErrUnsupportedAlgorithm
	}
	return &JWT{
		Header: JWTHeader{
			Algorithm: signAlgo,
			Type:      jwtType,
		},
		Payload: payload,
	}, nil
}

// TokenID -
type TokenID string

// JWT - JSON Web Token
type JWT struct {
	Header  JWTHeader
	Payload JWTPayload
}

// JWTHeader JWT header
type JWTHeader struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ,omitempty"`
	ContentType string    `json:"cty,omitempty"`
	SignKeyID   JWKID     `json:"kid,omitempty"`
	JWKURI      string    `json:"jku,omitempty"`
	Critical    []string  `jon:"crit,omitempty"`
	Zip         string    `json:"zip,omitempty"`
	JWK         *JWK      `json:"jwk,omitmepty"`
}

// JWTPayload - JWT payload
type JWTPayload struct {
	RegisteredClaims
	PrivateClaims `json:"priv"`
}

// RegisteredClaims - common data embedded in JWT
type RegisteredClaims struct {
	ExpirationTimestamp int64  `json:"exp,omitempty"`
	IssuedAtTimestamp   int64  `json:"iat,omitempty"`
	Issuer              string `json:"iss,omitempty"`
	Subject             string `json:"sub,omitempty"`
	Audiance            string `json:"aud,omitempty"`
}

// PrivateClaims - app specific data embedded in JWT
type PrivateClaims map[string]interface{}

// Encode - encode jwt into signed base64 string
func (jwt *JWT) Encode(signKeyID JWKID, signKey *rsa.PrivateKey) (string, error) {
	jwt.Header.SignKeyID = signKeyID
	// base64 encoding of the header
	headerJSON, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", err
	}
	headerBase64 := JWTBase64Encoding.EncodeToString(headerJSON)
	payloadJSON, err := json.Marshal(jwt.Payload)
	if err != nil {
		return "", err
	}
	payloadBase64 := JWTBase64Encoding.EncodeToString(payloadJSON)
	plainPart := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)
	hash := sha256.Sum256([]byte(plainPart))
	var signature []byte
	switch jwt.Header.Algorithm {
	case RS256:
		signature, err = rsa.SignPKCS1v15(rand.Reader, signKey, crypto.SHA256, hash[:])
		if err != nil {
			return "", err
		}
		break
	case PS256:
		signature, err = rsa.SignPSS(rand.Reader, signKey, crypto.SHA256, hash[:], nil)
		if err != nil {
			return "", err
		}
	}
	signatureBase64 := JWTBase64Encoding.EncodeToString(signature)
	encoded := fmt.Sprintf("%s.%s", plainPart, signatureBase64)
	return encoded, nil
}

// ExtractJWTParts return base64 encoded string of the header, the payload and the signature
func ExtractJWTParts(jwtStr string) (headerBase64, payloadBase64, signatureBase64 string, err error) {
	jwtStrSplit := strings.Split(jwtStr, ".")
	if len(jwtStrSplit) != 3 {
		return "", "", "", ErrJWTUnparsable
	}
	headerBase64, payloadBase64, signatureBase64 = jwtStrSplit[0], jwtStrSplit[1], jwtStrSplit[2]
	return headerBase64, payloadBase64, signatureBase64, nil

}

// VerifyJWT - validate the jwt integerity
func VerifyJWT(jwtStr string, signKey *rsa.PublicKey) error {
	headerBase64, payloadBase64, signatureBase64, err := ExtractJWTParts(jwtStr)
	if err != nil {
		return err
	}
	jwt, err := decodeJWT(headerBase64, payloadBase64)
	if err != nil {
		return err
	}
	return verifyJWT(headerBase64, payloadBase64, signatureBase64, signKey, jwt.Header.Algorithm)
}
func verifyJWT(headerBase64, payloadBase64, signatureBase64 string, publicKey *rsa.PublicKey, algo Algorithm) error {
	plainPart := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)
	hash := sha256.Sum256([]byte(plainPart))
	signature, err := JWTBase64Encoding.DecodeString(signatureBase64)
	if err != nil {
		return err
	}
	switch algo {
	case RS256:
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	case PS256:
		return rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil)
	default:
		return ErrUnsupportedAlgorithm
	}
}

// DecodeJWT - parse a base64 string into a jwt
func DecodeJWT(jwtStr string) (*JWT, error) {
	headerBase64, payloadBase64, _, err := ExtractJWTParts(jwtStr)
	if err != nil {
		return nil, err
	}
	return decodeJWT(headerBase64, payloadBase64)
}
func decodeJWT(headerBase64, payloadBase64 string) (*JWT, error) {
	headerJSON, err := JWTBase64Encoding.DecodeString(headerBase64)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := JWTBase64Encoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, err
	}
	var header JWTHeader
	err = json.Unmarshal(headerJSON, &header)
	if err != nil {
		return nil, err
	}
	var payload JWTPayload
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return nil, err
	}
	jwt := JWT{
		Header:  header,
		Payload: payload,
	}
	return &jwt, nil
}

// DecodeVerifyJWT - parse a base64 string into a jwt
func DecodeVerifyJWT(jwtStr string, signKey *rsa.PublicKey) (*JWT, error) {
	headerBase64, payloadBase64, signatureBase64, err := ExtractJWTParts(jwtStr)
	if err != nil {
		return nil, err
	}
	jwt, err := decodeJWT(headerBase64, payloadBase64)
	if err != nil {
		return nil, err
	}
	err = verifyJWT(headerBase64, payloadBase64, signatureBase64, signKey, jwt.Header.Algorithm)
	if err != nil {
		return nil, err
	}
	return jwt, nil
}
