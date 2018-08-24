package jws

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
	JWTType = "JWT"
	// S256 - SHA-256
	S256 = "S256"
)

// Base64Encoding - encoding used to encode and decode tokens
var Base64Encoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// ErrJWTUnparsable -
var ErrJWTUnparsable = errors.New("ErrJWTUnparsable")

// NewJWT - creates a new JWT from the payload
func NewJWT(payload JWTPayload) *JWT {
	return &JWT{
		Header: JWTHeader{
			Algo: RS256,
			Type: JWTType,
		},
		Payload: payload,
	}
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
	Algo      string `json:"alg"`
	Type      string `json:"typ"`
	SignKeyID JWKID  `json:"kid"`
}

// JWTPayload - JWT payload
type JWTPayload struct {
	RegisteredClaims
	PrivateClaims
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
func (jwt *JWT) Encode(signKeyID JWKID, privateKey *rsa.PrivateKey) (string, error) {
	jwt.Header.SignKeyID = signKeyID
	// base64 encoding of the header
	headerJSON, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", err
	}
	headerBase64 := Base64Encoding.EncodeToString(headerJSON)
	payloadJSON, err := json.Marshal(jwt.Payload)
	if err != nil {
		return "", err
	}
	payloadBase64 := Base64Encoding.EncodeToString(payloadJSON)
	plainPart := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)
	hash := sha256.Sum256([]byte(plainPart))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	signatureBase64 := Base64Encoding.EncodeToString(signature)
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
func VerifyJWT(jwtStr string, publicKey *rsa.PublicKey) error {
	headerBase64, payloadBase64, signatureBase64, err := ExtractJWTParts(jwtStr)
	if err != nil {
		return err
	}
	return verifyJWT(headerBase64, payloadBase64, signatureBase64, publicKey)
}
func verifyJWT(headerBase64, payloadBase64, signatureBase64 string, publicKey *rsa.PublicKey) error {
	plainPart := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)
	hash := sha256.Sum256([]byte(plainPart))
	signature, err := Base64Encoding.DecodeString(signatureBase64)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
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
	headerJSON, err := Base64Encoding.DecodeString(headerBase64)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := Base64Encoding.DecodeString(payloadBase64)
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

// DecodeAndVerifyJWT - parse a base64 string into a jwt
func DecodeAndVerifyJWT(jwtStr string, publicKey *rsa.PublicKey) (*JWT, error) {
	headerBase64, payloadBase64, signatureBase64, err := ExtractJWTParts(jwtStr)
	if err != nil {
		return nil, err
	}
	err = verifyJWT(headerBase64, payloadBase64, signatureBase64, publicKey)
	if err != nil {
		return nil, err
	}
	return decodeJWT(headerBase64, payloadBase64)
}
