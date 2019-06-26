package jwc

// https://tools.ietf.org/html/rfc7517

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

const rsaType = "RSA"

var (
	// ErrJWKValueOutOfRangeParsingBigInt -
	ErrJWKValueOutOfRangeParsingBigInt = errors.New("ErrJWKValueOutOfRangeParsingBigInt")
)

// JWK - JSON Web Key
type JWK struct {
	Type                   string     `json:"kty"`
	ID                     JWKID      `json:"kid"`
	Usage                  Usage      `json:"use"`
	Algorithm              Algorithm  `json:"alg"`
	CertificateChainBase64 []string   `json:"x5c,omitempty"`
	ThumbprintBase64       string     `json:"x5t,omitempty"`
	ExpirationTime         *time.Time `json:"exp,omitempty"`
}

// JWKID - identify a specific jwk in a set
type JWKID string

// RSAPublicJWK - rsa public JSON web key
type RSAPublicJWK struct {
	JWK
	ModulusBase64        string `json:"n"`
	PublicExponentBase64 string `json:"e"`
}

// RSAToPublicJWK - takes rsa public key and returns it as JWK
func RSAToPublicJWK(publicKey *rsa.PublicKey, jwkID JWKID, algo Algorithm, expirationTime *time.Time) (*RSAPublicJWK, error) {
	publicX509DER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicX509DERBase64 := base64.RawStdEncoding.EncodeToString(publicX509DER)
	publicThumbprint := sha1.Sum(publicX509DER)
	publicThumbprintBase64 := base64.RawURLEncoding.EncodeToString(publicThumbprint[:])
	modulusBase64 := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	expBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(expBytes, uint32(publicKey.E))
	publicExponentBase64 := base64.RawURLEncoding.EncodeToString(expBytes)
	var usage Usage
	switch algo {
	case RS256, PS256:
		usage = Signing
		break
	case ROAEP, RSA15:
		usage = Encryption
	}
	publicJWK := RSAPublicJWK{
		JWK: JWK{
			CertificateChainBase64: []string{publicX509DERBase64},
			ThumbprintBase64:       publicThumbprintBase64,
			ExpirationTime:         expirationTime,
			ID:                     jwkID,
			Type:                   rsaType,
			Algorithm:              algo,
			Usage:                  usage,
		},
		ModulusBase64:        modulusBase64,
		PublicExponentBase64: publicExponentBase64,
	}
	return &publicJWK, nil
}

// PublicRSA - takes JWK and return it as rsa public key
func (jwk *RSAPublicJWK) PublicRSA() (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.ModulusBase64)
	if err != nil {
		return nil, err
	}
	modulus := new(big.Int)
	modulus = modulus.SetBytes(modulusBytes)
	publicExponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.PublicExponentBase64)
	if err != nil {
		return nil, err
	}
	publicExponent := int(binary.LittleEndian.Uint32(publicExponentBytes))
	rsaPublicKey := rsa.PublicKey{
		N: modulus,
		E: publicExponent,
	}
	return &rsaPublicKey, nil
}

// RSAPrivateJWK - rsa private JSON web key
type RSAPrivateJWK struct {
	JWK
	ModulusBase64           string `json:"n"`
	PublicExponentBase64    string `json:"e"`
	PrivateExponentBase64   string `json:"d"`
	FirstPrimeFactorBase64  string `json:"p"`
	SecondPrimeFactorBase64 string `json:"q"`
	// precomputed fields
	PrivateExpModFirstPrimeMinusOneBase64  string `json:"dp"` // d mod(p-1)
	PrivateExpModSecondPrimeMinusOneBase64 string `json:"dq"` // d mod(q-1)
	SecondPrimeInverseModFirstPrimeBase64  string `json:"qi"` // q^-1 mod p
}

// PublicKey -
func (jwk *RSAPrivateJWK) PublicKey() *RSAPublicJWK {
	return &RSAPublicJWK{
		JWK: JWK{
			Type:                   jwk.Type,
			ID:                     jwk.ID,
			Usage:                  jwk.Usage,
			Algorithm:              jwk.Algorithm,
			CertificateChainBase64: jwk.CertificateChainBase64,
			ThumbprintBase64:       jwk.ThumbprintBase64,
			ExpirationTime:         jwk.ExpirationTime,
		},
		ModulusBase64:        jwk.ModulusBase64,
		PublicExponentBase64: jwk.PublicExponentBase64,
	}
}

// RSAToPrivateJWK - takes rsa private key and returns it as JWK
func RSAToPrivateJWK(privateKey *rsa.PrivateKey, jwkID JWKID, algo Algorithm, expirationTime *time.Time) (*RSAPrivateJWK, error) {
	privateX509DER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateX509DERBase64 := base64.RawStdEncoding.EncodeToString(privateX509DER)
	privateThumbprint := sha1.Sum(privateX509DER)
	privateThumbprintBase64 := base64.RawURLEncoding.EncodeToString(privateThumbprint[:])
	modulusBase64 := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	expBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(expBytes, uint32(privateKey.PublicKey.E))
	publicExponentBase64 := base64.RawURLEncoding.EncodeToString(expBytes)
	privateExponentBase64 := base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes())
	firstPrimeFactor := privateKey.Primes[0]
	firstPrimeFactorBase64 := base64.RawURLEncoding.EncodeToString(firstPrimeFactor.Bytes())
	secondPrimeFactor := privateKey.Primes[1]
	secondPrimeFactorBase64 := base64.RawURLEncoding.EncodeToString(secondPrimeFactor.Bytes())
	// precomputed
	privateExpModFirstPrimeMinusOneBase64 := base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dp.Bytes())
	privateExpModSecondPrimeMinusOneBase64 := base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dq.Bytes())
	secondPrimeInverseModFirstPrimeBase64 := base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Qinv.Bytes())
	var usage Usage
	switch algo {
	case RS256, PS256:
		usage = Signing
		break
	case ROAEP, RSA15:
		usage = Encryption
	}
	privateJWK := RSAPrivateJWK{
		JWK: JWK{
			CertificateChainBase64: []string{privateX509DERBase64},
			ThumbprintBase64:       privateThumbprintBase64,
			ExpirationTime:         expirationTime,
			ID:                     jwkID,
			Type:                   rsaType,
			Algorithm:              algo,
			Usage:                  usage,
		},
		ModulusBase64:           modulusBase64,
		PublicExponentBase64:    publicExponentBase64,
		PrivateExponentBase64:   privateExponentBase64,
		FirstPrimeFactorBase64:  firstPrimeFactorBase64,
		SecondPrimeFactorBase64: secondPrimeFactorBase64,
		// precomputed
		PrivateExpModFirstPrimeMinusOneBase64:  privateExpModFirstPrimeMinusOneBase64,
		PrivateExpModSecondPrimeMinusOneBase64: privateExpModSecondPrimeMinusOneBase64,
		SecondPrimeInverseModFirstPrimeBase64:  secondPrimeInverseModFirstPrimeBase64,
	}
	return &privateJWK, nil
}

// PrivateRSA -  takes JWK and return it as rsa private key
func (jwk *RSAPrivateJWK) PrivateRSA() (*rsa.PrivateKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.ModulusBase64)
	if err != nil {
		return nil, err
	}
	modulus := new(big.Int)
	modulus = modulus.SetBytes(modulusBytes)
	publicExponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.PublicExponentBase64)
	if err != nil {
		return nil, err
	}
	publicExponent := int(binary.LittleEndian.Uint32(publicExponentBytes))
	privateExponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.PrivateExponentBase64)
	if err != nil {
		return nil, err
	}
	privateExponent := new(big.Int)
	privateExponent = privateExponent.SetBytes(privateExponentBytes)
	firstPrimeFactorBytes, err := base64.RawURLEncoding.DecodeString(jwk.FirstPrimeFactorBase64)
	if err != nil {
		return nil, err
	}
	firstPrimeFactor := new(big.Int)
	firstPrimeFactor = firstPrimeFactor.SetBytes(firstPrimeFactorBytes)
	secondPrimeFactorBytes, err := base64.RawURLEncoding.DecodeString(jwk.SecondPrimeFactorBase64)
	if err != nil {
		return nil, err
	}
	secondPrimeFactor := new(big.Int)
	secondPrimeFactor = secondPrimeFactor.SetBytes(secondPrimeFactorBytes)
	privateExpModFirstPrimeMinusOneBytes, err := base64.RawURLEncoding.DecodeString(jwk.PrivateExpModFirstPrimeMinusOneBase64)
	if err != nil {
		return nil, err
	}
	privateExpModFirstPrimeMinusOne := new(big.Int)
	privateExpModFirstPrimeMinusOne = privateExpModFirstPrimeMinusOne.SetBytes(privateExpModFirstPrimeMinusOneBytes)
	privateExpModSecondPrimeMinusOneBytes, err := base64.RawURLEncoding.DecodeString(jwk.PrivateExpModSecondPrimeMinusOneBase64)
	if err != nil {
		return nil, err
	}
	privateExpModSecondPrimeMinusOne := new(big.Int)
	privateExpModSecondPrimeMinusOne = privateExpModSecondPrimeMinusOne.SetBytes(privateExpModSecondPrimeMinusOneBytes)
	secondPrimeInverseModFirstPrimeBytes, err := base64.RawURLEncoding.DecodeString(jwk.SecondPrimeInverseModFirstPrimeBase64)
	if err != nil {
		return nil, err
	}
	secondPrimeInverseModFirstPrime := new(big.Int)
	secondPrimeInverseModFirstPrime = secondPrimeInverseModFirstPrime.SetBytes(secondPrimeInverseModFirstPrimeBytes)
	rsaPrivateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: modulus,
			E: publicExponent,
		},
		D:      privateExponent,
		Primes: []*big.Int{firstPrimeFactor, secondPrimeFactor},
		Precomputed: rsa.PrecomputedValues{
			Dp:   privateExpModFirstPrimeMinusOne,
			Dq:   privateExpModSecondPrimeMinusOne,
			Qinv: secondPrimeInverseModFirstPrime,
		},
	}
	return &rsaPrivateKey, nil
}
