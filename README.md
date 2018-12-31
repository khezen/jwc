# jwc

[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://godoc.org/github.com/khezen/jwc)
[![Build Status](http://img.shields.io/travis/khezen/jwc.svg?style=flat-square)](https://travis-ci.org/khezen/jwc) [![codecov](https://img.shields.io/codecov/c/github/khezen/jwc/master.svg?style=flat-square)](https://codecov.io/gh/khezen/jwc)
[![Go Report Card](https://goreportcard.com/badge/github.com/khezen/jwc?style=flat-square)](https://goreportcard.com/report/github.com/khezen/jwc)

* jws - JSON Web Signature
  * RSASSA-PSS + SHA256, recommended +
  * RSASSA-PKCS1-v1_5 + SHA256, recommended -
  
* jwe - JSON Web Encryption
  * RSA-OAEP, recommended +
  * RSAES-PKCS1-v1_5, recommended -