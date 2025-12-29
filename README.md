# go-analyze/encoding

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-analyze/encoding/blob/master/LICENSE)
[![Tests - Main Push](https://github.com/go-analyze/encoding/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-analyze/encoding/actions/workflows/tests-main.yml)

Lightweight encoding packages for niche use cases not covered by Go's standard library. These packages are useful when you need compact encodings with specific character set requirements.

The API closely mirrors Go's `encoding/base64` and related packages, making it easy to transition to standard implementations if they become available. Packages will be deprecated and removed if equivalent functionality is added to the standard library.

## Installation

```bash
go get github.com/go-analyze/encoding@latest
```

## base85

The standard library's `encoding/ascii85` package only supports the Adobe/btoa variant with a fixed alphabet. This package provides base85 encoding with support for custom alphabets via `NewEncoding()`, following the same pattern as `encoding/base64`.

### RFC1924

RFC1924 defines a base85 encoding designed for compact representation of IPv6 addresses. It uses an 85-character alphabet consisting of `0-9`, `A-Z`, `a-z`, and 23 punctuation symbols, deliberately excluding characters that could cause parsing issues in various contexts (quotes, comma, period, slash, colon, brackets, and backslash).

```go
package main

import (
	"fmt"

	"github.com/go-analyze/encoding/base85"
)

func main() {
	data := []byte("Hello, World!")

	// Encode
	encoded := base85.RFC1924.EncodeToString(data)
	fmt.Println(encoded) // NM&qnZ!92JZ*pv8Ap

	// Decode
	decoded, err := base85.RFC1924.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decoded)) // Hello, World!
}
```

### Custom Alphabets

Create encodings with custom 85-character alphabets:

```go
enc := base85.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
encoded := enc.EncodeToString(data)
```
