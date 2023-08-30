# Simple HMAC Library written in Go

This is a simple HMAC library that implements the HMAC algorithm described in RFC2104.
Currently supports the generation of HMAC digests using MD5, SHA-1, SHA-256 and SHA-512 hashing primitives.

## Usage

Simply import the library and use the preferred hashing function:

```Go
  package main

  import (
    "fmt"
    "github.com/mcaimi/go-hmac/rfc2104"
    )

  const (
    KEY = "my-secret-key"
    MSG = "plaintext"
    )

  func main() {
    var digest []byte
    digest = rfc2104.Hmac([]byte(KEY), []byte(MSG), "sha1");

    fmt.Printf("%x\n", digest);
  }
```
