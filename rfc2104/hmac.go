package rfc2104

import (
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
)

// compute HMAC with MD5 hash algirithm
func MD5Hmac(key []byte, message []byte) []byte {
  var x hmac = newHmac(key, message, md5.New);
  x.digest();

  // return 
  return x.hmacBytes();
}

// compute HMAC with SHA-1 hash algirithm
func SHA1Hmac(key []byte, message []byte) []byte {
  var x hmac = newHmac(key, message, sha1.New);
  x.digest();

  return x.hmacBytes();
}

// compute HMAC with SHA-256 hash algirithm
func SHA256Hmac(key []byte, message []byte) []byte {
  var x hmac = newHmac(key, message, sha256.New);
  x.digest();

  return x.hmacBytes();
}

// compute HMAC with SHA-512 hash algirithm
func SHA512Hmac(key []byte, message []byte) []byte {
  var x hmac = newHmac(key, message, sha512.New);
  x.digest();

  return x.hmacBytes();
}
