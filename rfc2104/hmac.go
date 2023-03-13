package rfc2104

import (
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
)

// compute HMAC with MD5 hash algirithm
func MD5Hmac(key string, message string) []byte {
  var x hmac = newHmac(key, message, md5.New);
  x.digest();

  // return 
  return x.hmacBytes();
}

func SHA1Hmac(key string, message string) []byte {
  var x hmac = newHmac(key, message, sha1.New);
  x.digest();

  return x.hmacBytes();
}

func SHA256Hmac(key string, message string) []byte {
  var x hmac = newHmac(key, message, sha256.New);
  x.digest();

  return x.hmacBytes();
}

func SHA512Hmac(key string, message string) []byte {
  var x hmac = newHmac(key, message, sha512.New);
  x.digest();

  return x.hmacBytes();
}
