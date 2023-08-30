package rfc2104

// generic hmac function
func Hmac(key []byte, message []byte, algorithm string) []byte {
  var x HMAC = NewHmac(key, message, algorithm);
  x.Digest();

  // return
  return x.HmacBytes();
}

