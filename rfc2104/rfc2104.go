package rfc2104

// calculate HMAC as per RFC2104 specification
import (
  "hash"
  "fmt"
)

// bytes used to perform XOR operations on key material
const INNER_PAD byte = 0x36
const OUTER_PAD byte = 0x5C

// hmac object type
type HMAC struct {
  key, message, inner, outer []byte;
  computer hash.Hash;
  blocklen, keylen, msglen int;
  hmacAlgorithm string;
}

// 
// Create new HMAC computer
// Parameters:
// key: the hash key material
// message: the plaintext message of which the function will compute the HMAC digest
// difest_f: hash cpomputer init function
//
// HMAC is computed as
// HMAC = HASH_FUNC((key xor outer_pad) + HASH_FUNC((key xor inner_pad) + message))
// 
func NewHmac(key []byte, message []byte, algorithm string) HMAC {
  var x HMAC;

  // convert key and message strings to byte arrays
  x.key = key;
  x.message = message;
  // compute byte array lenghts
  x.keylen = len(x.key);
  x.msglen = len(x.message);

  // instantiate the digest computer with the selected hashing algorithm function
  x.computer = getHashFunc(algorithm)();
  x.blocklen = x.computer.BlockSize();
  // allocate space for computed inner and outer hash bytes
  x.inner = make([]byte, x.blocklen);
  x.outer = make([]byte, x.blocklen);

  // return the hmac object
  return x;
}

// Calculate the HMAC digest value
func (h *HMAC) Digest() {
  // check key length: if greater than blocksize, then hash it
  // to keep it below the blocksize length
  if (h.keylen > h.blocklen) {
    h.computer.Write(h.key);
    h.key = h.computer.Sum(nil);
  }

  // prepare inner pad
  copy(h.inner, h.key);
  // perform XOR operations on key material
  for i := range h.inner {
    h.inner[i] ^= INNER_PAD;
  }
  // cacluate inner hash
  h.computer.Write(h.inner);
  h.computer.Write(h.message);
  inner_hash := h.computer.Sum(nil);
  h.computer.Reset();

  // prepare outer pad
  copy(h.outer, h.key);
  // perform XOR operation on key material
  for i := range h.outer {
    h.outer[i] ^= OUTER_PAD;
  }
  // calculate HMAC digest
  h.computer.Write(h.outer);
  h.computer.Write(inner_hash);
}

// get hmac digest bytes
func (h *HMAC) HmacBytes() []byte {
  // return the hmac digest bytes as a byte array
  return h.computer.Sum(nil);
}

// get hmac digest in string format
func (h *HMAC) HmacString() string {
  // return the hmac digest in string format
  return fmt.Sprintf("%x", h.computer.Sum(nil));
}
