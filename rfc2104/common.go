package rfc2104

import (
  "hash"
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
)

// supported algorithms
func getHashFunc(algo string) func() hash.Hash {
  var algorithm_table = map[string]func() hash.Hash{
    "md5" : md5.New,
    "sha1" : sha1.New,
    "sha256" : sha256.New,
    "sha512" : sha512.New,
  };

  return algorithm_table[algo];
}

