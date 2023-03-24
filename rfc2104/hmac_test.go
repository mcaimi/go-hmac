package rfc2104

import (
  "testing"
  "fmt"
)

// for test key and msg see https://www.rfc-editor.org/rfc/rfc2104.txt
const (
  TEST_KEY = "Jefe"
  TEST_MESSAGE = "what do ya want for nothing?"
  MD5_VALID_HASH = "750c783e6ab0b503eaa86e310a5db738"
  SHA1_VALID_HASH = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
  SHA256_VALID_HASH = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  SHA512_VALID_HASH = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
)

type testParams struct {
  k, m, hash string
  hashFunc func([]byte, []byte) []byte
}

var hmacByteTests = []testParams {
  testParams{TEST_KEY, TEST_MESSAGE, MD5_VALID_HASH, MD5Hmac},
  testParams{TEST_KEY, TEST_MESSAGE, SHA1_VALID_HASH, SHA1Hmac},
  testParams{TEST_KEY, TEST_MESSAGE, SHA256_VALID_HASH, SHA256Hmac},
  testParams{TEST_KEY, TEST_MESSAGE, SHA512_VALID_HASH, SHA512Hmac},
}

func TestHmac(t *testing.T) {
  var result string;

  // compute test cases
  for _, testCase := range hmacByteTests {
    result = fmt.Sprintf("%x", testCase.hashFunc([]byte(testCase.k), []byte(testCase.m)));
    if result != testCase.hash {
      t.Errorf("Computed Hash %q is does not match test vector %q", result, testCase.hash);
    }
    t.Logf("Passed test case with computed HMAC [%q]", result);
  }
}
