package pkcs

import (
	"fmt"
	"testing"
)

func Example_verify() {
	hasher := new(PBKDF2Hasher)
	pwd := "testpwd"
	hash := hasher.EncodeDefault(pwd)
	ok, _ := hasher.Verify(pwd, hash)
	fmt.Printf("%v", ok)
	ok, _ = hasher.Verify("wrongPwd", hash)
	fmt.Printf("%v", ok)
	// Output:
	// truefalse
}

func BenchmarkEncode(b *testing.B) {
	hasher := new(PBKDF2Hasher)
	for i := 0; i < b.N; i++ {
		hasher.EncodeDefault("testpwd")
	}
}
