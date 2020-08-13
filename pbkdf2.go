package pkcs

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Iterations = 120000
	SaltSize   = 12
	Keylen     = 256 / 8
	Hasher     = "pbkdf2_sha256"
)

var (
	ErrHasher = errors.New("Invalid hash algorithm")
	ErrFmt    = errors.New("Format can not be parsed")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type PBKDF2Hasher struct {
}

//GenSalt Generate a cryptographically secure nonce salt in ASCII.
func (p PBKDF2Hasher) GenSalt(size int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	length := len(letters)
	salt := make([]rune, size)

	for i := range salt {
		salt[i] = letters[rand.Intn(length)]
	}
	return string(salt)
}

//EncodeDefault as defined in RFC 2898 and default args in const
func (p PBKDF2Hasher) EncodeDefault(pwd string) string {
	salt := p.GenSalt(SaltSize)
	digest := sha256.New

	// If dklen is None then the digest size of the hash algorithm hash_name is used, 256/8 = 32
	dk := pbkdf2.Key([]byte(pwd), []byte(salt), Iterations, Keylen, digest)
	hash := base64.StdEncoding.EncodeToString(dk)

	return Hasher + "$" + strconv.FormatInt(int64(Iterations), 10) + "$" + salt + "$" + hash
}

//Encode as defined in RFC 2898
func (p PBKDF2Hasher) Encode(pwd, salt string, iterations int) string {
	digest := sha256.New
	dk := pbkdf2.Key([]byte(pwd), []byte(salt), iterations, Keylen, digest)
	hash := base64.StdEncoding.EncodeToString(dk)

	return Hasher + "$" + strconv.FormatInt(int64(iterations), 10) + "$" + salt + "$" + hash
}

//Decode just splits string by $
func (p PBKDF2Hasher) Decode(str string) (dict map[string]string, err error) {
	dict = make(map[string]string, 3)
	eles := strings.Split(str, "$")
	if len(eles) != 4 {
		err = ErrFmt
		return
	}
	if eles[0] != Hasher {
		err = ErrHasher
		return
	}
	dict["iterations"] = eles[1]
	dict["salt"] = eles[2]
	dict["hash"] = eles[3]
	return
}

//Verify password with ciphertext
func (p *PBKDF2Hasher) Verify(pwd string, cipher string) (bool, error) {
	decoded, err := p.Decode(cipher)
	if err != nil {
		return false, err
	}

	iterations, err := strconv.Atoi(decoded["iterations"])
	if err != nil {
		return false, err
	}
	encoded := p.Encode(pwd, decoded["salt"], iterations)

	return cipher == encoded, nil
}
