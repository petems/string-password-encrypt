package stringpasswordencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func EncryptValue(value string, password string) string {

	key := []byte(password)
	nonce := make([]byte, 12)

	// Randomizing the nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext := []byte(value)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Append the nonce to the end of file
	encryptedValue := append(ciphertext, nonce...)

	encryptedString := string(encryptedValue)

	return encryptedString
}

func DecryptValue(value string, password string) string {

	ciphertext := []byte(value)

	key := []byte(password)
	salt := ciphertext[len(ciphertext)-12:]
	str := hex.EncodeToString(salt)

	nonce, err := hex.DecodeString(str)

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	plaintextString := string(plaintext)

	return plaintextString
}
