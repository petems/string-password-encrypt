package stringpasswordencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

// Encrypt encrypts given byte data using a given password
func Encrypt(password, value string) (string, error) {
	key := []byte(password)
	data := []byte(value)

	key, salt, err := deriveKey(key, nil)
	if err != nil {
		return "", err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)

	return string(ciphertext), nil
}

// Decrypt decrypts given byte ciphertext using a given password
func Decrypt(password, value string) (string, error) {
	key := []byte(password)
	data := []byte(value)

	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := deriveKey(key, salt)
	if err != nil {
		return "", err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func Base64Encode(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	encrypted, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// https://blog.filippo.io/the-scrypt-parameters/
	// interactive logins: 2^15 — 1 << 15 — 32 768 — 86ms
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}
