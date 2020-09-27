package stringpasswordencrypt

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecryptValue(t *testing.T) {
	data := []struct {
		password string
		secret   string
	}{
		{"password123", "secret"},
		{"really-long-password-over-16-characters", "secret"},
		{"really-long-password-over-16-characters", "really-long-secret-over-16-characters"},
	}
	for _, d := range data {
		encryptedValue, err := Encrypt(d.password, d.secret)

		assert.NoError(t, err)
		assert.NotEqual(t, encryptedValue, d.secret)

		decryptedValue, err := Decrypt(d.password, encryptedValue)

		assert.NoError(t, err)

		assert.Equal(t, string(decryptedValue), d.secret)
	}
}

func TestEncryptMultipleTimesGivesDifferentEncryptedValues(t *testing.T) {
	data := []struct {
		password string
		secret   string
	}{
		{"password123", "secret"},
		{"really-long-password-over-16-characters", "secret"},
		{"really-long-password-over-16-characters", "really-long-secret-over-16-characters"},
	}
	for _, d := range data {
		encryptedValue1, err := Encrypt(d.password, d.secret)
		assert.NoError(t, err)
		encryptedValue2, err := Encrypt(d.password, d.secret)
		assert.NoError(t, err)

		assert.NotEqual(t, encryptedValue1, encryptedValue2)

		decryptedValue1, err := Decrypt(d.password, encryptedValue1)
		assert.NoError(t, err)
		decryptedValue2, err := Decrypt(d.password, encryptedValue2)
		assert.NoError(t, err)

		assert.Equal(t, decryptedValue1, decryptedValue2)
	}
}

func TestDecryptInvalidPassword(t *testing.T) {
	data := []struct {
		password string
		secret   string
	}{
		{"password123", "secret"},
		{"really-long-password-over-16-characters", "secret"},
		{"really-long-password-over-16-characters", "really-long-secret-over-16-characters"},
	}
	for _, d := range data {
		encryptedValue, err := Encrypt(d.password, d.secret)

		assert.NoError(t, err)
		assert.NotEqual(t, encryptedValue, d.secret)

		emptyString, err := Decrypt("invalid-password", encryptedValue)

		assert.Equal(t, emptyString, "")

		assert.EqualError(t, err, "cipher: message authentication failed")
	}
}

func TestEncryptingAndBase64Encoding(t *testing.T) {
	data := []struct {
		password string
		secret   string
	}{
		{"password123", "secret"},
		{"really-long-password-over-16-characters", "secret"},
		{"really-long-password-over-16-characters", "really-long-secret-over-16-characters"},
	}
	for _, d := range data {
		encryptedValue, err := Encrypt(d.password, d.secret)

		assert.NoError(t, err)
		assert.NotEqual(t, encryptedValue, d.secret)

		base64encrypted := Base64Encode(encryptedValue)

		assert.Regexp(t, regexp.MustCompile("^[0-9a-zA-Z_=-]+$"), string(base64encrypted))

		base64decrypted, err := Base64Decode(base64encrypted)

		assert.NoError(t, err)

		decryptedValue, err := Decrypt(d.password, base64decrypted)

		assert.NoError(t, err)

		assert.Equal(t, string(decryptedValue), d.secret)
	}
}

// This is an example of encrypting and decrypting a value with a password
func Example() {
	encryptedValue, _ := Encrypt("password123", "secret")
	decryptedValue, _ := Decrypt("password123", encryptedValue)
	fmt.Println(string(decryptedValue))
	// Output: secret
}
