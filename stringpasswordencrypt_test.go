package stringpasswordencrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecryptValue(t *testing.T) {
	encryptedValue, err := Encrypt([]byte("password123"), []byte("secret"))

	assert.NoError(t, err)
	assert.NotEqual(t, encryptedValue, "secret")

	decryptedValue, err := Decrypt([]byte("password123"), []byte(encryptedValue))

	assert.NoError(t, err)

	assert.Equal(t, string(decryptedValue), "secret")
}

func TestEncryptMultipleTimesGivesDifferentValues(t *testing.T) {
	encryptedValue1, err := Encrypt([]byte("password123"), []byte("secret"))

	assert.NoError(t, err)

	encryptedValue2, err := Encrypt([]byte("password123"), []byte("secret"))

	assert.NoError(t, err)

	assert.NotEqual(t, encryptedValue1, encryptedValue2)
}
