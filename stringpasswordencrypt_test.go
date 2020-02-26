package stringpasswordencrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecryptValue(t *testing.T) {
	encryptedValue := EncryptValue("secret", "password123")

	assert.NotEqual(t, encryptedValue, "secret")

	decruptedValue := DecryptValue(encryptedValue, "password123")

	assert.Equal(t, decruptedValue, "secret")
}

func TestEncryptMultipleTimesGivesDifferentValues(t *testing.T) {
	encryptedValue1 := EncryptValue("secret", "password123")
	encryptedValue2 := EncryptValue("secret", "password123")

	assert.NotEqual(t, encryptedValue1, encryptedValue2)
}
