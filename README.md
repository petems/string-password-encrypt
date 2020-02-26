# string-password-encrypt

A library for encrypting and decrypting a string using a password. 

Heavily based on "https://github.com/isfonzar/filecrypt" - All credit due

## Example 

```go
import "github.com/petems/string-password-encrypt"

encryptedValue := EncryptValue("secret", "password123")
decruptedValue := DecryptValue(encryptedValue, "password123")
```