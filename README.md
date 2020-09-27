# string-password-encrypt

A an example library for encrypting and decrypting a string using a password. 

Was originally based heavily on "https://github.com/isfonzar/filecrypt", however
after some reading, I moved to a `scrypt` implementation rather than `pbkdf2`

**Caveat Emptor**: Whilst this does seem to follow the golang crypto fundamentals as far as I can tell, it's making
a lot of assumptions and using a lot of defaults. For example, it's using the `N` value of `32768` which is
the [recomendation for interactive logins as of 2017](https://blog.filippo.io/the-scrypt-parameters/)

## Example 

```go
import "github.com/petems/string-password-encrypt"

encryptedValue := EncryptValue("secret", "password123")
decryptedValue := DecryptValue(encryptedValue, "password123")
```

The value encypted value will be binary, so won't be useful for storing in a config file:

```go
import "github.com/petems/string-password-encrypt"

encryptedValue := EncryptValue("secret", "password123")
fmt.Print("Value: " + encryptedValue) // Value: f����V\�W(5`��{T�w_U�.k�?	)�:�fい��H��!�p����y}��|�n'���E�
```

So we've got two base64 encoding helper methods, so you can encode it to a [Base64 URL Encoding](https://tools.ietf.org/html/rfc4648) for easy storage in a config file

```go
import "github.com/petems/string-password-encrypt"

encryptedValue := EncryptValue("secret", "password123")

base64encrypted := Base64Encode([]byte(encryptedValue))

fmt.Print("Value: " + base64encrypted) // Value: qj_eW3AEIjcAjOkow0m6HjIFecjJQJ2l55ZL86eIu6SzG0CneqVYVA_RUWUufQbGwWdvDyJgDkOjEk5b2NpLwVLA

base64decrypted, err := Base64Decode(base64encrypted)

if err != nil {
	panic(err)
}

decryptedValue := DecryptValue([]byte(base64decrypted), "password123")
```