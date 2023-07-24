package passlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Lock will encrypt the payload with the given key, and append the given salt to the payload.
// Exposure of the salt doesn't weaken the key, since the passphrase is also required to arrive at the same key.
// However, tampering with the salt or the payload would prevent Unlock from recovering the plaintext payload.
func Lock(key, salt, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherText := append(gcm.Seal(nonce, nonce, data, nil), salt...)
	return cipherText, nil
}

// Unlock will decrypt the payload after stripping the salt from the end of it.
// The salt length is expected to match the key length (which is enforced by KeyGenerator).
func Unlock(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	cipherText = cipherText[:len(cipherText)-len(key)]
	return gcm.Open(nil, nonce, cipherText, nil)
}
