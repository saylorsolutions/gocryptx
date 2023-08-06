package passlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Lock will encrypt the payload with the given Key, and append the given Salt to the payload.
// Exposure of the Salt doesn't weaken the Key, since the passphrase is also required to arrive at the same Key.
// Salt exposure is required to be able to derive the same Key from the same passphrase.
// However, tampering with the Salt or the payload would prevent Unlock from recovering the Plaintext payload.
func Lock(key Key, salt Salt, data Plaintext) (Encrypted, error) {
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

// Unlock will decrypt the payload after stripping the Salt from the end of it.
// The Salt length is expected to match the Key length (which is enforced by KeyGenerator).
func Unlock(key Key, data Encrypted) (Plaintext, error) {
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
