package pki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

type decryptOptions struct {
	rsa struct {
		expectedLabel []byte
		hash          hash.Hash
	}
}

func (d *decryptOptions) apply(opts ...DecryptOption) error {
	d.rsa.hash = sha256.New()
	d.rsa.expectedLabel = nil
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return err
		}
	}
	return nil
}

type DecryptOption func(options *decryptOptions) error

func RSADecryptExpectLabel(expected []byte) DecryptOption {
	return func(options *decryptOptions) error {
		if expected == nil {
			return fmt.Errorf("empty RSA decryption label")
		}
		options.rsa.expectedLabel = expected
		return nil
	}
}

func RSADecryptHash(h hash.Hash) DecryptOption {
	return func(options *decryptOptions) error {
		if h == nil {
			return fmt.Errorf("nil hash for RSA decryption")
		}
		options.rsa.hash = h
		return nil
	}
}

func Decrypt(receiverKey crypto.PrivateKey, senderKey crypto.PublicKey, payload Encrypted, opts ...DecryptOption) (Plaintext, error) {
	switch k := receiverKey.(type) {
	case *rsa.PrivateKey:
		return DecryptRSA(k, payload, opts...)
	case *ed25519.PrivateKey:
		pub, ok := senderKey.(ed25519.PublicKey)
		if !ok {
			privPtr, ok := senderKey.(*ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected ed25519 sender key for ed25519 receiver key")
			}
			pub = *privPtr
		}
		return DecryptED25519(*k, pub, payload)
	case ed25519.PrivateKey:
		pub, ok := senderKey.(ed25519.PublicKey)
		if !ok {
			privPtr, ok := senderKey.(*ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("expected ed25519 sender key for ed25519 receiver key")
			}
			pub = *privPtr
		}
		return DecryptED25519(k, pub, payload)
	case *ecdsa.PrivateKey:
		pub, ok := senderKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ecdsa sender key for ecdsa receiver key")
		}
		return DecryptECDSA(k, pub, payload)
	default:
		return nil, errUnknownKeyType
	}
}

func DecryptRSA(priv *rsa.PrivateKey, payload Encrypted, opts ...DecryptOption) (Plaintext, error) {
	options := new(decryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(options.rsa.hash, rand.Reader, priv, payload, options.rsa.expectedLabel)
}

func DecryptECDSA(receiverKey *ecdsa.PrivateKey, senderKey *ecdsa.PublicKey, payload Encrypted, opts ...DecryptOption) (Plaintext, error) {
	options := new(decryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	if err := validECDHCurve(senderKey.Curve); err != nil {
		return nil, fmt.Errorf("sender key: %w", err)
	}
	if err := validECDHCurve(receiverKey.Curve); err != nil {
		return nil, fmt.Errorf("receiver key: %w", err)
	}
	ecdhPriv, err := receiverKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	ecdhPub, err := senderKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	secret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return aes256GcmDecrypt(secret[:aes256KeySize], payload)
}

func DecryptED25519(receiverKey ed25519.PrivateKey, senderKey ed25519.PublicKey, payload Encrypted, opts ...DecryptOption) (Plaintext, error) {
	options := new(decryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	xPriv := ed25519PrivateKeyToCurve25519(receiverKey)
	xPub, err := ed25519PublicKeyToCurve25519(senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sender key to montgomery point: %w", err)
	}
	secret, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return aes256GcmDecrypt(secret, payload)
}

func aes256GcmDecrypt(secret []byte, encrypted []byte) (Plaintext, error) {
	if len(secret) != aes256KeySize {
		return nil, fmt.Errorf("invalid key with length %d, expected %d", len(secret), aes256KeySize)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherText := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}
