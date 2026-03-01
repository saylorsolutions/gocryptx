package pki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	aes256KeySize = 32
)

var (
	errUnknownKeyType   = errors.New("unknown key type")
	errIncompatibleKeys = errors.New("incompatible key types")
)

func ErrUnknownKeyType() error {
	return errUnknownKeyType
}

func ErrIncompatibleKeys() error {
	return errIncompatibleKeys
}

// Encrypted is the result of an encryption operation.
// Encrypted data can be passed over insecure channels without exposing its Plaintext equivalent.
type Encrypted []byte

// Plaintext is unprotected data that has not had any encryption operation applied to it.
type Plaintext []byte

type encryptOptions struct {
	rsa struct {
		label []byte
		hash  hash.Hash
	}
}

type EncryptOption func(options *encryptOptions) error

func (options *encryptOptions) apply(opts ...EncryptOption) error {
	options.rsa.label = nil
	options.rsa.hash = sha256.New()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return err
		}
	}
	return nil
}

func RSAEncryptLabel(label string) EncryptOption {
	return func(options *encryptOptions) error {
		label = strings.TrimSpace(label)
		if len(label) == 0 {
			return fmt.Errorf("empty label set for RSA encrypt")
		}
		options.rsa.label = []byte(label)
		return nil
	}
}

func RSAEncryptHash(h hash.Hash) EncryptOption {
	return func(options *encryptOptions) error {
		if h == nil {
			return fmt.Errorf("nil hash for RSA encryption")
		}
		options.rsa.hash = h
		return nil
	}
}

func Encrypt(senderKey crypto.PrivateKey, receiverKey crypto.PublicKey, payload Plaintext, opts ...EncryptOption) (Encrypted, error) {
	switch k := receiverKey.(type) {
	case *rsa.PublicKey:
		return EncryptRSA(k, payload, opts...)
	case ed25519.PublicKey:
		priv, ok := senderKey.(ed25519.PrivateKey)
		if !ok {
			privPtr, ok := senderKey.(*ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("expected ed25519 sender key for ed25519 receiver key")
			}
			priv = *privPtr
		}
		return EncryptED25519(priv, k, payload)
	case *ecdsa.PublicKey:
		priv, ok := senderKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected ecdsa sender key for ecdsa receiver key")
		}
		return EncryptECDSA(priv, k, payload)
	default:
		return nil, errUnknownKeyType
	}
}

func EncryptRSA(pub *rsa.PublicKey, payload Plaintext, opts ...EncryptOption) (Encrypted, error) {
	options := new(encryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(options.rsa.hash, rand.Reader, pub, payload, options.rsa.label)
}

func validECDHCurve(curve elliptic.Curve) error {
	switch curve {
	case elliptic.P256():
		fallthrough
	case elliptic.P384():
		fallthrough
	case elliptic.P521():
		return nil
	default:
		return fmt.Errorf("key curve cannot be used with ECDH")
	}
}

func EncryptECDSA(senderKey *ecdsa.PrivateKey, receiverKey *ecdsa.PublicKey, payload Plaintext, opts ...EncryptOption) (Encrypted, error) {
	options := new(encryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	if err := validECDHCurve(senderKey.Curve); err != nil {
		return nil, fmt.Errorf("sender key: %w", err)
	}
	if err := validECDHCurve(receiverKey.Curve); err != nil {
		return nil, fmt.Errorf("receiver key: %w", err)
	}
	ecdhPriv, err := senderKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	ecdhPub, err := receiverKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	secret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return aes256GcmEncrypt(secret[:aes256KeySize], payload)
}

func EncryptED25519(senderKey ed25519.PrivateKey, receiverKey ed25519.PublicKey, payload Plaintext, opts ...EncryptOption) (Encrypted, error) {
	options := new(encryptOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	xPriv := ed25519PrivateKeyToCurve25519(senderKey)
	xPub, err := ed25519PublicKeyToCurve25519(receiverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert receiver key to montgomery point: %w", err)
	}
	secret, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	return aes256GcmEncrypt(secret, payload)
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func aes256GcmEncrypt(secret []byte, payload Plaintext) (Encrypted, error) {
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, payload, nil), nil
}
