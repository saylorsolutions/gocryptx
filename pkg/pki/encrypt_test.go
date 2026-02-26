package pki_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/saylorsolutions/gocryptx/pkg/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptRSA(t *testing.T) {
	sender, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	receiver, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	testPayload := []byte("Test message")
	encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(encrypted, testPayload))
	decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted)
	require.NoError(t, err)
	assert.Equal(t, pki.Plaintext(testPayload), decrypted)
}

func TestRSAEncryptLabel(t *testing.T) {
	sender, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	receiver, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	testPayload := []byte("Test message")
	encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload, pki.RSAEncryptLabel("test"))
	t.Run("Without label", func(t *testing.T) {
		_, err := pki.Decrypt(receiver, sender.Public(), encrypted)
		require.Error(t, err, "Should be an error since the label doesn't match")
	})
	t.Run("With label", func(t *testing.T) {
		decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted, pki.RSADecryptExpectLabel("test"))
		require.NoError(t, err)
		assert.Equal(t, pki.Plaintext(testPayload), decrypted)
	})
}

func TestRSAEncryptHash(t *testing.T) {
	sender, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	receiver, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	testPayload := []byte("Test message")
	encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload, pki.RSAEncryptHash(sha512.New()))
	t.Run("Wrong hash", func(t *testing.T) {
		_, err := pki.Decrypt(receiver, sender.Public(), encrypted, pki.RSADecryptHash(sha256.New()))
		require.Error(t, err, "Should be an error since a different hash function was used")
	})
	t.Run("With correct hash", func(t *testing.T) {
		decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted, pki.RSADecryptHash(sha512.New()))
		require.NoError(t, err)
		assert.Equal(t, pki.Plaintext(testPayload), decrypted)
	})
}

func TestEncryptECDSA(t *testing.T) {
	tests := map[string]elliptic.Curve{
		"P521": elliptic.P521(),
		"P384": elliptic.P384(),
		"P256": elliptic.P256(),
	}
	for name, curve := range tests {
		t.Run(name, func(t *testing.T) {
			sender, err := pki.GenerateECDSAKeypair(curve)
			require.NoError(t, err)
			receiver, err := pki.GenerateECDSAKeypair(curve)
			require.NoError(t, err)
			testPayload := []byte("Test message")
			encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload)
			require.NoError(t, err)
			assert.False(t, bytes.Contains(encrypted, testPayload))
			decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted)
			require.NoError(t, err)
			assert.Equal(t, pki.Plaintext(testPayload), decrypted)
		})
	}
}

func TestEncryptECDSA_UnsupportedCurve(t *testing.T) {
	sender, err := pki.GenerateECDSAKeypair(elliptic.P224())
	require.NoError(t, err)
	receiver, err := pki.GenerateECDSAKeypair(elliptic.P224())
	require.NoError(t, err)
	testPayload := []byte("Test message")
	_, err = pki.Encrypt(sender, receiver.Public(), testPayload)
	require.Error(t, err, "Should be an error since P224 is considered insufficient security for ECDH")
}

func TestEncryptED25519(t *testing.T) {
	sender, err := pki.GenerateED25519Keypair()
	require.NoError(t, err)
	receiver, err := pki.GenerateED25519Keypair()
	require.NoError(t, err)
	testPayload := []byte("Test message")
	encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(encrypted, testPayload))
	decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted)
	require.NoError(t, err)
	assert.Equal(t, pki.Plaintext(testPayload), decrypted)
}
