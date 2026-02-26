package pki_test

import (
	"bytes"
	"crypto/elliptic"
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

func TestEncryptECDSA(t *testing.T) {
	sender, err := pki.GenerateECDSAKeypair(elliptic.P521())
	require.NoError(t, err)
	receiver, err := pki.GenerateECDSAKeypair(elliptic.P521())
	require.NoError(t, err)
	testPayload := []byte("Test message")
	encrypted, err := pki.Encrypt(sender, receiver.Public(), testPayload)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(encrypted, testPayload))
	decrypted, err := pki.Decrypt(receiver, sender.Public(), encrypted)
	require.NoError(t, err)
	assert.Equal(t, pki.Plaintext(testPayload), decrypted)
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
