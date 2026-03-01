package pki_test

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/saylorsolutions/gocryptx/pkg/pki"
	"github.com/stretchr/testify/require"
)

func TestSignRSA(t *testing.T) {
	rsaSigner, err := pki.GenerateRSAKeypair()
	require.NoError(t, err)
	payload := pki.Plaintext("Test payload")
	sig, err := pki.Sign(rsaSigner, payload, pki.SignRSAHash(crypto.SHA256))
	require.NoError(t, err)
	t.Log(sig.Base64())
	verified, err := pki.Verify(rsaSigner.Public(), payload, sig /* sha256 is the default */)
	require.NoError(t, err)
	require.True(t, verified, "Signature should be considered valid")
}

func TestSignECDSA(t *testing.T) {
	curves := map[string]elliptic.Curve{
		"P224": elliptic.P224(),
		"P256": elliptic.P256(),
		"P384": elliptic.P384(),
		"P521": elliptic.P521(),
	}
	for name, curve := range curves {
		t.Run(name, func(t *testing.T) {
			ecdsaSigner, err := pki.GenerateECDSAKeypair(curve)
			require.NoError(t, err)
			payload := pki.Plaintext("Test payload")
			sig, err := pki.Sign(ecdsaSigner, payload, pki.SignECDSAHash(crypto.SHA256))
			require.NoError(t, err)
			t.Log(sig.Base64())
			verified, err := pki.Verify(ecdsaSigner.Public(), payload, sig /* sha256 is the default */)
			require.NoError(t, err)
			require.True(t, verified, "Signature should be considered valid")
		})
	}
}

func TestSignEd25519(t *testing.T) {
	edSigner, err := pki.GenerateED25519Keypair()
	require.NoError(t, err)
	payload := pki.Plaintext("Test payload")
	sig, err := pki.Sign(edSigner, payload)
	require.NoError(t, err)
	t.Log(sig.Base64())
	verified, err := pki.Verify(edSigner.Public(), payload, sig)
	require.NoError(t, err)
	require.True(t, verified, "Signature should be considered valid")
}
