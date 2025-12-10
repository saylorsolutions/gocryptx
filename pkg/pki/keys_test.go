package pki

import (
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateKeypair(t *testing.T) {
	tests := map[string]func(t *testing.T) Keypair{
		"RSA": func(t *testing.T) Keypair {
			kp, err := GenerateRSAKeypair()
			require.NoError(t, err)
			return kp
		},
		"ECDSA": func(t *testing.T) Keypair {
			curves := []elliptic.Curve{elliptic.P224(), elliptic.P384(), elliptic.P256(), elliptic.P521()}
			i, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt))
			require.NoError(t, err)
			i = new(big.Int).Mod(i, big.NewInt(int64(len(curves))))
			kp, err := GenerateECDSAKeypair(curves[int(i.Int64())])
			require.NoError(t, err)
			return kp
		},
		"ED25519": func(t *testing.T) Keypair {
			kp, err := GenerateED25519Keypair()
			require.NoError(t, err)
			return kp
		},
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, ValidateKeypair(fn(t)))
		})
	}
}

func TestLoadKeypairFromFile(t *testing.T) {
	tests := map[string]struct {
		getKeypair func(*testing.T) Keypair
	}{
		"RSA": {
			getKeypair: func(t *testing.T) Keypair {
				kp, err := GenerateRSAKeypair()
				require.NoError(t, err)
				return kp
			},
		},
		"ECDSA": {
			getKeypair: func(t *testing.T) Keypair {
				kp, err := GenerateECDSAKeypair(elliptic.P384())
				require.NoError(t, err)
				return kp
			},
		},
		"ED25519": {
			getKeypair: func(t *testing.T) Keypair {
				kp, err := GenerateED25519Keypair()
				require.NoError(t, err)
				return kp
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			kp := tc.getKeypair(t)
			require.NoError(t, ValidateKeypair(kp))
			tmp, err := os.MkdirTemp("", name+"-*")
			t.Cleanup(func() {
				_ = os.RemoveAll(tmp)
				t.Log("Removed temp directory", tmp)
			})
			require.NoError(t, err)
			privPath := filepath.Join(tmp, "priv")
			pubPath := filepath.Join(tmp, "pub")
			privData, err := PrivateKeyAsBytes(kp)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(privPath, privData, 0600))
			pubData, err := PublicKeyAsBytes(kp)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(pubPath, pubData, 0600))

			_, err = LoadKeypairFromFile(privPath, pubPath)
			require.NoError(t, err)
		})
	}
}
