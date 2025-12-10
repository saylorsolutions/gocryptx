package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ed25519"
)

// Keypair is an abstraction for a public/private key pair.
// Both embedded interfaces expose a Public method that may be used to get the public key.
type Keypair interface {
	crypto.Signer
}

// GenerateRSAKeypair will generate an RSA 4096 keypair for use with other operations.
func GenerateRSAKeypair() (Keypair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	priv.Precompute()
	if err := ValidateKeypair(priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func GenerateECDSAKeypair(curve elliptic.Curve) (Keypair, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair with curve '%s': %w", curve.Params().Name, err)
	}
	if err := ValidateKeypair(priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func GenerateED25519Keypair() (Keypair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ED25519 key pair: %w", err)
	}
	if err := ValidateKeypair(&priv); err != nil {
		return nil, err
	}
	return &priv, nil
}

// ValidateKeypair is used to verify that the private and public keys are associated with each other.
func ValidateKeypair(pair Keypair) error {
	switch priv := pair.(type) {
	case *rsa.PrivateKey:
		orig, err := randomSignatureTarget()
		if err != nil {
			return err
		}
		pub := priv.PublicKey
		hashed := sha256.Sum256(orig)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
		if err != nil {
			return fmt.Errorf("failed to sign data for verification: %w", err)
		}
		if err := rsa.VerifyPKCS1v15(&pub, crypto.SHA256, hashed[:], sig); err != nil {
			return fmt.Errorf("failed to verify private and public key association by signature: %w", err)
		}
		return nil
	case *ecdsa.PrivateKey:
		orig, err := randomSignatureTarget()
		if err != nil {
			return err
		}
		hash := sha256.Sum256(orig)
		pub := priv.PublicKey
		sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
		if err != nil {
			return fmt.Errorf("failed to sign data for verification: %w", err)
		}
		if !ecdsa.VerifyASN1(&pub, hash[:], sig) {
			return fmt.Errorf("failed to verify private and public key association by signature")
		}
		return nil
	case *ed25519.PrivateKey:
		orig, err := randomSignatureTarget()
		if err != nil {
			return err
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("no public key associated with ed25519 private key")
		}
		sig := ed25519.Sign(*priv, orig)
		if !ed25519.Verify(pub, orig, sig) {
			return fmt.Errorf("failed to verify private and public key association by signature")
		}
		return nil
	case *ed25519KeyPair:
		orig, err := randomSignatureTarget()
		if err != nil {
			return err
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("no public key associated with ed25519 private key")
		}
		sig := ed25519.Sign(*priv.PrivateKey, orig)
		if !ed25519.Verify(pub, orig, sig) {
			return fmt.Errorf("failed to verify private and public key association by signature")
		}
		return nil
	default:
		return NotSupported("private key algorithm is not supported")
	}
}

func randomSignatureTarget() ([]byte, error) {
	orig := make([]byte, 255)
	_, err := rand.Read(orig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random data for signature verification: %w", err)
	}
	return orig, nil
}

// LoadKeypairFromFile will attempt to read the given data files as a private and public key pair.
// If they are PEM encoded, then they will be decoded from the block before attempting to load them.
func LoadKeypairFromFile(priv, pub string) (Keypair, error) {
	privData, err := os.ReadFile(priv) //nolint:gosec // This is intended to allow arbitrary file reads.
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file '%s': %w", priv, err)
	}
	pubData, err := os.ReadFile(pub) //nolint:gosec // This is intended to allow arbitrary file reads.
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file '%s': %w", pub, err)
	}
	privPem, _ := pem.Decode(privData)
	if privPem != nil {
		privData = privPem.Bytes
	}
	pubPem, _ := pem.Decode(pubData)
	if pubPem != nil {
		pubData = pubPem.Bytes
	}
	var (
		errs    []error
		loaders = []kpLoader{
			loadRSAKeypair,
			loadECDSAKeypair,
			loadED25519Keypair,
		}
	)
	for _, loader := range loaders {
		kp, err := loader(privData, pubData)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := ValidateKeypair(kp); err != nil {
			return nil, err
		}
		return kp, nil
	}

	return nil, errors.Join(errs...)
}

type kpLoader = func(privData, pubData []byte) (Keypair, error)

type publicKeyTypes interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

func loadPublicKey[T publicKeyTypes](pubData []byte) (T, error) {
	var (
		a   any
		err error
	)
	if a, err = x509.ParsePKIXPublicKey(pubData); err != nil {
		if a, err = x509.ParsePKCS1PublicKey(pubData); err != nil {
			return nil, fmt.Errorf("failed to parse public key")
		}
	}
	if pub, ok := a.(T); ok {
		return pub, nil
	}
	return nil, fmt.Errorf("failed to parse public key")
}

type privateKeyTypes interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

func loadPrivateKey[T privateKeyTypes](privData []byte) (T, error) {
	var (
		a   any
		err error
	)
	if a, err = x509.ParsePKCS1PrivateKey(privData); err != nil {
		if a, err = x509.ParsePKCS8PrivateKey(privData); err != nil {
			if a, err = x509.ParseECPrivateKey(privData); err != nil {
				return nil, fmt.Errorf("failed to parse private key")
			}
		}
	}
	if priv, ok := a.(T); ok {
		return priv, nil
	}
	return nil, fmt.Errorf("failed to parse private key")
}

func loadRSAKeypair(privData, pubData []byte) (Keypair, error) {
	priv, err := loadPrivateKey[*rsa.PrivateKey](privData)
	if err != nil {
		return nil, err
	}
	pub, err := loadPublicKey[*rsa.PublicKey](pubData)
	if err != nil {
		return nil, err
	}
	priv.PublicKey = *pub
	if err := ValidateKeypair(priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func loadECDSAKeypair(privData, pubData []byte) (Keypair, error) {
	privKey, err := loadPrivateKey[*ecdsa.PrivateKey](privData)
	if err != nil {
		return nil, err
	}
	pubKey, err := loadPublicKey[*ecdsa.PublicKey](pubData)
	if err != nil {
		return nil, err
	}
	privKey.PublicKey = *pubKey
	if err := ValidateKeypair(privKey); err != nil {
		return nil, err
	}
	return privKey, nil
}

var _ Keypair = (*ed25519KeyPair)(nil)

type ed25519KeyPair struct {
	*ed25519.PrivateKey
	pub ed25519.PublicKey
}

func (kp ed25519KeyPair) Public() crypto.PublicKey {
	return kp.pub
}

func loadED25519Keypair(privData, pubData []byte) (Keypair, error) {
	privKey, err := loadPrivateKey[ed25519.PrivateKey](privData)
	if err != nil {
		return nil, err
	}
	pubKey, err := loadPublicKey[ed25519.PublicKey](pubData)
	if err != nil {
		return nil, err
	}
	kp := &ed25519KeyPair{PrivateKey: &privKey, pub: pubKey}
	if err := ValidateKeypair(kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// PrivateKeyAsBytes encodes the private key in a PKCS #8 format.
// Other formats result in a NotSupported error.
func PrivateKeyAsBytes(keys Keypair) ([]byte, error) {
	switch priv := keys.(type) {
	case *rsa.PrivateKey:
		data, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA private key to bytes: %w", err)
		}
		return data, nil
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key to bytes: %w", err)
		}
		return data, nil
	case *ed25519KeyPair:
		return marshalEd25519PrivateKey(priv.PrivateKey)
	case *ed25519.PrivateKey:
		return marshalEd25519PrivateKey(priv)
	default:
		return nil, NotSupported("unsupported private key format")
	}
}

func marshalEd25519PrivateKey(priv *ed25519.PrivateKey) ([]byte, error) {
	data, err := x509.MarshalPKCS8PrivateKey(*priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ED25519 private key to bytes: %w", err)
	}
	return data, nil
}

// PublicKeyAsBytes encodes the public key in a format appropriate to the algorithm in use.
//
//   - PKCS #1 for RSA
//   - PKCS #8 for ECDSA and ED25519
//
// Other formats result in a NotSupported error.
func PublicKeyAsBytes(keys Keypair) ([]byte, error) {
	switch priv := keys.(type) {
	case *rsa.PrivateKey:
		data := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
		return data, nil
	case *ecdsa.PrivateKey:
		pub, ok := priv.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("failed to get ECDSA public key from key pair")
		}
		data, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA public key to bytes: %w", err)
		}
		return data, nil
	case *ed25519KeyPair:
		data, err := x509.MarshalPKIXPublicKey(priv.pub)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ED25519 public key to bytes: %w", err)
		}
		return data, nil
	case *ed25519.PrivateKey:
		data, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ED25519 public key to bytes: %w", err)
		}
		return data, nil
	default:
		return nil, NotSupported("unsupported public key format")
	}
}

func (o CertOutput) PrivateKeyAsBytes() ([]byte, error) {
	return PrivateKeyAsBytes(o.keypair)
}

func (o CertOutput) WritePrivateKeyBytes(w io.Writer) (int, error) {
	data, err := o.PrivateKeyAsBytes()
	if err != nil {
		return 0, err
	}
	return w.Write(data)
}

func (o CertOutput) PrivateKeyAsPEMBlock(pemType string) ([]byte, error) {
	var buf bytes.Buffer
	if err := o.WritePrivateKeyPEMBlock(&buf, pemType); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o CertOutput) WritePrivateKeyPEMBlock(w io.Writer, pemType string) error {
	data, err := o.PrivateKeyAsBytes()
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{
		Type:  pemType,
		Bytes: data,
	})
}
