package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// Keypair is an abstraction for a public/private key pair.
// Both embedded interfaces expose a Public method that may be used to get the public key.
type Keypair interface {
	crypto.Signer
	crypto.Decrypter
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

// ValidateKeypair is used to verify that the private and public keys are associated with each other.
func ValidateKeypair(pair Keypair) error {
	switch priv := pair.(type) {
	case *rsa.PrivateKey:
		orig := make([]byte, 255)
		_, err := rand.Read(orig)
		if err != nil {
			return fmt.Errorf("failed to generate random data for signature verification: %w", err)
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
	default:
		return NotSupported("private key algorithm is not supported")
	}
}

// LoadKeypairFromFile will attempt to read DER/PEM encoded data files as a private and public key pair.
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
	var errs []error
	{
		// Try RSA, this doesn't handle encrypted private keys.
		kp, err := loadRSAKeypair(privData, pubData)
		if err != nil {
			errs = append(errs, err)
		} else {
			return kp, nil
		}
	}
	return nil, errors.Join(errs...)
}

func loadRSAKeypair(privData, pubData []byte) (Keypair, error) {
	priv, err := x509.ParsePKCS1PrivateKey(privData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data as RSA private key: %w", err)
	}
	pub, err := x509.ParsePKCS1PublicKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data as RSA public key: %w", err)
	}
	priv.PublicKey = *pub
	if err := ValidateKeypair(priv); err != nil {
		return nil, err
	}
	return priv, nil
}

// PrivateKeyAsBytes encodes the private key in a format appropriate to the algorithm in use.
//
//   - PKCS1 for RSA
//
// Other formats result in a NotSupported error.
func PrivateKeyAsBytes(keys Keypair) ([]byte, error) {
	switch priv := keys.(type) {
	case *rsa.PrivateKey:
		data := x509.MarshalPKCS1PrivateKey(priv)
		return data, nil
	default:
		return nil, NotSupported("unsupported private key format")
	}
}

// PublicKeyAsBytes encodes the public key in a format appropriate to the algorithm in use.
//
//   - PKCS1 for RSA
//
// Other formats result in a NotSupported error.
func PublicKeyAsBytes(keys Keypair) ([]byte, error) {
	switch priv := keys.(type) {
	case *rsa.PrivateKey:
		data := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
		return data, nil
	default:
		return nil, NotSupported("unsupported private key format")
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
