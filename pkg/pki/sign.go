package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

type Signature []byte

func (s Signature) Base64() string {
	return base64.StdEncoding.EncodeToString(s)
}

type signOptions struct {
	rsa struct {
		hash crypto.Hash
	}
	ecdsa struct {
		hash crypto.Hash
	}
}

func (o *signOptions) apply(opts ...SignOpt) error {
	o.rsa.hash = crypto.SHA256
	o.ecdsa.hash = crypto.SHA256
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
}

type SignOpt = func(opts *signOptions) error

func SignRSAHash(hash crypto.Hash) SignOpt {
	return func(opts *signOptions) error {
		opts.rsa.hash = hash
		return nil
	}
}

func SignECDSAHash(hash crypto.Hash) SignOpt {
	return func(opts *signOptions) error {
		opts.ecdsa.hash = hash
		return nil
	}
}

func Sign(priv crypto.PrivateKey, payload Plaintext, opts ...SignOpt) (Signature, error) {
	options := new(signOptions)
	if err := options.apply(opts...); err != nil {
		return nil, err
	}
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		h := options.rsa.hash.New()
		h.Write(payload)
		return rsa.SignPSS(rand.Reader, priv, options.rsa.hash, h.Sum(nil), nil)
	case *ecdsa.PrivateKey:
		h := options.ecdsa.hash.New()
		h.Write(payload)
		return ecdsa.SignASN1(rand.Reader, priv, h.Sum(nil))
	case *ed25519KeyPair:
		return ed25519.Sign(*priv.PrivateKey, payload), nil
	case ed25519.PrivateKey:
		return ed25519.Sign(priv, payload), nil
	case *ed25519.PrivateKey:
		return ed25519.Sign(*priv, payload), nil
	default:
		return nil, fmt.Errorf("unknown keypair type for signatures")
	}
}

func Verify(pub crypto.PublicKey, payload Plaintext, sig Signature, opts ...SignOpt) (bool, error) {
	options := new(signOptions)
	if err := options.apply(opts...); err != nil {
		return false, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		h := options.rsa.hash.New()
		h.Write(payload)
		err := rsa.VerifyPSS(pub, options.rsa.hash, h.Sum(nil), sig, nil)
		return err == nil, err
	case *ecdsa.PublicKey:
		h := options.ecdsa.hash.New()
		h.Write(payload)
		return ecdsa.VerifyASN1(pub, h.Sum(nil), sig), nil
	case ed25519.PublicKey:
		return ed25519.Verify(pub, payload, sig), nil
	default:
		return false, fmt.Errorf("unknown keypair type for signature verification")
	}
}
