package pki

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	CAType = "CA CERTIFICATE"
)

func ReadCACert(path string) (*x509.Certificate, error) {
	return readPemCert(path, "CA")
}

func readPemCert(path, certType string) (*x509.Certificate, error) {
	certdata, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s cert at path '%s': %w", certType, path, err)
	}
	certpem, _ := pem.Decode(certdata)
	if certpem.Type != CAType {
		return nil, fmt.Errorf("decoded PEM block is not of the correct type: expected '%s', got '%s'", CAType, certpem.Type)
	}
	certs, err := x509.ParseCertificates(certpem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate from path '%s': %w", path, err)
	}
	switch len(certs) {
	case 0:
		return nil, fmt.Errorf("no certificates found in path '%s'", path)
	case 1:
		return certs[0], nil
	default:
		return nil, fmt.Errorf("more than one cert found in path '%s'", path)
	}
}

func ReadServerCertAndKey(certpath, keypath string) (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := readPemCert(certpath, "server")
	if err != nil {
		return nil, nil, err
	}
	pubkey, ok := cert.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("server certificate at path '%s' does not contain a public key", certpath)
	}
	keydata, err := os.ReadFile(keypath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file at path '%s': %w", keypath, err)
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		privKey, err := parseAndValidateRSAPrivateKey(keydata, pubkey)
		if err != nil {
			return nil, nil, err
		}
		return cert, privKey, nil
	default:
		return nil, nil, fmt.Errorf("unknown or unsupported cert key type: '%s'", cert.PublicKeyAlgorithm.String())
	}
}

func parseAndValidateRSAPrivateKey(keydata []byte, pubkey crypto.PublicKey) (crypto.PrivateKey, error) {
	rsaPriv, err := x509.ParsePKCS1PrivateKey(keydata)
	if err != nil {
		anyPriv, err := x509.ParsePKCS8PrivateKey(keydata)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key as PKCS #1 or #8: %w", err)
		}
		_rsaPriv, ok := anyPriv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unable to parse private key as PKCS #1 or #8: %w", err)
		}
		rsaPriv = _rsaPriv
	}
	rsaPub, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA public key")
	}
	rsaPriv.PublicKey = *rsaPub
	rsaPriv.Precompute()
	if err := rsaPriv.Validate(); err != nil {
		return nil, fmt.Errorf("private key is invalid: %w", err)
	}
	return rsaPriv, nil
}
