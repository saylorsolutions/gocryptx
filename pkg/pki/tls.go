package pki

import (
	"crypto/tls"
	"fmt"
)

const (
	certPemType    = "CERTIFICATE"
	privKeyPemType = "PRIVATE KEY"
)

// AsTLSCert is used to create a tls.Certificate for use in (m)TLS scenarios.
// This makes it much more convenient to work with the tls package directly, rather than depending on files already being present on the running system.
// It also provides a great deal of flexibility for working with certificates in memory.
func (o CertOutput) AsTLSCert() (*tls.Certificate, error) {
	cert, err := o.CertAsPEMBlock(certPemType)
	if err != nil {
		return nil, fmt.Errorf("failed to encode certificate as PEM block: %w", err)
	}
	key, err := o.PrivateKeyAsPEMBlock(privKeyPemType)
	if err != nil {
		return nil, fmt.Errorf("failed to encode key as PEM block: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert/key data: %w", err)
	}
	return &tlsCert, nil
}
