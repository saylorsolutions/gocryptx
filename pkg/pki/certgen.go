package pki

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"time"
)

// NotSupported is an error indicating that the operation is not supported.
type NotSupported string

func (n NotSupported) Error() string {
	return string(n)
}

// CertOutput is used to keep the context of generated crypto material together for convenience.
type CertOutput struct {
	certData []byte
	cert     *x509.Certificate
	keypair  Keypair
}

func (o CertOutput) Certificate() *x509.Certificate {
	return o.cert
}

func (o CertOutput) Keypair() Keypair {
	return o.keypair
}

func (o CertOutput) CertAsDERBytes() []byte {
	return o.certData
}

func (o CertOutput) WriteCertDERBytes(w io.Writer) (int, error) {
	return w.Write(o.certData)
}

func (o CertOutput) CertAsPEMBlock(pemType string) ([]byte, error) {
	var buf bytes.Buffer
	if err := o.WriteCertPEMBlock(&buf, pemType); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o CertOutput) WriteCertPEMBlock(w io.Writer, pemType string) error {
	err := pem.Encode(w, &pem.Block{
		Type:  pemType,
		Bytes: o.certData,
	})
	if err != nil {
		return fmt.Errorf("failed to encode PEM block: %w", err)
	}
	return nil
}

// CertGenOpt is an option to a Generate*Cert function that configures the certificate.
type CertGenOpt func(opts *certGenOpt) error

type certGenOpt struct {
	cert           *x509.Certificate
	certKeyPair    Keypair
	signingCert    *x509.Certificate
	signingKeyPair Keypair
	deferred       []CertGenOpt
}

// SANHosts is used to specify valid hosts for server verification.
func SANHosts(hosts ...string) CertGenOpt {
	return func(opts *certGenOpt) error {
		if len(hosts) == 0 {
			return fmt.Errorf("no hosts specified")
		}
		valid := make([]string, len(hosts))
		for i, host := range hosts {
			validHost, err := ParseHost(host)
			if err != nil {
				return err
			}
			valid[i] = validHost
		}
		opts.cert.DNSNames = append(opts.cert.DNSNames, valid...)
		return nil
	}
}

// SANIPAddresses is used to specify valid IP addresses for server verification.
func SANIPAddresses(ips ...net.IP) CertGenOpt {
	return func(opts *certGenOpt) error {
		if len(ips) == 0 {
			return fmt.Errorf("no IPs specified")
		}
		opts.cert.IPAddresses = append(opts.cert.IPAddresses, ips...)
		return nil
	}
}

// WithRSAKey generates an RSA 4096 key to be used with a generated certificate.
func WithRSAKey() CertGenOpt {
	return func(opts *certGenOpt) error {
		kp, err := GenerateRSAKeypair()
		if err != nil {
			return err
		}
		opts.certKeyPair = kp
		return nil
	}
}

// WithECDSAKey generates an ECDSA key - using the given curve - to be used with a generated certificate.
func WithECDSAKey(curve elliptic.Curve) CertGenOpt {
	return func(opts *certGenOpt) error {
		kp, err := GenerateECDSAKeypair(curve)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
		opts.certKeyPair = kp
		return nil
	}
}

// WithED25519Key generates an ED25519 key pair to be used with a generated certificate.
func WithED25519Key() CertGenOpt {
	return func(opts *certGenOpt) error {
		kp, err := GenerateED25519Keypair()
		if err != nil {
			return fmt.Errorf("failed to generate ED25519 key pair: %w", err)
		}
		opts.certKeyPair = kp
		return nil
	}
}

// UseKeypair allows specifying a Keypair to use instead of generating a fresh Keypair.
// It's generally preferred to generate new keys for certificates, but there are specific cases where this is useful.
//
// Avoid using this where possible.
func UseKeypair(keys Keypair) CertGenOpt {
	return func(opts *certGenOpt) error {
		if err := ValidateKeypair(keys); err != nil {
			return err
		}
		opts.certKeyPair = keys
		return nil
	}
}

// ValidAt is used to specify when a certificate will become valid for use.
// This is optional, and all generators will default to the current timestamp in UTC.
func ValidAt(validStart time.Time) CertGenOpt {
	return func(opts *certGenOpt) error {
		if validStart.IsZero() {
			return fmt.Errorf("cannot use zero valid start timestamp")
		}
		opts.cert.NotBefore = validStart.UTC()
		return nil
	}
}

// ValidFor is used to specify the number of years/months/days that a certificate should be considered valid.
// This is added to a value passed to ValidAt if specified, or the current timestamp otherwise.
//
// This is required in all cases.
func ValidFor(years, months, days int) CertGenOpt {
	return func(opts *certGenOpt) error {
		if years < 0 || months < 0 || days < 0 {
			return fmt.Errorf("cannot use negative values: years=%d, months=%d, days=%d", years, months, days)
		}
		if years == 0 && months == 0 && days == 0 {
			return fmt.Errorf("no validity interval specified")
		}
		opts.deferred = append(opts.deferred, func(opts *certGenOpt) error {
			opts.cert.NotAfter = opts.cert.NotBefore.AddDate(years, months, days)
			return nil
		})
		return nil
	}
}

type pubEqual interface {
	Equal(other crypto.PublicKey) bool
}

// SignWith is used to specify what certificate and Keypair is used to sign the generated certificate.
func SignWith(signingCert *x509.Certificate, signingKey Keypair) CertGenOpt {
	return func(opts *certGenOpt) error {
		if signingCert == nil {
			return fmt.Errorf("nil certificate")
		}
		if !signingCert.IsCA || signingCert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("certificate may not be used to sign a certificate")
		}
		if signingKey == nil {
			return fmt.Errorf("nil key pair")
		}
		anyPub := signingKey.Public()
		if anyPub == nil {
			return fmt.Errorf("missing associated public key to validate key pair")
		}
		pub, ok := anyPub.(pubEqual)
		if !ok {
			return fmt.Errorf("public key does not provide the expected interactions")
		}
		if !pub.Equal(signingCert.PublicKey) {
			return fmt.Errorf("key pair does not match the given signing certificate")
		}
		if err := ValidateKeypair(signingKey); err != nil {
			return err
		}
		opts.signingCert = signingCert
		opts.signingKeyPair = signingKey
		return nil
	}
}

func ensureValidStartSet(opts *certGenOpt) error {
	if opts.cert.NotBefore.IsZero() {
		opts.cert.NotBefore = time.Now().UTC()
	}
	return nil
}

func ensureKeySet(opts *certGenOpt) error {
	if opts.certKeyPair == nil {
		return fmt.Errorf("no key pair generation setting used")
	}
	return nil
}

func applyOpts(subject pkix.Name, deferOpts []CertGenOpt, opts ...CertGenOpt) (*certGenOpt, error) {
	options := certGenOpt{
		cert: &x509.Certificate{
			Subject: subject,
		},
		deferred: deferOpts,
	}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("unable to generate CA cert: %w", err)
		}
	}
	for _, deferred := range options.deferred {
		if err := deferred(&options); err != nil {
			return nil, fmt.Errorf("unable to generate CA cert: %w", err)
		}
	}
	notBefore := options.cert.NotBefore
	notAfter := options.cert.NotAfter
	switch {
	case notAfter.IsZero():
		fallthrough
	case notAfter.Before(notBefore):
		fallthrough
	case notAfter.Equal(notBefore):
		return nil, fmt.Errorf("invalid validity upper bound")
	}
	return &options, nil
}

func usageCACert(opts *certGenOpt) error {
	opts.cert.IsCA = true
	opts.cert.BasicConstraintsValid = true
	opts.cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	opts.cert.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}
	return nil
}

// GenerateCACert generates a self-signed, root Certificate Authority (CA) certificate.
// These certs are usually long-lived with closely guarded keys.
func GenerateCACert(subject pkix.Name, opts ...CertGenOpt) (*CertOutput, error) {
	validateOpts := []CertGenOpt{
		usageCACert,
		ensureKeySet,
		ensureValidStartSet,
	}
	options, err := applyOpts(subject, validateOpts, opts...)
	if err != nil {
		return nil, err
	}
	certBytes, caCert, err := createSelfSignedCert(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	return &CertOutput{
		certData: certBytes,
		cert:     caCert,
		keypair:  options.certKeyPair,
	}, nil
}

func createSelfSignedCert(options *certGenOpt) ([]byte, *x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		options.cert,
		options.cert,
		options.certKeyPair.Public(),
		options.certKeyPair,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create self-signed certificate: %w", err)
	}
	finalCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse finalized certificate: %w", err)
	}
	return certBytes, finalCert, nil
}

func ensureSigningKeySet(opts *certGenOpt) error {
	if opts.signingKeyPair == nil {
		return fmt.Errorf("no signing key pair specified")
	}
	return nil
}

func ensureSigningCertSet(opts *certGenOpt) error {
	if opts.signingCert == nil {
		return fmt.Errorf("no signing cert specified")
	}
	if !opts.signingCert.IsCA {
		return fmt.Errorf("attempting to sign a certificate with a non-CA cert")
	}
	return nil
}

// GenerateIntermediateCACert generates an intermediate CA certificate that is used to subdivide and manage trust zones.
// If there are multiple contexts of use for a set of certificates, then this may be a use-case for intermediate certificates.
func GenerateIntermediateCACert(subject pkix.Name, opts ...CertGenOpt) (*CertOutput, error) {
	validateOpts := []CertGenOpt{
		usageCACert,
		ensureKeySet,
		ensureValidStartSet,
		ensureSigningKeySet,
		ensureSigningCertSet,
	}
	options, err := applyOpts(subject, validateOpts, opts...)
	if err != nil {
		return nil, err
	}
	certBytes, intermCert, err := createSignedCert(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}
	return &CertOutput{
		certData: certBytes,
		cert:     intermCert,
		keypair:  options.certKeyPair,
	}, nil
}

func ensureLeafCert(opts *certGenOpt) error {
	if opts.cert.IsCA || opts.cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return fmt.Errorf("server certs may not be CA certs")
	}
	return nil
}

func usageServerCert(opts *certGenOpt) error {
	opts.cert.IsCA = false
	opts.cert.KeyUsage = x509.KeyUsageDigitalSignature
	opts.cert.ExtKeyUsage = append(opts.cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return nil
}

func usageClientCert(opts *certGenOpt) error {
	opts.cert.IsCA = false
	opts.cert.KeyUsage = x509.KeyUsageDigitalSignature
	opts.cert.ExtKeyUsage = append(opts.cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	return nil
}

// GenerateServerCert is used to generate a certificate for server verification.
// This is commonly seen on the web for most sites that take user safety seriously.
func GenerateServerCert(subject pkix.Name, opts ...CertGenOpt) (*CertOutput, error) {
	validateOpts := []CertGenOpt{
		usageServerCert,
		ensureKeySet,
		ensureValidStartSet,
		ensureSigningKeySet,
		ensureSigningCertSet,
		ensureLeafCert,
	}
	options, err := applyOpts(subject, validateOpts, opts...)
	if err != nil {
		return nil, err
	}
	options.cert.BasicConstraintsValid = true
	certBytes, serverCert, err := createSignedCert(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}
	return &CertOutput{
		certData: certBytes,
		cert:     serverCert,
		keypair:  options.certKeyPair,
	}, nil
}

// GenerateClientCert generates a client certificate for mTLS scenarios.
// This means that the client may *also* be verified along with servers, establishing a policy of zero-trust.
// This is most useful in higher security/risk scenarios, where more verification is desired to limit risk.
// It may also be used as part of a Multi-Factor Authentication (MFA) scheme to validate machines as well as users.
func GenerateClientCert(subject pkix.Name, opts ...CertGenOpt) (*CertOutput, error) {
	validateOpts := []CertGenOpt{
		usageClientCert,
		ensureKeySet,
		ensureValidStartSet,
		ensureSigningKeySet,
		ensureSigningCertSet,
		ensureLeafCert,
	}
	options, err := applyOpts(subject, validateOpts, opts...)
	if err != nil {
		return nil, err
	}
	options.cert.BasicConstraintsValid = true
	certBytes, serverCert, err := createSignedCert(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}
	return &CertOutput{
		certData: certBytes,
		cert:     serverCert,
		keypair:  options.certKeyPair,
	}, nil
}

func createSignedCert(options *certGenOpt) ([]byte, *x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		options.cert,
		options.signingCert,
		options.certKeyPair.Public(),
		options.signingKeyPair,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signed certificate: %w", err)
	}
	finalCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse finalized certificate: %w", err)
	}
	return certBytes, finalCert, nil
}
