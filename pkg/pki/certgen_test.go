package pki

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyAlgorithms(t *testing.T) {
	tests := map[string]CertGenOpt{
		"RSA":        WithRSAKey(),
		"ECDSA-P224": WithECDSAKey(elliptic.P224()),
		"ECDSA-P256": WithECDSAKey(elliptic.P256()),
		"ECDSA-P384": WithECDSAKey(elliptic.P384()),
		"ECDSA-P521": WithECDSAKey(elliptic.P521()),
		"ED25519":    WithED25519Key(),
	}

	for name, opt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := GenerateCACert(
				new(NameBuilder).CommonName("testing").Build(),
				opt,
				ValidFor(1, 0, 0),
			)
			require.NoError(t, err)
			require.NoError(t, ValidateKeypair(result.Keypair()))
		})
	}
}

func TestGenerateCACert(t *testing.T) {
	sub := new(NameBuilder).Organization("My Org").Build()
	cert, err := GenerateCACert(sub,
		WithRSAKey(),
		ValidFor(0, 0, 30),
	)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	require.NoError(t, ValidateKeypair(cert.Keypair()))
}

func TestGenerateIntermediateCACert(t *testing.T) {
	caCert, err := GenerateCACert(
		new(NameBuilder).Organization("My Org").Build(),
		WithRSAKey(),
		ValidFor(1, 0, 0),
	)
	require.NoError(t, err)
	assert.NotNil(t, caCert)
	intermCert, err := GenerateIntermediateCACert(
		new(NameBuilder).Organization("My sub-org").Build(),
		WithRSAKey(),
		ValidFor(0, 3, 0),
		SignWith(caCert.Certificate(), caCert.Keypair()),
	)
	require.NoError(t, err)
	assert.NotNil(t, intermCert)
}

func TestMutualTLS(t *testing.T) {
	// Simulate a full mTLS scenario.
	addr := testGetOpenPort(t)
	t.Log("Server address:", addr)
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	srvIP := net.ParseIP(host)
	ctx, cancel := context.WithCancel(t.Context())
	caCert, err := GenerateCACert(
		new(NameBuilder).Organization("ca").Build(),
		ValidFor(1, 0, 0),
		WithRSAKey(),
	)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert.Certificate())
	srvCert, err := GenerateServerCert(
		new(NameBuilder).Organization("server").Build(),
		WithRSAKey(),
		ValidFor(1, 0, 0),
		SignWith(caCert.Certificate(), caCert.Keypair()),
		SANIPAddresses(srvIP),
	)
	require.NoError(t, err)
	cliCert, err := GenerateClientCert(
		new(NameBuilder).Organization("client").Build(),
		WithRSAKey(),
		ValidFor(1, 0, 0),
		SignWith(caCert.Certificate(), caCert.Keypair()),
	)
	require.NoError(t, err)
	addr, srvWg := testMTLSServer(t, ctx, addr, srvCert, pool)
	client := testMTLSClient(t, cliCert, pool)

	resp, err := client.Get(fmt.Sprintf("https://%s/testing", addr))
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	cancel()
	srvWg.Wait()
}

func testMTLSServer(t *testing.T, ctx context.Context, addr string, server *CertOutput, pool *x509.CertPool) (string, *sync.WaitGroup) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srvTlsCert, err := server.AsTLSCert()
	require.NoError(t, err)
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			ClientCAs:    pool,
			Certificates: []tls.Certificate{*srvTlsCert}, // Intermediates would go after the "leaf" server cert.
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadHeaderTimeout: time.Second,
	}
	wg := testStartServer(t, ctx, srv)
	return addr, wg
}

func testGetOpenPort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", ":0") //nolint:gosec // This is fine for a test server.
	require.NoError(t, err)
	addr := lis.Addr()
	require.NoError(t, lis.Close())
	return addr.String()
}

func testStartServer(t *testing.T, ctx context.Context, srv *http.Server) *sync.WaitGroup {
	t.Helper()
	require.NoError(t, ctx.Err())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh := make(chan error)
		go func() {
			defer close(errCh)
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				errCh <- err
			}
		}()
		select {
		case <-ctx.Done():
			timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			assert.NoError(t, srv.Shutdown(timeout))
		case <-errCh:
			return
		}
	}()
	return &wg
}

func testMTLSClient(t *testing.T, client *CertOutput, pool *x509.CertPool) *http.Client {
	cliCert, err := client.AsTLSCert()
	require.NoError(t, err)
	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      pool,
				Certificates: []tls.Certificate{*cliCert}, // Intermediates would go after the "leaf" client cert.
			},
		},
	}
	return cli
}
