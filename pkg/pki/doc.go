/*
Package pki provides public key capabilities with a consistent API.
This includes x509 certificate generation and use for constructing certificate chains.

# Certificates

Different certificate types required for certificate chains are supported.

  - CA certificate: This certificate is self-signed, and established as the root authority for a chain.
    Created with GenerateCACert.
  - Intermediate: An intermediate is signed by a CA cert (or another intermediate), and used as an intermediate authority in a chain.
    Created with GenerateIntermediateCACert.
  - Server cert: A server cert is assigned to a server to allow clients to authenticate it.
    Created with GenerateServerCert.
  - Client cert: A client cert is used for mTLS to allow servers to also authenticate clients.
    Created with GenerateClientCert.

# Public key encryption

The Encrypt and Decrypt functions allow using public keys for encrypting and decrypting data, respectively.
Supported key types:

  - RSA
  - NIST curves (P256, P384, and P521)
  - Ed25519 curve (translated to X25519 points)

In the case of elliptic curve keys, encryption uses AES 256 GCM.

# Public key signatures

The Sign and Verify functions allow using public keys for signing and verifying signatures, respectively.
Supported key types:

  - RSA (uses SHA-256 hashes by default)
  - All NIST curves (uses SHA-256 hashes by default)
  - Ed25519 curve
*/
package pki
