# Go Cryptx

[![Go Report Card](https://goreportcard.com/badge/github.com/saylorsolutions/gocryptx)]

This repo has a few helpful crypto utilities that I've used or plan to use.
I'm happy to accept PRs relating to functionality or documentation.

---
**Note:**

See the [Security Policy](SECURITY.md) for details about how to responsibly report security issues.
These should be resolved ***outside*** of the normal PR flow to protect users from undue risk.

---

## Packages
* **xor:** Provides some utilities for XOR screening, including an io.Reader and io.Writer implementation that screens in flight.
* **passlock:** Provides some utilities for AES 128/256 encryption using a user-supplied passphrase. This is useful for situations where key management is considered harder than password management.
  * Provides a KeyGenerator type that uses scrypt under the hood to generate AES 128/256 keys based on the given passphrase and a secure random seed.
    * The key generator may be tuned to match your threat model, but reasonable default are provided.
  * This also includes a way to encrypt/decrypt a payload with multiple, surrogate keys. This allows multiple, independent passphrases to be used to interact with a payload.
  * There are no guarantees that this mechanism is interoperable with other passphrase locking mechanisms or systems.

## Applications
* **xorgen:** Provides a CLI that can be used with go:generate comments to easily embed XOR screened and compressed files.
