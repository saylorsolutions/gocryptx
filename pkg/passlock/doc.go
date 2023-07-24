/*
Package passlock provides functions for encrypting data using a key derived from a user-provided passphrase.
This uses AES-256 encryption to encrypt the provided data.

# How it works:

A key and salt is generated from the given password. The salt is prepended to the encrypted payload so the same key can be derived later, given the same passphrase.
Scrypt is memory and CPU hard, so it's impractical to brute force the hash to get the original value, provided that sufficient tuning values are provided to the KeyGenerator.

The key and salt are passed to the Encrypt function to use the key to encrypt the payload and prepend the salt.
The passphrase is passed to the Decrypt function to derive the key from the passphrase and salt, and decrypt the payload.

# General guidelines:
  - AES-512 is better for high security applications, while AES-256 is a good default for most cases.
  - It's possible to customize the CPU cost, iteration count, and relative block size parameters directly. If you're not an expert, then don't use SetIterations, SetCPUCost, or SetRelativeBlockSize.
  - Both short and long delay iteration GeneratorOpt functions are provided, choose the correct iterations for your use-case using either SetLongDelayIterations or SetShortDelayIterations.
*/
package passlock
