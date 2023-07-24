/*
Package passlock provides functions for encrypting data using a key derived from a user-provided passphrase.
This uses AES-256 encryption to encrypt the provided data.

# How it works:

A key and salt is generated from the given passphrase. The salt is appended to the encrypted payload so the same key can be derived later given the same passphrase.
Scrypt is memory and CPU hard, so it's impractical to brute force the salt to get the original passphrase, provided that sufficient tuning values are provided to the KeyGenerator.

The key, salt, and plaintext are passed to the Lock function to encrypt the payload and append the salt to it.
The key is recovered from the encrypted payload by passing the original passphrase and the payload to KeyGenerator.Derive.
The key and encrypted payload are passed to the Unlock function to decrypt the payload and return the original plain text.

# General guidelines:
  - It's possible to customize the CPU cost, iteration count, and relative block size parameters directly for key generation. If you're not an expert, then don't use SetIterations, SetCPUCost, or SetRelativeBlockSize.
  - Both short and long delay iteration GeneratorOpt functions are provided, choose the correct iterations for your use-case using either SetLongDelayIterations or SetShortDelayIterations.
  - This method of encryption (AES256GCM) supports encrypting and authenticating at most about 64GB at a time. You could get around this by splitting a very large file into multiple chunks that include some metadata to prevent reordering or truncating.
  - AES-256 is a good default for a lot of cases, with excellent security and good throughput speeds. This library only supports AES-256 since that is the best supported by the Go standard lib, and it conforms to the constraints posed by AES in general.
  - When deriving the key from an encrypted payload, make sure that the same KeyGenerator settings are used. Not doing so will likely result in an incorrect key.
*/
package passlock
