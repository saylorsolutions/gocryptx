/*
Package passlock provides functions for encrypting data using a key derived from a user-provided passphrase.
This uses AES-256 encryption to encrypt the provided data.

# How it works:

A key and salt is generated from the given passphrase. The salt is appended to the encrypted payload so the same key can be derived later given the same passphrase.
Scrypt is memory and CPU hard, so it's impractical to brute force the salt to get the original passphrase, provided that sufficient tuning values are provided to the KeyGenerator.

The key, salt, and plaintext are passed to the Lock function to encrypt the payload and append the salt to it.
The key is recovered from the encrypted payload by passing the original passphrase and the payload to KeyGenerator.Derive.
The key and encrypted payload are passed to the Unlock function to decrypt the payload and return the original plain text.

The MultiLocker type extends the functionality above by providing the ability to use multiple surrogate keys to interact with the encrypted payload.
A MultiLocker is created using a KeyGenerator, and the encrypted payload is set by calling MultiLocker.Lock with the base passphrase and plaintext.
Once created, surrogate keys may be added to the MultiLocker that allow reading the encrypted payload.
A MultiLocker with surrogate keys and encrypted payload may be persisted to disk in binary form, and read back - including key generation settings.

A freshly read MultiLocker may not be changed in any way. Editing is enabled by calling EnableUpdate with the base passphrase.
After this call completes successfully, surrogate keys may be added or removed.
A new encrypted payload may not be set to a MultiLocker if surrogate keys exist, and the MultiLocker has not had EnableUpdate called. Allowing this operation would invalidate those keys otherwise.

# General guidelines:
  - It's possible to customize the CPU cost, iteration count, and relative block size parameters directly for key generation. If you're not an expert, then don't use SetIterations, SetCPUCost, or SetRelativeBlockSize.
  - Both short and long delay iteration GeneratorOpt functions are provided, choose the correct iterations for your use-case using either SetLongDelayIterations or SetShortDelayIterations.
  - This method of encryption (AES-GCM) supports encrypting and authenticating at most about 64GB at a time. You could get around this by splitting a very large file into multiple chunks that include some metadata to prevent reordering or truncating.
  - AES-256 is a good default for a lot of cases, with excellent security and good throughput speeds.
  - This library supports AES-256 since that is the best supported by the Go standard lib, but AES-128 may also be used for situations where more throughput is desired.
  - The main limit to throughput comes from key generation, the AES key size makes a much smaller impact to performance.
  - When deriving the key from an encrypted payload, make sure that the same KeyGenerator settings are used. Not doing so will likely result in an incorrect key.
  - Technically, a surrogate key could be used to update a MultiLocker encrypted payload without invalidating other surrogate keys, since there are no cryptographic blockers to that. The base MultiLocker doesn't provide that function as a logical constraint only.
*/
package passlock
