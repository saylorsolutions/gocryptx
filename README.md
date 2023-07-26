# Go Cryptx

This repo has a few helpful crypto utilities that I've used or plan to use.

---
**Note:**

Use at your own risk!
While I've done my best to ensure that this functionality is working as intended, I don't recommend using any of this for anything that could risk life, limb, property, or any serious material harm without extensive security review.

If you suspect that a security issue exists, please notify me by creating an issue here on GitHub, and I will address it as soon as possible.
If you are a security professional, I can always use another set of eyes to verify the security and integrity of these utilities.

When the time comes where I am no longer maintaining this repository, either by responding to or resolving issues, then I will mark it as archived to indicate that it should no longer be used in its current state.
If this is the case - and even before then - feel free to fork this repository and enhance as you see fit.

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
