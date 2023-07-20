/*
Package xor provides some light-weight screening of lower sensitivity data.

Note that this is NOT encryption, since it is easily reversible.
This falls squarely under the obfuscation category.
As such, it is NOT recommended for security critical use.
That being said, it's useful for preventing passive observation of plain text information since it generally requires knowledge of the original key to correctly reverse the process.

# How it works:

An XOR key (with optional offset) is provided to the functions in this package, which will be used to apply a bitwise XOR to every byte that passes through Reader or Writer.
Once a key byte is used, the screen will progress to the next byte in the key.
When the last byte is used, the first will be used again, operating like a ring buffer.

Providing an offset will make the screen start at the given offset instead of the first byte.
This is useful for adding a little randomness to the process in case it's likely that the same key can be used more than once.

# Important note:

The same key and offset parameters must be provided to accurately reverse the process.
Failing to do so will likely result in garbled or partly de-obfuscated data.

# General guidelines:
  - Longer keys are better, but have limited usefulness with a short payload.
  - Key length should ideally be a function of payload length.
  - For shorter payloads, using a shorter key with random offset is sufficient, but will still yield a predictable pattern.
  - Using securely generated keys with the OS entropy pool (like with GenKey or GenKeyAndOffset) are better.
  - Using a random offset is recommended, but not required.
*/
package xor
