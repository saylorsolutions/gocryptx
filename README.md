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

## Applications
* **xorgen:** Provides a CLI that can be used with go:generate comments to easily embed XOR screened and compressed files.
