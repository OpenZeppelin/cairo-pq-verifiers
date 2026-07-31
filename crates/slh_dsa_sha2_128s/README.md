# SLH-DSA-SHA2-128s verifier

**Scheme:** SLH-DSA-SHA2-128s, stateless hash-based signatures, final NIST standard
(FIPS 205).
**Status:** measured.

This crate verifies the category-1, small-signature SLH-DSA parameter set. Verification
reconstructs the FORS public key and seven-layer XMSS hypertree using the FIPS 205 SHA2
instantiation. SHA-256 compression is provided by Starknet's native syscall.
FIPS preimages are packed directly into 32-bit words, avoiding byte-by-byte decomposition
before each compression call.

The `PqSignatureVerifier` message hash is encoded as a 32-byte big-endian message and
passed through the pure SLH-DSA interface with an empty context. Public keys contain two
16-byte elements (2 felts); signatures contain 491 16-byte elements (7,856 bytes).

References:
[NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) and the
[slhdsa-c interoperable implementation](https://github.com/slh-dsa/slhdsa-c).

## Current efficiency

| Measurement | L2 gas | Cairo steps |
|---|---:|---:|
| Bare verification | 3,627,901,336 | 9,035,854 |
| Inside `__validate__` | 3,628,036,866 | 9,037,094 |

The verifier exceeds the 100,000,000-L2-gas cap by 36.3× and the 1,000,000-step
cap by 9.04×. The genuine fixture requires 4,116 SHA-256 block-processing syscalls.
