# SLH-DSA-SHAKE-128s verifier

**Scheme:** SLH-DSA-SHAKE-128s, stateless hash-based signatures, final NIST standard
(FIPS 205).
**Status:** measured.

This crate verifies the category-1, small-signature SLH-DSA parameter set. Verification
reconstructs the FORS public key and seven-layer XMSS hypertree using the FIPS 205 SHAKE
instantiation. SHAKE256 is implemented with Starknet's native Keccak syscall, explicit
SHAKE domain separation and padding, and the full 32-byte FIPS address. Hash inputs are
held in Keccak's native 64-bit lane representation throughout verification.

The `PqSignatureVerifier` message hash is encoded as a 32-byte big-endian message and
passed through the pure SLH-DSA interface with an empty context. Public keys contain two
16-byte elements (2 felts); signatures contain 491 16-byte elements (7,856 bytes).

References:
[NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) and the
[slhdsa-c interoperable implementation](https://github.com/slh-dsa/slhdsa-c).

## Current efficiency

| Measurement | L2 gas | Cairo steps |
|---|---:|---:|
| Bare verification | 410,340,991 | 843,750 |
| Inside `__validate__` | 410,476,521 | 844,990 |

The account fits the 1,000,000-step cap at 84.5%, but exceeds the 100,000,000-L2-gas cap
by 4.10× and therefore cannot run in `__validate__` under both measured limits. The
genuine fixture makes 2,099 Keccak syscalls, corresponding to 2,129 Keccak-f permutations
because the eight multi-rate T hashes absorb more than one block.
