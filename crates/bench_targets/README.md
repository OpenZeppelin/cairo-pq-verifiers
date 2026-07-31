# Benchmark accounts

**Component:** the account harness for the in-`__validate__` scenario: one deployable
account contract per verifier.
**Status:** measured (ECDSA-STARK, the five Falcon-512 variants, and
the SHA2 and SHAKE SLH-DSA-128s variants); other PQ verifiers' accounts land as their
schemes are implemented.

Unlike the verifier crates (one scheme each), this crate collects **one account contract
per verifier**, each in its own module. An account wraps its scheme the way a Starknet
account would: `validate()` reads the transaction hash and signature from the transaction
info, loads the stored public key, and runs the scheme's `verify`. Measuring a
deploy-and-call of it (minus a deploy-only baseline) captures the realistic validation
cost (dispatch, signature deserialization, and the key's storage read) on top of bare
verification, and building the contracts yields each scheme's contract-class size.

All accounts expose the same `IValidateBench` interface, defined at the crate root.

```
src/
  lib.cairo          # IValidateBench + one module per verifier account
  ecdsa_stark.cairo  # EcdsaStarkAccount (classical control)
  falcon_512.cairo   # Falcon512Account (hint) + Falcon512DirectAccount (direct)
                     #   + Falcon512ShakeAccount (SHAKE-256) + Falcon512PoseidonAccount
                     #   + Falcon512ShakeDirectAccount (SHAKE-256 direct)
  slh_dsa_sha2_128s.cairo  # SlhDsaSha2_128sAccount (FIPS 205)
  slh_dsa_shake_128s.cairo # SlhDsaShake128sAccount (FIPS 205)
```

## Current efficiency

One row per verifier account. The 100M-L2-gas / 1M-step validation cap is the deployability
threshold. Every Falcon account fits it. The standardized SLH-DSA accounts do not:
reconstructing their FORS and XMSS trees requires thousands of native hash syscalls. The
SHAKE account fits the step cap after packing hashes into native Keccak lanes, but remains
over the L2-gas cap.

| Account | Measurement | L2 gas | Steps |
|---|---|--:|--:|
| `EcdsaStarkAccount` | inside `__validate__` | 160,795 | 1,437 |
| `Falcon512Account` (hint) | inside `__validate__` | 14,380,100 | 119,124 |
| `Falcon512DirectAccount` (direct) | inside `__validate__` | 24,525,310 | 219,565 |
| `Falcon512PoseidonAccount` (Poseidon) | inside `__validate__` | 13,615,909 | 111,950 |
| `Falcon512ShakeAccount` (SHAKE-256) | inside `__validate__` | 51,733,728 | 327,157 |
| `Falcon512ShakeDirectAccount` (SHAKE-256 direct) | inside `__validate__` | 61,878,938 | 427,598 |
| `SlhDsaSha2_128sAccount` (FIPS 205) | inside `__validate__` | 1,803,202,906 | 4,273,118 |
| `SlhDsaShake128sAccount` (FIPS 205) | inside `__validate__` | 410,476,521 | 844,990 |
