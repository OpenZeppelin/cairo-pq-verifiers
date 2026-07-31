# PQ verifiers for Starknet accounts

[![CI](https://img.shields.io/github/actions/workflow/status/OpenZeppelin/cairo-pq-verifiers/efficiency.yml?branch=main&label=CI)](https://github.com/OpenZeppelin/cairo-pq-verifiers/actions/workflows/efficiency.yml)

_Comparing candidate post-quantum signature verifiers for a Starknet account by their
verification cost._

> [!WARNING]
> **Experimental and unaudited.** This repository is intended for research and benchmarking. The verifiers and account contracts have not undergone an independent security audit. This software is provided on an “as is” and “as available” basis, without warranties or liability for any losses incurred through its use.

## Why

Starknet's STARK proofs are post-quantum. The ECDSA signatures that authorize account
transactions are not, and Shor's algorithm could forge them. Because Starknet accounts are
smart contracts (account abstraction), a post-quantum account can ship today by swapping the
check inside `__validate__`, provided that verification fits Starknet's validation limits.
This repo measures which schemes fit, and which is cheapest — and ships deployable
post-quantum accounts you can try today (see below).

## What we measure

For each scheme, the cost of verifying one signature, both alone and inside a real
`__validate__`: L2 gas, Cairo steps, signature and key size, contract class size, and where
the steps go.

Validation is capped at 1,000,000 steps and 100,000,000 L2 gas (blockifier v0.13.4;
both unchanged as of Starknet 0.14.3), so a verifier has to fit under both.

These are resource measurements — steps and builtins priced with the protocol gas table.
Transaction **fees** meter L2 gas differently for Sierra ≥ 1.7 classes and run between
about 1.7× and 2.7× these values, depending on the variant. The CLI prints live receipt
gas; the fee meter and devnet-measured receipts per scheme are documented in
[`pq-accounts/USAGE.md`](pq-accounts/USAGE.md#what-transactions-cost).

## Snapshot

Current efficiency of every measured entry, per crate (the values pinned in
[`efficiency_baseline.json`](efficiency_baseline.json); caps are 100,000,000 L2 gas and
1,000,000 steps):

| Crate | Measurement | L2 gas | Steps | % of gas cap |
|---|---|--:|--:|--:|
| [`ecdsa_stark`](crates/ecdsa_stark) | verify (classical control) | 30,855 | 152 | 0.03% |
| [`falcon_512`](crates/falcon_512) | verify, hint variant (BLAKE2s) | 12,809,640 | 104,854 | 12.8% |
| [`falcon_512`](crates/falcon_512) | verify, direct variant (BLAKE2s) | 23,005,760 | 205,781 | 23.0% |
| [`falcon_512`](crates/falcon_512) | verify, Poseidon variant (native) | 12,045,449 | 97,681 | 12.0% |
| [`falcon_512`](crates/falcon_512) | verify, SHAKE-256 variant (standard) | 50,163,668 | 312,892 | 50.2% |
| [`falcon_512`](crates/falcon_512) | verify, SHAKE-256 direct variant (standard) | 60,359,788 | 413,819 | 60.4% |
| [`slh_dsa_sha2_128s`](crates/slh_dsa_sha2_128s) | verify, FIPS 205 | 1,803,067,376 | 4,271,878 | 1,803.1% |
| [`slh_dsa_shake_128s`](crates/slh_dsa_shake_128s) | verify, FIPS 205 | 410,340,991 | 843,750 | 410.3% |
| [`bench_targets`](crates/bench_targets) | ECDSA-STARK account, inside `__validate__` | 160,795 | 1,437 | 0.16% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 hint account, inside `__validate__` | 14,380,100 | 119,124 | 14.4% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 direct account, inside `__validate__` | 24,525,310 | 219,565 | 24.5% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 Poseidon account, inside `__validate__` | 13,615,909 | 111,950 | 13.6% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 SHAKE-256 account, inside `__validate__` | 51,733,728 | 327,157 | 51.7% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 SHAKE-256 direct account, inside `__validate__` | 61,878,938 | 427,598 | 61.9% |
| [`bench_targets`](crates/bench_targets) | SLH-DSA-SHA2-128s account, inside `__validate__` | 1,803,202,906 | 4,273,118 | 1,803.2% |
| [`bench_targets`](crates/bench_targets) | SLH-DSA-SHAKE-128s account, inside `__validate__` | 410,476,521 | 844,990 | 410.5% |
| [`ntt`](crates/ntt) | forward 512-point transform | 8,895,740 | 81,826 | 8.9% |
| [`ntt`](crates/ntt) | forward transform, unreduced output | 7,832,270 | 73,587 | 7.8% |
| [`ntt`](crates/ntt) | generated Falcon-512 transform, felt input | 2,137,010 | 15,635 | 2.1% |
| [`ntt`](crates/ntt) | generated Falcon-512 transform, `u16` input | 2,137,010 | 15,635 | 2.1% |
| [`ntt`](crates/ntt) | forward + inverse roundtrip | 22,725,980 | 211,044 | 22.7% |
| [`ml_dsa_44`](crates/ml_dsa_44) | verify | stub (not yet measured) | — | — |
| [`poseidon_wots`](crates/poseidon_wots) | verify | stub (not yet measured) | — | — |

ECDSA-STARK is the classical scheme in use today, a cost reference rather than a PQ
candidate. Falcon-512 is the first PQ verifier measured, in five variants that share one
NTT-domain public key and a canonical 29-felt base-Q encoding. Packed coefficients are
validated and decoded directly to `u16`. The hint variants use two generated, fully unrolled
Falcon-512 forward transforms from the shared [`ntt`](crates/ntt) crate, followed by a fused
pointwise hint check and norm pass. The two direct variants (`falcon_512_direct`,
`falcon_512_shake_direct`) instead compute `INTT(NTT(s1) ∘ h_ntt)`, using the generated
forward transform and the generic inverse engine. They trade a more expensive inverse
transform for almost half the signature calldata (31 vs 60 felts) and no signer-supplied
hint. The variants otherwise differ only in the on-chain hash-to-point that binds the
message:

- **BLAKE2s** (hint and direct): a non-standard XOF swap via the `core::blake` builtin.
  Nearly the cheapest, but needs a matching signer.
- **Poseidon**: a native `hades_permutation` squeeze. Message-binding, the cheapest variant
  (marginally below BLAKE2s), and the most STARK-proving-friendly since it uses native field
  arithmetic. Also non-standard.
- **SHAKE-256**: the standard Falcon hash-to-point, interoperable with any compliant signer
  (e.g. falcon.py). The pure-Cairo Keccak-f[1600] (flat unrolled rounds, u128 lanes, lazy
  block squeezing) dominates this backend, so even the standards-compliant variant fits
  both validation caps. Its bare hint verifier uses about 4.2× the gas and 3.2× the steps
  of the native-Poseidon variant. A native
  `keccak_f1600` syscall ([SNIP-32](https://github.com/starknet-io/SNIPs)) would close the
  remaining gap. It comes in hint and direct forms; `falcon_512_shake_direct` carries no
  hint, mirroring a bare FIPS signature most closely, and is the most expensive of the five.

All five use genuine falcon.py-signed fixtures and fit the validation caps — the non-standard
variants with wide margin, and the SHAKE-256 accounts at 51.7–61.9% of the gas cap and
32.7–42.8% of the step cap.

The two SLH-DSA crates measure standardized, stateless hash-based alternatives at the same
NIST category. Both use the smallest FIPS 205 signature: 7,856 bytes, encoded as 491
16-byte felts, with a 32-byte public key. They accept genuine signatures from the
interoperable slhdsa-c implementation and differ only in FIPS 205's hash instantiation:

- [`slh_dsa_sha2_128s`](crates/slh_dsa_sha2_128s) packs preimages into SHA-256 words and
  reuses the invariant public-seed prefix state. Its 2,094 native compression calls
  dominate the remaining 1.80 billion L2 gas and 4.27 million steps.
- [`slh_dsa_shake_128s`](crates/slh_dsa_shake_128s) keeps preimages in native Keccak lanes
  and applies explicit SHAKE256 padding around Starknet's Keccak syscall. It cuts the bare
  cost to 410 million L2 gas and 843,750 steps—77.2% less gas and 80.3% fewer steps than
  SHA2. The account fits the step cap at 84.5%, but is still 4.10× over the gas cap.

Neither standard parameter set is therefore deployable inside `__validate__` under both
measured protocol limits. For SHA2, 97.9% of gas is already the native syscall floor; even
an idealized SHAKE signature with the minimum possible WOTS+ chains cannot meet the gas cap.

All five derive the message point on-chain from `message_hash`, which binds the signature to
the message. At s2morrow commit `4eff9ab`, its packed Poseidon verifier measures 81,212 steps
with Scarb 2.15.1 and Starknet Foundry 0.55.0, versus 97,681 here with Scarb 2.18.0 and
Starknet Foundry 0.59.0. That comparison is directional, not protocol-equivalent:
[s2morrow](https://github.com/feltroidprime/s2morrow) uses a different Poseidon
absorb-and-extract construction, while this verifier preserves its existing 16-bit-word
rejection stream. The NTT and packing costs here are already comparable to or below
s2morrow's; the remaining gap is concentrated in hash-to-point and the fused verification
core. Each variant also has an account contract measured inside `__validate__`, where the
realistic cost sits just above bare verify (the verifier dominates; dispatch, the 29-slot key
read, and deserialization are small). ML-DSA-44 and Poseidon-WOTS+ remain stubs behind the
same interface.

## Try the accounts

[`pq-accounts/`](pq-accounts) holds deployable SNIP-6 account contracts for the measured
verifiers that fit validation, plus three ways to drive them: a CLI whose devnet quickstart
declares, funds, deploys, and transacts in one command; an MCP server exposing the same
operations to LLM clients; and a local wallet daemon that plugs the accounts into browser
dapps (they appear in Voyager's connect-wallet dialog and sign contract calls with Falcon).
The walkthrough is [`pq-accounts/USAGE.md`](pq-accounts/USAGE.md), including deploying to
Sepolia.

## Report

`make report` regenerates these from the latest run:

```
results/report.html      # standalone HTML: sortable table, charts, profiler attribution
results/summary.md       # text summary
results/results.json     # raw data plus metadata
```

## Run

The toolchain is pinned in `.tool-versions` (Scarb 2.18.0, Starknet Foundry 0.59.0,
cairo-profiler 0.16.0, plus starknet-devnet 0.9.0 for the
[`pq-accounts`](pq-accounts/USAGE.md) walkthrough). Install it with
[asdf](https://asdf-vm.com) or [starkup](https://github.com/software-mansion/starkup).

```bash
make all        # measure, profile, then render the report
make test       # run the test suite
make check-eff  # efficiency ratchet: fail if any tracked cost regressed
make ratchet    # lock measured improvements into efficiency_baseline.json
```

Efficiency is a one-way ratchet: `efficiency_baseline.json` pins the cost of every
tracked benchmark pair (L2 gas and steps), CI fails any change that raises a number,
and improvements are committed via `make ratchet`.

## Schemes

| Crate | Scheme | Family | Standardization |
|---|---|---|---|
| [`ecdsa_stark`](crates/ecdsa_stark) | ECDSA-STARK | classical EC (control) | none |
| [`falcon_512`](crates/falcon_512) | Falcon-512 (FN-DSA); BLAKE2s hint+direct, SHAKE-256 hint+direct, Poseidon variants | lattice (NTRU) | draft, FIPS 206 (standard SHAKE-256; non-standard BLAKE2s / Poseidon) |
| [`slh_dsa_sha2_128s`](crates/slh_dsa_sha2_128s) | SLH-DSA-SHA2-128s | hash-based (stateless) | final, FIPS 205 |
| [`slh_dsa_shake_128s`](crates/slh_dsa_shake_128s) | SLH-DSA-SHAKE-128s | hash-based (stateless) | final, FIPS 205 |
| [`ml_dsa_44`](crates/ml_dsa_44) | ML-DSA-44 (Dilithium) | lattice (module) | final, FIPS 204 |
| [`poseidon_wots`](crates/poseidon_wots) | Poseidon-WOTS+ | hashing | not standardized |

## Method

Every scheme implements the one interface in
[`crates/bench_interface`](crates/bench_interface); each cost is the measured test minus a
baseline test that builds the same inputs but omits the verify call. Bare verify covers the
function alone. The validate scenario deploys an account mock from
[`crates/bench_targets`](crates/bench_targets) and calls it, which adds dispatch,
signature deserialization, and a storage read. Numbers come from Starknet Foundry (gas,
steps, builtins), a release build (class size), and cairo-profiler (attribution by
function).

## Layout

```
crates/
  bench_interface/   # the common PqSignatureVerifier interface plus cap constants
  ecdsa_stark/       # one crate per scheme (see each crate's README)
  falcon_512/
  slh_dsa_sha2_128s/
  slh_dsa_shake_128s/
  ml_dsa_44/
  poseidon_wots/
  ntt/               # generic NTT engine + generated Falcon-512 forward path
  bench_targets/     # one account contract per verifier, for the validate scenario
scripts/             # run_bench.py, profile.py, gen_report.py, check_efficiency.py
schemes.json         # the scheme registry
efficiency_baseline.json  # the efficiency ratchet (CI-enforced)
results/             # generated report plus committed snapshot
pq-accounts/         # deployable accounts + CLI, MCP server, browser wallet (USAGE.md)
```

Adding a scheme is documented in [`AGENTS.md`](AGENTS.md).

## References

- Falcon / FN-DSA: [spec](https://falcon-sign.info/falcon.pdf) ·
  [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-DSA / FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) ·
  [SLH-DSA / FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf)
- Reference Falcon wallet on Starknet: [s2morrow](https://github.com/feltroidprime/s2morrow)
- Starknet [fees](https://docs.starknet.io/learn/protocol/fees) ·
  [accounts](https://docs.starknet.io/learn/protocol/accounts)

## License

MIT. See [LICENSE](LICENSE).
