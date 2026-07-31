# AGENTS.md — conventions for this repository

Guidance for any agent or contributor editing this repo. Follow it so the project stays
consistent and publish-ready. (Applies to the whole repository; nested files, if any,
override for their subtree.)

## What this repo is

A **public, self-contained** benchmark comparing post-quantum signature verifiers for a
Starknet account, by on-chain verification cost. The audience is the Starknet/StarkWare
ecosystem and OpenZeppelin. It informs a future production account component, but it is
a standalone project and must read as one.

## Structure

```
crates/
  bench_interface/      # the PqSignatureVerifier trait + validation-cap constants
  ecdsa_stark/          # verifier crate: classical control (cost reference, not PQ)
  falcon_512/           # verifier crate: Falcon-512 — BLAKE2s hint+direct, SHAKE-256 hint+direct, Poseidon
  ml_dsa_44/            # verifier crate: stub
  poseidon_wots/        # verifier crate: stub
  ntt/                  # component crate: shared lazy-reduction NTT engine
  bench_targets/        # account harness: one account contract per verifier (validate scenario)
scripts/
  run_bench.py          # measures every schemes.json pair -> results/results.json
  profile.py            # cairo-profiler step attribution -> augments results.json
  gen_report.py         # results.json -> results/report.html + summary.md
  check_efficiency.py   # the efficiency ratchet gate (make check-eff / make ratchet)
  gen_ntt_tables.py     # proves the NTT engine model + emits its generated tables
  verify_ntt_constants.py  # re-derives the NTT root tables from first principles
  gen_falcon_fixture.py # generates the genuine Falcon fixtures (BLAKE2s + --variant shake|poseidon)
schemes.json            # scheme registry: one entry per verifier variant
efficiency_baseline.json  # the ratchet: pinned L2 gas + steps per benchmark pair
results/                # generated snapshot (never hand-edited)
.github/workflows/      # CI: test suite + efficiency ratchet gate
.tool-versions          # pinned toolchain (asdf); Makefile targets drive everything
pq-accounts/            # SEPARATE sub-project: the DEPLOYABLE accounts, not the harness
  contracts/            #   Cairo accounts — src/accounts/ (one per scheme) + src/utils/
  cli/                  #   Starknet.js deploy/transact CLI + stdio MCP server
  signers/              #   external signers (Falcon Python signer)
  USAGE.md              #   devnet-first deploy + transact guide
  SEPOLIA.md            #   public-network (Sepolia/mainnet) + browser-dapp guide
```

Three crate kinds. **Verifier crates** (one per scheme) implement `PqSignatureVerifier`
and are registered in `schemes.json`. **Component crates** (currently `crates/ntt`)
hold shared building blocks consumed by verifier crates; they are not in `schemes.json`
but carry their own benchmark pairs and ratchet entries, and their correctness argument
must be executable (reference-oracle tests in Cairo plus a Python model in `scripts/`),
not prose. **The account harness** (`crates/bench_targets`) grows with the verifiers
rather than being one thing: it holds one deployable account contract per verifier (one
module each, all exposing the crate-root `IValidateBench` interface), and its
measurements are the schemes' in-`__validate__` costs.

Separately, **`pq-accounts/`** is a sibling sub-project holding the *deployable* accounts
(real SNIP-6 contracts under `contracts/src/accounts/`, with shared interfaces and
execution helpers under `contracts/src/utils/`), a Starknet.js deploy/transact CLI, and
external signers. It is the real on-chain artifact, distinct from the benchmark harness.
Its deploy-and-transact walkthroughs are [`pq-accounts/USAGE.md`](pq-accounts/USAGE.md)
(devnet-first) and [`pq-accounts/SEPOLIA.md`](pq-accounts/SEPOLIA.md) (public networks +
browser dapps), which must stay in sync with the code (see the co-update table).

## What must be updated together

A change is complete only when everything it invalidates is regenerated in the same PR:

| If you change... | Also update... |
|---|---|
| Any measured Cairo code | `make all` (regenerates `results/`), `make check-eff`, and `make ratchet` if numbers improved |
| Any number in `efficiency_baseline.json` | the efficiency tables in the main README and in the owning crate's README |
| A verifier's cost or status | the README snapshot table |
| A scheme's encoding (felt layout, sizes) | `schemes.json` sizes, the crate README, the owning fixture generator (`scripts/gen_falcon_fixture.py` or `scripts/gen_slh_dsa_fixture.py`), and regenerate the fixture |
| The public surface of a measured crate | its benchmark pairs and `efficiency_baseline.json` entries (see below) |
| NTT tables or the engine's arithmetic | `scripts/gen_ntt_tables.py` (model first, then `--emit`), `scripts/verify_ntt_constants.py` must still pass |
| The toolchain (`.tool-versions`) | the README Run section, the `toolchain` field of `efficiency_baseline.json`, and a fresh `make all` |
| The CI workflow's `name:` or filename | the README status badge (its label and URL must match) |
| Registries (`schemes.json`, baseline) | nothing by hand elsewhere — scripts read them; never duplicate their data into docs |
| `pq-accounts` account contracts, CLI, or signers | re-check every command and layout reference in `pq-accounts/USAGE.md` and `pq-accounts/SEPOLIA.md` and update as needed |

Generated files are never hand-edited: `results/*`, `crates/ntt/src/roots_scaled.cairo`,
`crates/ntt/src/roots_felt.cairo`, `crates/ntt/src/bitrev.cairo`,
`crates/falcon_512/src/fixtures/blake.cairo`, `crates/falcon_512/src/fixtures/shake.cairo`,
`crates/falcon_512/src/fixtures/poseidon.cairo`,
`crates/slh_dsa_sha2_128s/src/fixtures.cairo`. Regenerate via the owning script.

## Performance: every public API is regression-checked

Efficiency is a **one-way ratchet**, and it covers the public surface:

- Every public function that does non-trivial work in a measured crate must be covered
  by a **paired benchmark** (a measured test and a baseline test that builds identical
  inputs and omits only the measured call) and a corresponding entry in
  `efficiency_baseline.json` (L2 gas and Cairo steps).
- Adding a public function means adding its pair and entry **in the same PR** (seed the
  numbers with `make ratchet`).
- CI (`.github/workflows/efficiency.yml`) fails any change that raises a pinned number.
  Run `make check-eff` before finishing; lock improvements with `make ratchet`.
- Raising a baseline entry is a deliberate human decision, justified explicitly in the
  commit that needs it — never "adjusted" to make CI pass.

## Documentation rules

- **Document for the external reader.** Every public function, struct, constant, and
  module carries a doc comment stating what it does, its inputs/outputs and
  preconditions, and where it sits in the flow — written for someone using or auditing
  the code cold on GitHub. Do not write maintainer notes ("TODO for next PR",
  "temporary until X"), internal-process references, or reviewer-directed remarks.
- **Comments describe the current API, behavior, and flow — never a comparison.** Do not
  explain how the code differs from a previous version, another PR, an upstream variant,
  or a rejected alternative ("previously...", "instead of the old...", "unlike PR #N",
  "was X gas"). Those comparisons describe code that does not exist here and go stale
  silently; they belong in commit messages or PR descriptions, not in code.
- **Measured numbers do not belong in code comments.** Costs live in
  `efficiency_baseline.json` and `results/`; READMEs may quote the current snapshot.
  Comments may state structural facts ("at most two reduction passes per transform"),
  not gas figures.
- **No per-file license or provenance headers, ever.** Source files carry no
  `SPDX-FileCopyrightText` / `SPDX-License-Identifier` blocks and no "ported from"
  header comments — not for original code and not for ported code. The repository
  `LICENSE` covers the project and carries the third-party notices that license
  compliance requires; upstream provenance and design decisions belong in commit
  messages and PR descriptions. A file starts directly with its `//!` module doc, which
  describes what the module does in present terms.
- Design rationale is welcome when it explains the current design on its own terms
  (e.g. why lazy reduction is sound, why an offset is a multiple of q) — the test is
  whether the comment still reads true to someone who has never seen any other version.

## The measurement contract (do not break)

- Every verifier implements `PqSignatureVerifier` from `crates/bench_interface`:
  `fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool`.
- Costs are isolated by **paired-test subtraction**. Test names are a fixed convention
  the scripts rely on:
  - bare verify: `bench_verify_<key>` and `bench_baseline_<key>`
  - in-`__validate__`: `bench_validate_<key>` and `bench_validate_base_<key>`
  - components: `bench_<name>` and its declared baseline in `efficiency_baseline.json`
  The baseline must build identical inputs and differ only by omitting the measured call.
- `schemes.json` is the scheme registry. Each entry's `verify_test` / `baseline_test` /
  `validate_test` / `validate_baseline_test` / `contract` must match real test and
  contract names. Sizes (`sig_felts`, `pubkey_felts`) must reflect the real encoding
  once implemented.
- **Never commit unverified cryptography.** A real verifier must be validated by a
  fixture it accepts (a genuine signature) *and* rejects when tampered, before
  `"implemented": true`. Stubs are allowed but must be labelled as such and excluded
  from headline numbers.

## Adding a scheme (the only supported flow)

1. Create `crates/<key>/` with `Scarb.toml`, `src/lib.cairo` (the `PqSignatureVerifier`
   impl), and a short `README.md` (format below).
2. Add `crates/<key>/tests/bench.cairo` with the paired `bench_verify_*` /
   `bench_baseline_*`.
3. (For the realistic scenario) add the scheme's account contract to
   `crates/bench_targets` — a new module implementing `IValidateBench`, mirroring the
   existing per-verifier modules — with paired `bench_validate_*` /
   `bench_validate_base_*` tests.
4. Add `crates/<key>` to `members` in `Scarb.toml`.
5. Add the `schemes.json` entry (`"implemented": true` only once validated by a real
   fixture) and the `efficiency_baseline.json` entries (seed with `make ratchet`).
6. `make all`, then commit the regenerated `results/`.

## README requirements

**Every crate README** has two mandatory parts:

1. A short description of what the crate is and does (a few sentences, external-reader
   voice), plus links to deeper detail (spec / NIST FIPS / reference implementation /
   the crate's executable correctness argument).
2. A **current-efficiency table** with one row per ratchet entry the crate owns, showing
   both **L2 gas and Cairo steps** (the values in `efficiency_baseline.json`). Stub
   crates state that no measurements exist yet instead of a table.

Verifier crates open with `**Scheme:** <name>, <family>, <standardization status>.`;
component crates with `**Component:** <what it provides>.`; both carry a
`**Status:** <measured | stub (pending implementation)>.` line. The account harness
(`bench_targets`) additionally lists its per-verifier module layout, and its efficiency
table has **one row per verifier account** — it grows with every scheme that gains a
validate scenario.

**The main README** must:

- show the current efficiency (L2 gas and steps) of **every measured entry across all
  crates** — verifier and component/helper crates (e.g. the NTT engine) alike — sourced
  from `efficiency_baseline.json`;
- **link to every crate** it mentions (tables and prose alike);
- never reference pull requests, issues, or repository history — it describes the
  current state only (history lives in commit messages).

## Repo basics

- **Self-contained.** Dependencies come from the Scarb registry only; never path-depend
  on anything outside this repository. The internal `pqbench_*` crates may path-depend
  on each other.
- **Write for an external reader everywhere** — READMEs, docs, and code alike. No
  references to internal libraries, monorepos, or private processes.
- **Keep the toolchain pinned** in `.tool-versions`; if you change it, say why in the
  README.

## Verify before you finish

All of these must pass, in this order:

```
scarb fmt            # formatting
make test            # full test suite
make check-eff       # no efficiency regressions (ratchet improvements if any)
make all             # results/ regenerate without errors
python3 scripts/gen_ntt_tables.py && python3 scripts/verify_ntt_constants.py
```

Finally, re-read your diff against the Documentation rules: no comparison comments, no
maintainer-facing notes, every new public item documented.
