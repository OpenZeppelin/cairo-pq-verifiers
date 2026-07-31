//! Account contracts for the in-`__validate__` benchmark scenario — one per verifier.
//!
//! Each verifier gets its own module holding a deployable account contract that wraps the
//! scheme the way a Starknet account would: it stores the scheme's public key and exposes
//! `validate()`, which reads the transaction hash and signature from the transaction info,
//! loads the stored key, and runs the scheme's `verify`. Measuring a deploy-and-call of it
//! (minus a deploy-only baseline) captures the realistic validation cost — calldata
//! deserialization, storage read, dispatch, and verification — not just the bare verify.
//! Building these contracts also yields each scheme's contract-class size.

pub mod ecdsa_stark;
pub mod falcon_512;
pub mod slh_dsa_sha2_128s;
pub mod slh_dsa_shake_128s;

/// Minimal account-validation surface every benchmark account exposes.
#[starknet::interface]
pub trait IValidateBench<TState> {
    fn validate(self: @TState) -> felt252;
}
