//! Benchmark and correctness scenarios for SLH-DSA-SHA2-128s.
//!
//! The paired benchmark builds identical genuine FIPS 205 inputs in both tests and
//! subtracts the baseline from the verifier call. Correctness is pinned by accepting the
//! reference-generated signature and rejecting a canonical but modified signature.

use pqbench_slh_dsa_sha2_128s::SlhDsaSha2_128sVerifier;
use pqbench_slh_dsa_sha2_128s::fixtures::{message, public_key, signature};

/// Builds the genuine fixture without invoking the verifier.
#[test]
fn bench_baseline_slh_dsa_sha2_128s() {
    let pk = public_key();
    let sig = signature();
    assert!(pk.len() == 2 && sig.len() == 491);
}

/// Measures verification of a genuine SLH-DSA-SHA2-128s signature.
#[test]
fn bench_verify_slh_dsa_sha2_128s() {
    let valid = SlhDsaSha2_128sVerifier::verify(message(), public_key().span(), signature().span());
    assert!(valid);
}

#[test]
fn test_slh_dsa_sha2_128s_rejects_tampered_signature() {
    let original = signature();
    let mut tampered = array![];
    let mut i = 0;
    while i != original.len() {
        let value = *original.at(i);
        tampered.append(if i == 0 {
            value + 1
        } else {
            value
        });
        i += 1;
    }
    assert!(!SlhDsaSha2_128sVerifier::verify(message(), public_key().span(), tampered.span()));
}

#[test]
fn test_slh_dsa_sha2_128s_rejects_bad_lengths() {
    assert!(
        !SlhDsaSha2_128sVerifier::verify(
            message(), public_key().span().slice(0, 1), signature().span(),
        ),
    );
    assert!(
        !SlhDsaSha2_128sVerifier::verify(
            message(), public_key().span(), signature().span().slice(0, 490),
        ),
    );
}
