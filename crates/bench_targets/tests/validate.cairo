//! In-`__validate__` benchmark scenario (paired-test subtraction).
//!
//! `bench_validate_<scheme>` deploys the account mock and calls `validate()`;
//! `bench_validate_base_<scheme>` deploys it and sets up the same cheats but does NOT call.
//! validate_cost = bench_validate_<scheme> - bench_validate_base_<scheme>, which cancels the
//! deploy cost and isolates the realistic validation call (tx-info read + storage read +
//! deserialization + verify + dispatch).

use openzeppelin_testing::constants::stark::KEY_PAIR;
use openzeppelin_testing::declare_and_deploy;
use openzeppelin_testing::signing::SerializedSigning;
use pqbench_falcon_512::fixtures::{blake, poseidon, shake};
use pqbench_slh_dsa_sha2_128s::fixtures as slh_dsa;
use pqbench_slh_dsa_shake_128s::fixtures as slh_dsa_shake;
use pqbench_targets::{IValidateBenchDispatcher, IValidateBenchDispatcherTrait};
use snforge_std::{start_cheat_signature_global, start_cheat_transaction_hash_global};

const MSG: felt252 = 'BENCH_MSG';

/// Falcon accounts take the 29-felt public key as an `Array<felt252>` constructor arg,
/// so the deploy calldata is its Serde encoding (length-prefixed).
fn falcon_calldata() -> Array<felt252> {
    let mut calldata = array![];
    blake::public_key().serialize(ref calldata);
    calldata
}

/// The SHAKE fixture has its own keypair, so its deploy calldata is that key's encoding.
fn falcon_shake_calldata() -> Array<felt252> {
    let mut calldata = array![];
    shake::public_key().serialize(ref calldata);
    calldata
}

/// The Poseidon fixture has its own keypair, so its deploy calldata is that key's encoding.
fn falcon_poseidon_calldata() -> Array<felt252> {
    let mut calldata = array![];
    poseidon::public_key().serialize(ref calldata);
    calldata
}

/// The SLH-DSA account stores its two-felt `PK.seed || PK.root` public key.
fn slh_dsa_calldata() -> Array<felt252> {
    let mut calldata = array![];
    slh_dsa::public_key().serialize(ref calldata);
    calldata
}

/// The SLH-DSA-SHAKE account stores its two-felt `PK.seed || PK.root` public key.
fn slh_dsa_shake_calldata() -> Array<felt252> {
    let mut calldata = array![];
    slh_dsa_shake::public_key().serialize(ref calldata);
    calldata
}

/// The direct variant's 31-felt signature is the `s1 ‖ salt` prefix of the hint signature.
fn signature_direct() -> Array<felt252> {
    let mut out = array![];
    let mut prefix = blake::signature().span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

/// The SHAKE direct signature: the 31-felt `s1 ‖ salt` prefix of the SHAKE hint fixture.
fn signature_shake_direct() -> Array<felt252> {
    let mut out = array![];
    let mut prefix = shake::signature().span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

#[test]
fn bench_validate_base_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let address = declare_and_deploy("EcdsaStarkAccount", array![key_pair.public_key]);
    start_cheat_transaction_hash_global(MSG);
    start_cheat_signature_global(signature.span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(signature.len() == 2);
}

#[test]
fn bench_validate_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let address = declare_and_deploy("EcdsaStarkAccount", array![key_pair.public_key]);
    start_cheat_transaction_hash_global(MSG);
    start_cheat_signature_global(signature.span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512() {
    let address = declare_and_deploy("Falcon512Account", falcon_calldata());
    start_cheat_transaction_hash_global(blake::msg());
    start_cheat_signature_global(blake::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(blake::signature().len() == 60);
}

#[test]
fn bench_validate_falcon_512() {
    let address = declare_and_deploy("Falcon512Account", falcon_calldata());
    start_cheat_transaction_hash_global(blake::msg());
    start_cheat_signature_global(blake::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_direct() {
    let address = declare_and_deploy("Falcon512DirectAccount", falcon_calldata());
    start_cheat_transaction_hash_global(blake::msg());
    start_cheat_signature_global(signature_direct().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(signature_direct().len() == 31);
}

#[test]
fn bench_validate_falcon_512_direct() {
    let address = declare_and_deploy("Falcon512DirectAccount", falcon_calldata());
    start_cheat_transaction_hash_global(blake::msg());
    start_cheat_signature_global(signature_direct().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_shake() {
    let address = declare_and_deploy("Falcon512ShakeAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(shake::msg());
    start_cheat_signature_global(shake::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(shake::signature().len() == 60);
}

#[test]
fn bench_validate_falcon_512_shake() {
    let address = declare_and_deploy("Falcon512ShakeAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(shake::msg());
    start_cheat_signature_global(shake::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_poseidon() {
    let address = declare_and_deploy("Falcon512PoseidonAccount", falcon_poseidon_calldata());
    start_cheat_transaction_hash_global(poseidon::msg());
    start_cheat_signature_global(poseidon::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(poseidon::signature().len() == 60);
}

#[test]
fn bench_validate_falcon_512_poseidon() {
    let address = declare_and_deploy("Falcon512PoseidonAccount", falcon_poseidon_calldata());
    start_cheat_transaction_hash_global(poseidon::msg());
    start_cheat_signature_global(poseidon::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_shake_direct() {
    let address = declare_and_deploy("Falcon512ShakeDirectAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(shake::msg());
    start_cheat_signature_global(signature_shake_direct().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(signature_shake_direct().len() == 31);
}

#[test]
fn bench_validate_falcon_512_shake_direct() {
    let address = declare_and_deploy("Falcon512ShakeDirectAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(shake::msg());
    start_cheat_signature_global(signature_shake_direct().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_slh_dsa_sha2_128s() {
    let address = declare_and_deploy("SlhDsaSha2_128sAccount", slh_dsa_calldata());
    start_cheat_transaction_hash_global(slh_dsa::message());
    start_cheat_signature_global(slh_dsa::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(slh_dsa::signature().len() == 491);
}

#[test]
fn bench_validate_slh_dsa_sha2_128s() {
    let address = declare_and_deploy("SlhDsaSha2_128sAccount", slh_dsa_calldata());
    start_cheat_transaction_hash_global(slh_dsa::message());
    start_cheat_signature_global(slh_dsa::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_slh_dsa_shake_128s() {
    let address = declare_and_deploy("SlhDsaShake128sAccount", slh_dsa_shake_calldata());
    start_cheat_transaction_hash_global(slh_dsa_shake::message());
    start_cheat_signature_global(slh_dsa_shake::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(slh_dsa_shake::signature().len() == 491);
}

#[test]
fn bench_validate_slh_dsa_shake_128s() {
    let address = declare_and_deploy("SlhDsaShake128sAccount", slh_dsa_shake_calldata());
    start_cheat_transaction_hash_global(slh_dsa_shake::message());
    start_cheat_signature_global(slh_dsa_shake::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}
