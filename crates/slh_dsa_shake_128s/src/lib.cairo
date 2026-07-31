//! SLH-DSA-SHAKE-128s signature verification (FIPS 205).
//!
//! The verifier implements the pure SLH-DSA external interface with an empty context over
//! the transaction hash serialized as a 32-byte big-endian message. It reconstructs the
//! FORS public key and all seven XMSS layers of the hypertree, using Starknet's native
//! Keccak syscall with the SHAKE256 domain separator for the FIPS 205 category-1 hash
//! instantiation.
//!
//! Each 16-byte SLH-DSA string is encoded as one felt, interpreted in big-endian byte order.
//! This aligns calldata with the scheme's native element boundaries and makes every element
//! canonical by requiring it to fit in `u128`.

pub mod fixtures;
use core::integer::u128_byte_reverse;
use pqbench_interface::PqSignatureVerifier;
use starknet::SyscallResultTrait;

/// Number of felts in a public key: `PK.seed || PK.root`, one 16-byte value per felt.
pub const PUBKEY_FELTS: u32 = 2;
/// Number of felts in a signature: 7,856 bytes as 491 16-byte values.
pub const SIG_FELTS: u32 = 491;

const FORS_HEIGHT: u32 = 12;
const FORS_TREES: u32 = 14;
const FORS_TREE_SIZE: u32 = 4096;
const FORS_SIG_NODES: u32 = 182;
const WOTS_LEN: u32 = 35;
const XMSS_HEIGHT: u32 = 9;
const XMSS_SIG_NODES: u32 = 44;
const HT_LAYERS: u32 = 7;
const HT_SIG_OFFSET: u32 = 183;
const TREE_MASK: u64 = 0x3fffffffffffff;
const LEAF_MASK: u32 = 0x1ff;

const WOTS_HASH: u8 = 0;
const WOTS_PK: u8 = 1;
const TREE: u8 = 2;
const FORS_TREE: u8 = 3;
const FORS_ROOTS: u8 = 4;

/// The full 32-byte address used by FIPS 205's SHAKE parameter sets.
#[derive(Copy, Drop)]
struct Address {
    layer: u8,
    tree: u64,
    address_type: u8,
    key_pair: u32,
    chain_or_height: u32,
    hash_or_index: u32,
}

/// A 16-byte SLH-DSA string in the two little-endian lanes absorbed by Keccak.
#[derive(Copy, Drop)]
struct Node {
    lane0: u64,
    lane1: u64,
}

/// Invariant lanes of `PK.seed || ADRS`; the final ADRS lane is supplied per hash.
#[derive(Copy, Drop)]
struct HashPrefix {
    seed0: u64,
    seed1: u64,
    address0: u64,
    address1: u64,
    address2: u64,
}

fn zero_address() -> Address {
    Address {
        layer: 0, tree: 0, address_type: 0, key_pair: 0, chain_or_height: 0, hash_or_index: 0,
    }
}

fn set_type_and_clear(ref address: Address, address_type: u8) {
    address.address_type = address_type;
    address.key_pair = 0;
    address.chain_or_height = 0;
    address.hash_or_index = 0;
}

fn node_from_u128(value: u128) -> Node {
    let (high, low) = DivRem::div_rem(u128_byte_reverse(value), 0x10000000000000000);
    Node { lane0: low.try_into().unwrap(), lane1: high.try_into().unwrap() }
}

fn node_from_digest(digest: u256) -> Node {
    let (high, low) = DivRem::div_rem(digest.low, 0x10000000000000000);
    Node { lane0: low.try_into().unwrap(), lane1: high.try_into().unwrap() }
}

/// Packs the invariant first three ADRS lanes alongside the public-seed lanes.
fn hash_prefix(pk_seed: Node, address: Address) -> HashPrefix {
    let layer: u128 = address.layer.into();
    let tree: u128 = address.tree.into();
    let address_type: u128 = address.address_type.into();
    let key_pair: u128 = address.key_pair.into();
    let first = layer * 0x1000000000000000000000000 + tree;
    let second = address_type * 0x1000000000000000000000000 + key_pair * 0x10000000000000000;
    let first = node_from_u128(first);
    let second = node_from_u128(second);
    HashPrefix {
        seed0: pk_seed.lane0,
        seed1: pk_seed.lane1,
        address0: first.lane0,
        address1: first.lane1,
        address2: second.lane0,
    }
}

/// Packs the final ADRS lane when the two fields fit the SHAKE-128s bounds.
#[inline(always)]
fn address_last_lane(chain_or_height: u32, hash_or_index: u32) -> u64 {
    let (index_high, index_low) = DivRem::div_rem(hash_or_index, 256);
    let chain: u64 = chain_or_height.into();
    let index_high: u64 = index_high.into();
    let index_low: u64 = index_low.into();
    chain * 0x1000000 + index_high * 0x1000000000000 + index_low * 0x100000000000000
}

/// Packs the final ADRS lane for WOTS+ fields, both of which fit in one byte.
#[inline(always)]
fn wots_address_last_lane(chain: u32, hash_index: u32) -> u64 {
    let chain: u64 = chain.into();
    let hash_index: u64 = hash_index.into();
    chain * 0x1000000 + hash_index * 0x100000000000000
}

/// Applies SHAKE256 padding and returns the first 32 output bytes as a little-endian u256.
fn shake256(ref input: Array<u64>) -> u256 {
    // The syscall's rate is 17 u64 lanes. SHAKE uses domain byte 0x1f and pad10*1.
    if input.len() % 17 == 16 {
        input.append(0x800000000000001f);
        return starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall();
    }
    input.append(0x1f);
    while input.len() % 17 != 16 {
        input.append(0);
    }
    input.append(0x8000000000000000);
    starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall()
}

#[inline(always)]
fn f_hash(prefix: HashPrefix, address3: u64, value: Node) -> Node {
    let input = [
        prefix.seed0, prefix.seed1, prefix.address0, prefix.address1, prefix.address2, address3,
        value.lane0, value.lane1, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0x8000000000000000,
    ];
    node_from_digest(starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall())
}

#[inline(always)]
fn h_hash(prefix: HashPrefix, address3: u64, left: Node, right: Node) -> Node {
    let input = [
        prefix.seed0, prefix.seed1, prefix.address0, prefix.address1, prefix.address2, address3,
        left.lane0, left.lane1, right.lane0, right.lane1, 0x1f, 0, 0, 0, 0, 0, 0x8000000000000000,
    ];
    node_from_digest(starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall())
}

fn t_hash(prefix: HashPrefix, mut values: Span<Node>) -> Node {
    let mut input = array![
        prefix.seed0, prefix.seed1, prefix.address0, prefix.address1, prefix.address2, 0,
    ];
    while let Some(value) = values.pop_front() {
        input.append((*value).lane0);
        input.append((*value).lane1);
    }
    node_from_digest(shake256(ref input))
}

fn append_le_bytes(mut value: u128, count: u32, ref out: Array<u8>) {
    let mut i = 0;
    while i != count {
        out.append((value % 256).try_into().unwrap());
        value /= 256;
        i += 1;
    }
}

fn h_msg(message_hash: felt252, randomizer: Node, pk_seed: Node, pk_root: Node) -> Array<u8> {
    // H_msg = SHAKE256(R || PK.seed || PK.root || M', 30), with M' = 0x00 || 0x00 || M.
    let message: u256 = message_hash.into();
    let high = node_from_u128(message.high);
    let low = node_from_u128(message.low);
    let (m0_high, m0_low) = DivRem::div_rem(high.lane0, 0x1000000000000);
    let (m1_high, m1_low) = DivRem::div_rem(high.lane1, 0x1000000000000);
    let (m2_high, m2_low) = DivRem::div_rem(low.lane0, 0x1000000000000);
    let (m3_high, m3_low) = DivRem::div_rem(low.lane1, 0x1000000000000);
    let input = [
        randomizer.lane0, randomizer.lane1, pk_seed.lane0, pk_seed.lane1, pk_root.lane0,
        pk_root.lane1, m0_low * 0x10000, m0_high + m1_low * 0x10000, m1_high + m2_low * 0x10000,
        m2_high + m3_low * 0x10000, m3_high + 0x1f0000, 0, 0, 0, 0, 0, 0x8000000000000000,
    ];
    let digest = starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall();
    let mut out = array![];
    append_le_bytes(digest.low, 16, ref out);
    append_le_bytes(digest.high, 14, ref out);
    out
}

fn fors_indices(md: Span<u8>) -> Array<u32> {
    let mut indices = array![];
    let mut i = 0;
    while i != 21 {
        let b0: u32 = (*md.at(i)).into();
        let b1: u32 = (*md.at(i + 1)).into();
        let b2: u32 = (*md.at(i + 2)).into();
        indices.append(b0 * 16 + b1 / 16);
        indices.append((b1 % 16) * 256 + b2);
        i += 3;
    }
    indices
}

fn append_wots_lane(mut lane: u64, ref digits: Array<u32>, ref checksum: u32) {
    let mut i = 0;
    while i != 8 {
        let (remaining, byte) = DivRem::div_rem(lane, 256);
        let (high, low) = DivRem::div_rem(byte, 16);
        let high: u32 = high.try_into().unwrap();
        let low: u32 = low.try_into().unwrap();
        digits.append(high);
        digits.append(low);
        checksum += 30 - high - low;
        lane = remaining;
        i += 1;
    }
}

fn wots_digits(message: Node) -> Array<u32> {
    let mut digits = array![];
    let mut checksum = 0;
    append_wots_lane(message.lane0, ref digits, ref checksum);
    append_wots_lane(message.lane1, ref digits, ref checksum);
    let (high, low_byte) = DivRem::div_rem(checksum, 256);
    let (middle, low) = DivRem::div_rem(low_byte, 16);
    digits.append(high);
    digits.append(middle);
    digits.append(low);
    digits
}

fn wots_pk_from_sig(
    signature: Span<Node>, message: Node, pk_seed: Node, mut address: Address,
) -> Node {
    let digits = wots_digits(message);
    let mut endpoints = array![];
    let key_pair = address.key_pair;
    let prefix = hash_prefix(pk_seed, address);
    let mut i = 0;
    while i != WOTS_LEN {
        let start = *digits.at(i);
        let mut node = *signature.at(i);
        let mut j = start;
        while j != 15 {
            node = f_hash(prefix, wots_address_last_lane(i, j), node);
            j += 1;
        }
        endpoints.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, WOTS_PK);
    address.key_pair = key_pair;
    t_hash(hash_prefix(pk_seed, address), endpoints.span())
}

fn xmss_pk_from_sig(
    leaf_index: u32, signature: Span<Node>, message: Node, pk_seed: Node, mut address: Address,
) -> Node {
    set_type_and_clear(ref address, WOTS_HASH);
    address.key_pair = leaf_index;
    let mut node = wots_pk_from_sig(signature.slice(0, WOTS_LEN), message, pk_seed, address);

    set_type_and_clear(ref address, TREE);
    let tree_prefix = hash_prefix(pk_seed, address);
    let mut index = leaf_index;
    let mut height = 0;
    while height != XMSS_HEIGHT {
        let auth = *signature.at(WOTS_LEN + height);
        let (parent, side) = DivRem::div_rem(index, 2);
        let address3 = address_last_lane(height + 1, parent);
        if side == 0 {
            node = h_hash(tree_prefix, address3, node, auth);
        } else {
            node = h_hash(tree_prefix, address3, auth, node);
        }
        index = parent;
        height += 1;
    }
    node
}

fn fors_pk_from_sig(
    signature: Span<Node>, md: Span<u8>, pk_seed: Node, mut address: Address,
) -> Node {
    let indices = fors_indices(md);
    let key_pair = address.key_pair;
    let tree_prefix = hash_prefix(pk_seed, address);
    let mut roots = array![];
    let mut i = 0;
    while i != FORS_TREES {
        let index = *indices.at(i);
        let mut tree_index = i * FORS_TREE_SIZE + index;
        let mut node = f_hash(tree_prefix, address_last_lane(0, tree_index), *signature.at(i * 13));
        let mut height = 0;
        while height != FORS_HEIGHT {
            let auth = *signature.at(i * 13 + 1 + height);
            let (parent, side) = DivRem::div_rem(tree_index, 2);
            let address3 = address_last_lane(height + 1, parent);
            if side == 0 {
                node = h_hash(tree_prefix, address3, node, auth);
            } else {
                node = h_hash(tree_prefix, address3, auth, node);
            }
            tree_index = parent;
            height += 1;
        }
        roots.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, FORS_ROOTS);
    address.key_pair = key_pair;
    t_hash(hash_prefix(pk_seed, address), roots.span())
}

fn read_be_u64(mut bytes: Span<u8>) -> u64 {
    let mut value: u64 = 0;
    while let Some(byte) = bytes.pop_front() {
        value = value * 256 + (*byte).into();
    }
    value
}

fn read_be_u32(mut bytes: Span<u8>) -> u32 {
    let mut value: u32 = 0;
    while let Some(byte) = bytes.pop_front() {
        value = value * 256 + (*byte).into();
    }
    value
}

fn hypertree_root(
    signature: Span<Node>, message: Node, pk_seed: Node, mut tree_index: u64, mut leaf_index: u32,
) -> Node {
    let mut address = zero_address();
    address.tree = tree_index;
    let mut node = xmss_pk_from_sig(
        leaf_index, signature.slice(0, XMSS_SIG_NODES), message, pk_seed, address,
    );

    let mut layer = 1;
    while layer != HT_LAYERS {
        let (parent_tree, next_leaf) = DivRem::div_rem(tree_index, 512);
        leaf_index = next_leaf.try_into().unwrap();
        tree_index = parent_tree;
        address.layer = layer.try_into().unwrap();
        address.tree = tree_index;
        node =
            xmss_pk_from_sig(
                leaf_index,
                signature.slice(layer * XMSS_SIG_NODES, XMSS_SIG_NODES),
                node,
                pk_seed,
                address,
            );
        layer += 1;
    }
    node
}

fn decode_signature(mut encoded: Span<felt252>) -> Option<Array<Node>> {
    let mut decoded = array![];
    while let Some(value) = encoded.pop_front() {
        let node: u128 = match (*value).try_into() {
            Some(node) => node,
            None => { return None; },
        };
        decoded.append(node_from_u128(node));
    }
    Some(decoded)
}

/// Verifies a pure FIPS 205 SLH-DSA-SHAKE-128s signature with an empty context.
///
/// `message_hash` is serialized as a 32-byte big-endian message. `public_key` is
/// `PK.seed || PK.root` (2 felts), and `signature` is the 491-element FIPS signature
/// (`R || SIG_FORS || SIG_HT`), with every felt holding one 16-byte element.
/// Malformed lengths and values outside `u128` are rejected.
pub impl SlhDsaShake128sVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        if public_key.len() != PUBKEY_FELTS || signature.len() != SIG_FELTS {
            return false;
        }
        let pk_seed: u128 = match (*public_key.at(0)).try_into() {
            Some(value) => value,
            None => { return false; },
        };
        let pk_root: u128 = match (*public_key.at(1)).try_into() {
            Some(value) => value,
            None => { return false; },
        };
        let signature = match decode_signature(signature) {
            Some(value) => value,
            None => { return false; },
        };
        let pk_seed = node_from_u128(pk_seed);
        let pk_root = node_from_u128(pk_root);
        let digest = h_msg(message_hash, *signature.at(0), pk_seed, pk_root);
        let tree_index = read_be_u64(digest.span().slice(21, 7)) & TREE_MASK;
        let leaf_index = read_be_u32(digest.span().slice(28, 2)) & LEAF_MASK;

        let mut address = zero_address();
        address.tree = tree_index;
        set_type_and_clear(ref address, FORS_TREE);
        address.key_pair = leaf_index;
        let fors_pk = fors_pk_from_sig(
            signature.span().slice(1, FORS_SIG_NODES), digest.span().slice(0, 21), pk_seed, address,
        );
        let root = hypertree_root(
            signature.span().slice(HT_SIG_OFFSET, SIG_FELTS - HT_SIG_OFFSET),
            fors_pk,
            pk_seed,
            tree_index,
            leaf_index,
        );
        root.lane0 == pk_root.lane0 && root.lane1 == pk_root.lane1
    }
}
