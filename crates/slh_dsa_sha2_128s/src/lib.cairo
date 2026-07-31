//! SLH-DSA-SHA2-128s signature verification (FIPS 205).
//!
//! The verifier implements the pure SLH-DSA external interface with an empty context over
//! the transaction hash serialized as a 32-byte big-endian message. It reconstructs the
//! FORS public key and all seven XMSS layers of the hypertree, using Starknet's native
//! SHA-256 block-processing syscall for the FIPS 205 category-1 hash instantiation.
//!
//! Each 16-byte SLH-DSA string is encoded as one felt, interpreted in big-endian byte order.
//! This aligns calldata with the scheme's native element boundaries and makes every element
//! canonical by requiring it to fit in `u128`.

pub mod fixtures;
use core::sha256::compute_sha256_byte_array;
use pqbench_interface::PqSignatureVerifier;

/// Number of felts in a public key: `PK.seed || PK.root`, one 16-byte value per felt.
pub const PUBKEY_FELTS: u32 = 2;
/// Number of felts in a signature: 7,856 bytes as 491 16-byte values.
pub const SIG_FELTS: u32 = 491;

const N: u32 = 16;
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

/// The compressed 22-byte address used by FIPS 205's SHA2 parameter sets.
#[derive(Copy, Drop)]
struct Address {
    layer: u8,
    tree: u64,
    address_type: u8,
    key_pair: u32,
    chain_or_height: u32,
    hash_or_index: u32,
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

fn append_address(ref data: ByteArray, address: Address) {
    data.append_word(address.layer.into(), 1);
    data.append_word(address.tree.into(), 8);
    data.append_word(address.address_type.into(), 1);
    data.append_word(address.key_pair.into(), 4);
    data.append_word(address.chain_or_height.into(), 4);
    data.append_word(address.hash_or_index.into(), 4);
}

fn append_digest(ref data: ByteArray, digest: [u32; 8]) {
    let [d0, d1, d2, d3, d4, d5, d6, d7] = digest;
    data.append_word(d0.into(), 4);
    data.append_word(d1.into(), 4);
    data.append_word(d2.into(), 4);
    data.append_word(d3.into(), 4);
    data.append_word(d4.into(), 4);
    data.append_word(d5.into(), 4);
    data.append_word(d6.into(), 4);
    data.append_word(d7.into(), 4);
}

fn digest_node(digest: [u32; 8]) -> u128 {
    let [d0, d1, d2, d3, _, _, _, _] = digest;
    let value: felt252 = d0.into() * 0x1000000000000000000000000
        + d1.into() * 0x10000000000000000
        + d2.into() * 0x100000000
        + d3.into();
    value.try_into().unwrap()
}

fn append_u32_bytes(word: u32, ref out: Array<u8>) {
    out.append((word / 0x1000000).try_into().unwrap());
    out.append(((word / 0x10000) % 0x100).try_into().unwrap());
    out.append(((word / 0x100) % 0x100).try_into().unwrap());
    out.append((word % 0x100).try_into().unwrap());
}

fn digest_bytes_30(digest: [u32; 8]) -> Array<u8> {
    let [d0, d1, d2, d3, d4, d5, d6, d7] = digest;
    let mut out = array![];
    append_u32_bytes(d0, ref out);
    append_u32_bytes(d1, ref out);
    append_u32_bytes(d2, ref out);
    append_u32_bytes(d3, ref out);
    append_u32_bytes(d4, ref out);
    append_u32_bytes(d5, ref out);
    append_u32_bytes(d6, ref out);
    out.append((d7 / 0x1000000).try_into().unwrap());
    out.append(((d7 / 0x10000) % 0x100).try_into().unwrap());
    out
}

fn hash_prefix(pk_seed: u128, address: Address) -> ByteArray {
    let mut data: ByteArray = "";
    data.append_word(pk_seed.into(), N);
    data.append_word(0, 31);
    data.append_word(0, 17);
    append_address(ref data, address);
    data
}

fn f_hash(pk_seed: u128, address: Address, value: u128) -> u128 {
    let mut data = hash_prefix(pk_seed, address);
    data.append_word(value.into(), N);
    digest_node(compute_sha256_byte_array(@data))
}

fn h_hash(pk_seed: u128, address: Address, left: u128, right: u128) -> u128 {
    let mut data = hash_prefix(pk_seed, address);
    data.append_word(left.into(), N);
    data.append_word(right.into(), N);
    digest_node(compute_sha256_byte_array(@data))
}

fn t_hash(pk_seed: u128, address: Address, mut values: Span<u128>) -> u128 {
    let mut data = hash_prefix(pk_seed, address);
    while let Some(value) = values.pop_front() {
        data.append_word((*value).into(), N);
    }
    digest_node(compute_sha256_byte_array(@data))
}

fn h_msg(message_hash: felt252, randomizer: u128, pk_seed: u128, pk_root: u128) -> Array<u8> {
    // Algorithm 24 with an empty context: M' = 0x00 || 0x00 || M.
    let message: u256 = message_hash.into();
    let mut inner_input: ByteArray = "";
    inner_input.append_word(randomizer.into(), N);
    inner_input.append_word(pk_seed.into(), N);
    inner_input.append_word(pk_root.into(), N);
    inner_input.append_word(0, 1);
    inner_input.append_word(0, 1);
    inner_input.append_word(message.high.into(), N);
    inner_input.append_word(message.low.into(), N);
    let inner = compute_sha256_byte_array(@inner_input);

    // MGF1-SHA-256 needs one block for the 30-byte digest.
    let mut mgf_input: ByteArray = "";
    mgf_input.append_word(randomizer.into(), N);
    mgf_input.append_word(pk_seed.into(), N);
    append_digest(ref mgf_input, inner);
    mgf_input.append_word(0, 4);
    digest_bytes_30(compute_sha256_byte_array(@mgf_input))
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

fn wots_digits(message: u128) -> Array<u32> {
    let mut reversed = array![];
    let mut value = message;
    let mut i = 0;
    while i != 32 {
        reversed.append((value % 16).try_into().unwrap());
        value /= 16;
        i += 1;
    }

    let mut digits = array![];
    let mut checksum = 0;
    let mut remaining = 32;
    while remaining != 0 {
        remaining -= 1;
        let digit = *reversed.at(remaining);
        digits.append(digit);
        checksum += 15 - digit;
    }
    digits.append((checksum / 256) % 16);
    digits.append((checksum / 16) % 16);
    digits.append(checksum % 16);
    digits
}

fn wots_pk_from_sig(
    signature: Span<u128>, message: u128, pk_seed: u128, mut address: Address,
) -> u128 {
    let digits = wots_digits(message);
    let mut endpoints = array![];
    let key_pair = address.key_pair;
    let mut i = 0;
    while i != WOTS_LEN {
        address.chain_or_height = i;
        let start = *digits.at(i);
        let mut node = *signature.at(i);
        let mut j = start;
        while j != 15 {
            address.hash_or_index = j;
            node = f_hash(pk_seed, address, node);
            j += 1;
        }
        endpoints.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, WOTS_PK);
    address.key_pair = key_pair;
    t_hash(pk_seed, address, endpoints.span())
}

fn xmss_pk_from_sig(
    leaf_index: u32, signature: Span<u128>, message: u128, pk_seed: u128, mut address: Address,
) -> u128 {
    set_type_and_clear(ref address, WOTS_HASH);
    address.key_pair = leaf_index;
    let mut node = wots_pk_from_sig(signature.slice(0, WOTS_LEN), message, pk_seed, address);

    set_type_and_clear(ref address, TREE);
    address.hash_or_index = leaf_index;
    let mut index = leaf_index;
    let mut height = 0;
    while height != XMSS_HEIGHT {
        address.chain_or_height = height + 1;
        let auth = *signature.at(WOTS_LEN + height);
        if index % 2 == 0 {
            address.hash_or_index /= 2;
            node = h_hash(pk_seed, address, node, auth);
        } else {
            address.hash_or_index = (address.hash_or_index - 1) / 2;
            node = h_hash(pk_seed, address, auth, node);
        }
        index /= 2;
        height += 1;
    }
    node
}

fn fors_pk_from_sig(
    signature: Span<u128>, md: Span<u8>, pk_seed: u128, mut address: Address,
) -> u128 {
    let indices = fors_indices(md);
    let key_pair = address.key_pair;
    let mut roots = array![];
    let mut i = 0;
    while i != FORS_TREES {
        let index = *indices.at(i);
        address.chain_or_height = 0;
        address.hash_or_index = i * FORS_TREE_SIZE + index;
        let mut node = f_hash(pk_seed, address, *signature.at(i * 13));
        let mut local_index = index;
        let mut height = 0;
        while height != FORS_HEIGHT {
            address.chain_or_height = height + 1;
            let auth = *signature.at(i * 13 + 1 + height);
            if local_index % 2 == 0 {
                address.hash_or_index /= 2;
                node = h_hash(pk_seed, address, node, auth);
            } else {
                address.hash_or_index = (address.hash_or_index - 1) / 2;
                node = h_hash(pk_seed, address, auth, node);
            }
            local_index /= 2;
            height += 1;
        }
        roots.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, FORS_ROOTS);
    address.key_pair = key_pair;
    t_hash(pk_seed, address, roots.span())
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
    signature: Span<u128>, message: u128, pk_seed: u128, mut tree_index: u64, mut leaf_index: u32,
) -> u128 {
    let mut address = zero_address();
    address.tree = tree_index;
    let mut node = xmss_pk_from_sig(
        leaf_index, signature.slice(0, XMSS_SIG_NODES), message, pk_seed, address,
    );

    let mut layer = 1;
    while layer != HT_LAYERS {
        leaf_index = (tree_index % 512).try_into().unwrap();
        tree_index /= 512;
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

fn decode_signature(mut encoded: Span<felt252>) -> Option<Array<u128>> {
    let mut decoded = array![];
    while let Some(value) = encoded.pop_front() {
        let node: u128 = match (*value).try_into() {
            Some(node) => node,
            None => { return None; },
        };
        decoded.append(node);
    }
    Some(decoded)
}

/// Verifies a pure FIPS 205 SLH-DSA-SHA2-128s signature with an empty context.
///
/// `message_hash` is serialized as a 32-byte big-endian message. `public_key` is
/// `PK.seed || PK.root` (2 felts), and `signature` is the 491-element FIPS signature
/// (`R || SIG_FORS || SIG_HT`), with every felt holding one 16-byte element.
/// Malformed lengths and values outside `u128` are rejected.
pub impl SlhDsaSha2_128sVerifier of PqSignatureVerifier {
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
        root == pk_root
    }
}
