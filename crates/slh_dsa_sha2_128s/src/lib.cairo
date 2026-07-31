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
use core::gas::GasBuiltin;
use core::sha256::compute_sha256_u32_array;
use pqbench_interface::PqSignatureVerifier;
use starknet::{SyscallResultTrait, System};

// Core's high-level SHA-256 API does not expose resumable states. These declarations map
// to the same Cairo libfuncs used internally by `compute_sha256_u32_array`, allowing the
// invariant FIPS 205 `PK.seed || zero padding` block to be compressed once per signature.
extern type Sha256StateHandle;

impl Sha256StateHandleCopy of Copy<Sha256StateHandle>;
impl Sha256StateHandleDrop of Drop<Sha256StateHandle>;

extern fn sha256_state_handle_init(state: Box<[u32; 8]>) -> Sha256StateHandle nopanic;
extern fn sha256_state_handle_digest(state: Sha256StateHandle) -> Box<[u32; 8]> nopanic;

extern fn sha256_process_block_syscall(
    state: Sha256StateHandle, input: Box<[u32; 16]>,
) -> starknet::SyscallResult<Sha256StateHandle> implicits(GasBuiltin, System) nopanic;

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

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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

#[derive(Copy, Drop)]
struct Node {
    w0: u32,
    w1: u32,
    w2: u32,
    w3: u32,
}

#[derive(Copy, Drop)]
struct AddressWords {
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    carry: u32,
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

#[inline(always)]
fn split_u128(value: u128, two32: NonZero<u128>) -> Node {
    let (rest, w3) = DivRem::div_rem(value, two32);
    let (rest, w2) = DivRem::div_rem(rest, two32);
    let (w0, w1) = DivRem::div_rem(rest, two32);
    Node {
        w0: w0.try_into().unwrap(),
        w1: w1.try_into().unwrap(),
        w2: w2.try_into().unwrap(),
        w3: w3.try_into().unwrap(),
    }
}

fn append_aligned_node(ref input: Array<u32>, value: Node) {
    input.append(value.w0);
    input.append(value.w1);
    input.append(value.w2);
    input.append(value.w3);
}

/// Appends a 16-byte value after the two pending bytes in `carry`.
#[inline(always)]
fn append_shifted_node(ref input: Array<u32>, ref carry: u32, value: Node, two16: NonZero<u32>) {
    let (w0_hi, w0_lo) = DivRem::div_rem(value.w0, two16);
    let (w1_hi, w1_lo) = DivRem::div_rem(value.w1, two16);
    let (w2_hi, w2_lo) = DivRem::div_rem(value.w2, two16);
    let (w3_hi, w3_lo) = DivRem::div_rem(value.w3, two16);
    input.append(carry * 0x10000 + w0_hi);
    input.append(w0_lo * 0x10000 + w1_hi);
    input.append(w1_lo * 0x10000 + w2_hi);
    input.append(w2_lo * 0x10000 + w3_hi);
    carry = w3_lo;
}

fn digest_node(digest: [u32; 8]) -> Node {
    let [d0, d1, d2, d3, _, _, _, _] = digest;
    Node { w0: d0, w1: d1, w2: d2, w3: d3 }
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

fn compute_prefix_state(pk_seed: Node) -> Sha256StateHandle {
    let block = [
        pk_seed.w0, pk_seed.w1, pk_seed.w2, pk_seed.w3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let state = sha256_state_handle_init(BoxTrait::new(SHA256_INITIAL_STATE));
    sha256_process_block_syscall(state, BoxTrait::new(block)).unwrap_syscall()
}

/// Packs the 22-byte compressed address into words, leaving its low two bytes in `carry`.
fn address_words(address: Address) -> AddressWords {
    let layer: u64 = address.layer.into();
    let address_type: u64 = address.address_type.into();
    let a0: u32 = (layer * 0x1000000 + address.tree / 0x10000000000).try_into().unwrap();
    let a1: u32 = ((address.tree / 0x100) % 0x100000000).try_into().unwrap();
    let a2: u32 = ((address.tree % 0x100) * 0x1000000 + address_type * 0x10000).try_into().unwrap();
    // Every key-pair, chain/height, and node index in SHA2-128s fits in 16 bits.
    let a3 = address.key_pair * 0x10000;
    let a4 = address.chain_or_height * 0x10000;
    let carry = address.hash_or_index;
    AddressWords { a0, a1, a2, a3, a4, carry }
}

fn finish_node_hash(
    prefix_state: Sha256StateHandle, ref input: Array<u32>, carry: u32, total_bytes: u32,
) -> Node {
    input.append(carry * 0x10000 + 0x8000);
    input.append(0);
    while input.len() % 16 != 15 {
        input.append(0);
    }
    input.append(total_bytes * 8);

    let mut blocks = input.span();
    let mut state = prefix_state;
    while let Some(block) = blocks.multi_pop_front() {
        state = sha256_process_block_syscall(state, *block).unwrap_syscall();
    }
    digest_node(sha256_state_handle_digest(state).unbox())
}

#[inline(always)]
fn process_node_block(prefix_state: Sha256StateHandle, block: [u32; 16]) -> Node {
    let state = sha256_process_block_syscall(prefix_state, BoxTrait::new(block)).unwrap_syscall();
    digest_node(sha256_state_handle_digest(state).unbox())
}

#[inline(always)]
fn f_hash_words(
    prefix_state: Sha256StateHandle, a: AddressWords, value: Node, two16: NonZero<u32>,
) -> Node {
    let (w0_hi, w0_lo) = DivRem::div_rem(value.w0, two16);
    let (w1_hi, w1_lo) = DivRem::div_rem(value.w1, two16);
    let (w2_hi, w2_lo) = DivRem::div_rem(value.w2, two16);
    let (w3_hi, w3_lo) = DivRem::div_rem(value.w3, two16);
    let block = [
        a.a0, a.a1, a.a2, a.a3, a.a4, a.carry * 0x10000 + w0_hi, w0_lo * 0x10000 + w1_hi,
        w1_lo * 0x10000 + w2_hi, w2_lo * 0x10000 + w3_hi, w3_lo * 0x10000 + 0x8000, 0, 0, 0, 0, 0,
        816,
    ];
    process_node_block(prefix_state, block)
}

#[inline(always)]
fn h_hash_words(
    prefix_state: Sha256StateHandle, a: AddressWords, left: Node, right: Node, two16: NonZero<u32>,
) -> Node {
    let (l0_hi, l0_lo) = DivRem::div_rem(left.w0, two16);
    let (l1_hi, l1_lo) = DivRem::div_rem(left.w1, two16);
    let (l2_hi, l2_lo) = DivRem::div_rem(left.w2, two16);
    let (l3_hi, l3_lo) = DivRem::div_rem(left.w3, two16);
    let (r0_hi, r0_lo) = DivRem::div_rem(right.w0, two16);
    let (r1_hi, r1_lo) = DivRem::div_rem(right.w1, two16);
    let (r2_hi, r2_lo) = DivRem::div_rem(right.w2, two16);
    let (r3_hi, r3_lo) = DivRem::div_rem(right.w3, two16);
    let block = [
        a.a0, a.a1, a.a2, a.a3, a.a4, a.carry * 0x10000 + l0_hi, l0_lo * 0x10000 + l1_hi,
        l1_lo * 0x10000 + l2_hi, l2_lo * 0x10000 + l3_hi, l3_lo * 0x10000 + r0_hi,
        r0_lo * 0x10000 + r1_hi, r1_lo * 0x10000 + r2_hi, r2_lo * 0x10000 + r3_hi,
        r3_lo * 0x10000 + 0x8000, 0, 944,
    ];
    process_node_block(prefix_state, block)
}

fn t_hash(prefix_state: Sha256StateHandle, address: Address, mut values: Span<Node>) -> Node {
    let total_bytes = 86 + values.len() * 16;
    let a = address_words(address);
    let mut input = array![a.a0, a.a1, a.a2, a.a3, a.a4];
    let mut carry = a.carry;
    let two16: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    while let Some(value) = values.pop_front() {
        append_shifted_node(ref input, ref carry, *value, two16);
    }
    finish_node_hash(prefix_state, ref input, carry, total_bytes)
}

fn h_msg(
    message_hash: felt252, randomizer: Node, pk_seed: Node, pk_root: Node, two32: NonZero<u128>,
) -> Array<u8> {
    // Algorithm 24 with an empty context: M' = 0x00 || 0x00 || M.
    let message: u256 = message_hash.into();
    let mut inner_input = array![];
    append_aligned_node(ref inner_input, randomizer);
    append_aligned_node(ref inner_input, pk_seed);
    append_aligned_node(ref inner_input, pk_root);
    let mut carry = 0;
    let two16: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    append_shifted_node(ref inner_input, ref carry, split_u128(message.high, two32), two16);
    append_shifted_node(ref inner_input, ref carry, split_u128(message.low, two32), two16);
    let inner = compute_sha256_u32_array(inner_input, carry, 2);

    // MGF1-SHA-256 needs one block for the 30-byte digest.
    let mut mgf_input = array![];
    append_aligned_node(ref mgf_input, randomizer);
    append_aligned_node(ref mgf_input, pk_seed);
    let [d0, d1, d2, d3, d4, d5, d6, d7] = inner;
    mgf_input.append(d0);
    mgf_input.append(d1);
    mgf_input.append(d2);
    mgf_input.append(d3);
    mgf_input.append(d4);
    mgf_input.append(d5);
    mgf_input.append(d6);
    mgf_input.append(d7);
    mgf_input.append(0);
    digest_bytes_30(compute_sha256_u32_array(mgf_input, 0, 0))
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

#[inline(always)]
fn append_wots_word(word: u32, ref digits: Array<u32>, ref checksum: u32, sixteen: NonZero<u32>) {
    let (word, d7) = DivRem::div_rem(word, sixteen);
    let (word, d6) = DivRem::div_rem(word, sixteen);
    let (word, d5) = DivRem::div_rem(word, sixteen);
    let (word, d4) = DivRem::div_rem(word, sixteen);
    let (word, d3) = DivRem::div_rem(word, sixteen);
    let (word, d2) = DivRem::div_rem(word, sixteen);
    let (d0, d1) = DivRem::div_rem(word, sixteen);
    digits.append(d0);
    digits.append(d1);
    digits.append(d2);
    digits.append(d3);
    digits.append(d4);
    digits.append(d5);
    digits.append(d6);
    digits.append(d7);
    checksum += 120 - d0 - d1 - d2 - d3 - d4 - d5 - d6 - d7;
}

fn wots_digits(message: Node) -> Array<u32> {
    let mut digits = array![];
    let mut checksum = 0;
    let sixteen: NonZero<u32> = 16_u32.try_into().unwrap();
    append_wots_word(message.w0, ref digits, ref checksum, sixteen);
    append_wots_word(message.w1, ref digits, ref checksum, sixteen);
    append_wots_word(message.w2, ref digits, ref checksum, sixteen);
    append_wots_word(message.w3, ref digits, ref checksum, sixteen);
    digits.append((checksum / 256) % 16);
    digits.append((checksum / 16) % 16);
    digits.append(checksum % 16);
    digits
}

fn wots_pk_from_sig(
    signature: Span<Node>, message: Node, prefix_state: Sha256StateHandle, mut address: Address,
) -> Node {
    let digits = wots_digits(message);
    let mut endpoints = array![];
    let key_pair = address.key_pair;
    let mut hash_address = address_words(address);
    let two16: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    let mut i = 0;
    while i != WOTS_LEN {
        hash_address.a4 = i * 0x10000;
        let start = *digits.at(i);
        let mut node = *signature.at(i);
        let mut j = start;
        while j != 15 {
            hash_address.carry = j;
            node = f_hash_words(prefix_state, hash_address, node, two16);
            j += 1;
        }
        endpoints.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, WOTS_PK);
    address.key_pair = key_pair;
    t_hash(prefix_state, address, endpoints.span())
}

fn xmss_pk_from_sig(
    leaf_index: u32,
    signature: Span<Node>,
    message: Node,
    prefix_state: Sha256StateHandle,
    mut address: Address,
) -> Node {
    set_type_and_clear(ref address, WOTS_HASH);
    address.key_pair = leaf_index;
    let mut node = wots_pk_from_sig(signature.slice(0, WOTS_LEN), message, prefix_state, address);

    set_type_and_clear(ref address, TREE);
    let mut tree_address = address_words(address);
    let mut node_index = leaf_index;
    let two: NonZero<u32> = 2_u32.try_into().unwrap();
    let two16: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    let mut height = 0;
    while height != XMSS_HEIGHT {
        tree_address.a4 = (height + 1) * 0x10000;
        let auth = *signature.at(WOTS_LEN + height);
        let (parent_index, is_right) = DivRem::div_rem(node_index, two);
        tree_address.carry = parent_index;
        if is_right == 0 {
            node = h_hash_words(prefix_state, tree_address, node, auth, two16);
        } else {
            node = h_hash_words(prefix_state, tree_address, auth, node, two16);
        }
        node_index = parent_index;
        height += 1;
    }
    node
}

fn fors_pk_from_sig(
    signature: Span<Node>, md: Span<u8>, prefix_state: Sha256StateHandle, mut address: Address,
) -> Node {
    let indices = fors_indices(md);
    let key_pair = address.key_pair;
    let mut tree_address = address_words(address);
    let mut roots = array![];
    let two: NonZero<u32> = 2_u32.try_into().unwrap();
    let two16: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    let mut i = 0;
    while i != FORS_TREES {
        let index = *indices.at(i);
        let mut node_index = i * FORS_TREE_SIZE + index;
        tree_address.a4 = 0;
        tree_address.carry = node_index;
        let mut node = f_hash_words(prefix_state, tree_address, *signature.at(i * 13), two16);
        let mut height = 0;
        while height != FORS_HEIGHT {
            tree_address.a4 = (height + 1) * 0x10000;
            let auth = *signature.at(i * 13 + 1 + height);
            let (parent_index, is_right) = DivRem::div_rem(node_index, two);
            tree_address.carry = parent_index;
            if is_right == 0 {
                node = h_hash_words(prefix_state, tree_address, node, auth, two16);
            } else {
                node = h_hash_words(prefix_state, tree_address, auth, node, two16);
            }
            node_index = parent_index;
            height += 1;
        }
        roots.append(node);
        i += 1;
    }

    set_type_and_clear(ref address, FORS_ROOTS);
    address.key_pair = key_pair;
    t_hash(prefix_state, address, roots.span())
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
    signature: Span<Node>,
    message: Node,
    prefix_state: Sha256StateHandle,
    mut tree_index: u64,
    mut leaf_index: u32,
) -> Node {
    let mut address = zero_address();
    address.tree = tree_index;
    let mut node = xmss_pk_from_sig(
        leaf_index, signature.slice(0, XMSS_SIG_NODES), message, prefix_state, address,
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
                prefix_state,
                address,
            );
        layer += 1;
    }
    node
}

fn decode_signature(mut encoded: Span<felt252>, two32: NonZero<u128>) -> Option<Array<Node>> {
    let mut decoded = array![];
    while let Some(value) = encoded.pop_front() {
        let node: u128 = match (*value).try_into() {
            Some(node) => node,
            None => { return None; },
        };
        decoded.append(split_u128(node, two32));
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
        let two32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
        let signature = match decode_signature(signature, two32) {
            Some(value) => value,
            None => { return false; },
        };
        let pk_seed = split_u128(pk_seed, two32);
        let pk_root = split_u128(pk_root, two32);

        let digest = h_msg(message_hash, *signature.at(0), pk_seed, pk_root, two32);
        let prefix_state = compute_prefix_state(pk_seed);
        let tree_index = read_be_u64(digest.span().slice(21, 7)) & TREE_MASK;
        let leaf_index = read_be_u32(digest.span().slice(28, 2)) & LEAF_MASK;

        let mut address = zero_address();
        address.tree = tree_index;
        set_type_and_clear(ref address, FORS_TREE);
        address.key_pair = leaf_index;
        let fors_pk = fors_pk_from_sig(
            signature.span().slice(1, FORS_SIG_NODES),
            digest.span().slice(0, 21),
            prefix_state,
            address,
        );
        let root = hypertree_root(
            signature.span().slice(HT_SIG_OFFSET, SIG_FELTS - HT_SIG_OFFSET),
            fors_pk,
            prefix_state,
            tree_index,
            leaf_index,
        );
        root.w0 == pk_root.w0
            && root.w1 == pk_root.w1
            && root.w2 == pk_root.w2
            && root.w3 == pk_root.w3
    }
}
