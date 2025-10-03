#![forbid(unsafe_code)]
#![deny(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::result_large_err
)]

//! OBEX primitives: domain-tagged SHA3-256 hashing, fixed-width LE encodings, binary Merkle.

use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

pub type Hash256 = [u8; 32];

pub mod constants {
    // Tag registry (must match CONSENSUS_SPEC.md)
    pub const TAG_MERKLE_LEAF: &str = "obex.merkle.leaf";
    pub const TAG_MERKLE_NODE: &str = "obex.merkle.node";
    pub const TAG_MERKLE_EMPTY: &str = "obex.merkle.empty";
    pub const TAG_ALPHA: &str = "obex.alpha";
    pub const TAG_PART_LEAF: &str = "obex.part.leaf";
    pub const TAG_PARTREC: &str = "obex.partrec";
    pub const TAG_SEED: &str = "obex.seed";
    pub const TAG_L0: &str = "obex.l0";
    pub const TAG_LBL: &str = "obex.lbl";
    pub const TAG_IDX: &str = "obex.idx";
    pub const TAG_CHAL: &str = "obex.chal";
    pub const TAG_VRFY: &str = "obex.vrfy";
    pub const TAG_HEADER_ID: &str = "obex.header.id";
    pub const TAG_SLOT_SEED: &str = "obex.slot.seed";
    pub const TAG_VDF_YCORE: &str = "obex.vdf.ycore";
    pub const TAG_VDF_EDGE: &str = "obex.vdf.edge";
    pub const TAG_TX_ACCESS: &str = "obex.tx.access";
    pub const TAG_TX_BODY_V1: &str = "obex.tx.body.v1";
    pub const TAG_TX_ID: &str = "obex.tx.id";
    pub const TAG_TX_COMMIT: &str = "obex.tx.commit";
    pub const TAG_TX_SIG: &str = "obex.tx.sig";
    pub const TAG_TXID_LEAF: &str = "obex.txid.leaf";
    pub const TAG_TICKET_ID: &str = "obex.ticket.id";
    pub const TAG_TICKET_LEAF: &str = "obex.ticket.leaf";
    pub const TAG_SYS_TX: &str = "obex.sys.tx";
    pub const TAG_REWARD_DRAW: &str = "obex.reward.draw";
    pub const TAG_REWARD_RANK: &str = "obex.reward.rank";
}

#[must_use]
pub fn le_bytes<const W: usize>(mut x: u128) -> [u8; W] {
    let mut out = [0u8; W];
    let mut i = 0usize;
    while i < W {
        out[i] = (x & 0xFF) as u8;
        x >>= 8;
        i += 1;
    }
    out
}

#[must_use]
pub fn u64_from_le(b: &[u8]) -> u64 {
    let mut x: u64 = 0;
    let mut i = 0usize;
    while i < 8 && i < b.len() {
        x |= u64::from(b[i]) << (8 * i as u64);
        i += 1;
    }
    x
}

#[must_use]
pub fn h_tag(tag: &str, parts: &[&[u8]]) -> Hash256 {
    debug_assert!(tag.starts_with("obex."));
    let mut hasher = Sha3_256::new();
    hasher.update(tag.as_bytes());
    for p in parts {
        hasher.update(le_bytes::<8>(p.len() as u128));
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[must_use]
pub fn ct_eq_hash(a: &Hash256, b: &Hash256) -> bool {
    a.ct_eq(b).into()
}

#[must_use]
pub fn merkle_leaf(payload: &[u8]) -> Hash256 {
    h_tag(constants::TAG_MERKLE_LEAF, &[payload])
}

#[must_use]
pub fn merkle_node(l: &Hash256, r: &Hash256) -> Hash256 {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(l);
    cat[32..].copy_from_slice(r);
    h_tag(constants::TAG_MERKLE_NODE, &[&cat])
}

#[must_use]
pub fn merkle_root(leaves_payload: &[Vec<u8>]) -> Hash256 {
    if leaves_payload.is_empty() {
        return h_tag(constants::TAG_MERKLE_EMPTY, &[]);
    }
    let mut level: Vec<Hash256> = leaves_payload.iter().map(|p| merkle_leaf(p)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(last) = level.last().copied() {
                level.push(last);
            }
        }
        let mut next: Vec<Hash256> = Vec::with_capacity(level.len() / 2);
        let mut i = 0usize;
        while i < level.len() {
            next.push(merkle_node(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Hash256>,
    pub index: u64,
}

#[must_use]
pub fn merkle_verify_leaf(root: &Hash256, leaf_payload: &[u8], path: &MerklePath) -> bool {
    let mut h = merkle_leaf(leaf_payload);
    let mut idx = path.index;
    for sib in &path.siblings {
        h = if idx & 1 == 0 {
            merkle_node(&h, sib)
        } else {
            merkle_node(sib, &h)
        };
        idx >>= 1;
    }
    ct_eq_hash(root, &h)
}
