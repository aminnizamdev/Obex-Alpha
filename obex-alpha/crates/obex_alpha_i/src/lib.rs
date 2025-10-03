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

//! α‑I — Participation Engine (VRF + RAM‑hard + Merkle), per ALPHA_I_SPEC.md

use ed25519_dalek::{Signature, VerifyingKey};
use obex_primitives::{
    constants, ct_eq_hash, h_tag, le_bytes, merkle_root, merkle_verify_leaf, u64_from_le, Hash256,
};
use thiserror::Error;

pub const OBEX_ALPHA_I_VERSION: u32 = 1;
pub const MEM_MIB: usize = 512;
pub const LABEL_BYTES: usize = 32;
pub const N_LABELS: usize = (MEM_MIB * 1_048_576) / LABEL_BYTES; // 16,777,216
pub const PASSES: u32 = 3;
pub const CHALLENGES_Q: usize = 96;
pub const MAX_PARTREC_SIZE: usize = 600_000;

pub type Pk32 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePathLite {
    pub siblings: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeOpen {
    pub idx: u64,
    pub li: Hash256,
    pub pi: MerklePathLite,
    pub lim1: Hash256,
    pub pim1: MerklePathLite,
    pub lj: Hash256,
    pub pj: MerklePathLite,
    pub lk: Hash256,
    pub pk_: MerklePathLite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObexPartRec {
    pub version: u32,
    pub slot: u64,
    pub pk_ed25519: Pk32,
    pub vrf_pk: Pk32,
    pub y_edge_prev: Hash256,
    pub alpha: Hash256,
    pub vrf_y: Vec<u8>,  // 64 bytes
    pub vrf_pi: Vec<u8>, // 80 bytes
    pub seed: Hash256,
    pub root: Hash256,
    pub challenges: Vec<ChallengeOpen>, // len == 96
    pub sig: [u8; 64],
}

pub trait EcVrfVerifier {
    fn verify(&self, vk: &Pk32, alpha32: &Hash256, pi: &[u8]) -> Option<Vec<u8>>;
}

#[inline]
fn obex_alpha(parent_id: &Hash256, slot: u64, y_prev: &Hash256, vrf_pk: &Pk32) -> Hash256 {
    h_tag(
        constants::TAG_ALPHA,
        &[parent_id, &le_bytes::<8>(u128::from(slot)), y_prev, vrf_pk],
    )
}

#[inline]
fn obex_seed(y_prev: &Hash256, pk: &Pk32, vrf_y: &[u8]) -> Hash256 {
    h_tag(constants::TAG_SEED, &[y_prev, pk, vrf_y])
}

#[inline]
fn idx_j(seed: &Hash256, i: u64, p: u32) -> u64 {
    let b = h_tag(
        constants::TAG_IDX,
        &[
            seed,
            &le_bytes::<8>(u128::from(i)),
            &le_bytes::<4>(u128::from(p)),
            &[0x00],
        ],
    );
    if i == 0 {
        0
    } else {
        u64_from_le(&b[..8]) % i
    }
}

#[inline]
fn idx_k(seed: &Hash256, i: u64, p: u32) -> u64 {
    let b = h_tag(
        constants::TAG_IDX,
        &[
            seed,
            &le_bytes::<8>(u128::from(i)),
            &le_bytes::<4>(u128::from(p)),
            &[0x01],
        ],
    );
    if i == 0 {
        0
    } else {
        u64_from_le(&b[..8]) % i
    }
}

#[inline]
fn label_update(seed: &Hash256, i: u64, l_im1: &Hash256, l_j: &Hash256, l_k: &Hash256) -> Hash256 {
    h_tag(
        constants::TAG_LBL,
        &[seed, &le_bytes::<8>(u128::from(i)), l_im1, l_j, l_k],
    )
}

#[inline]
fn chal_index(y_prev: &Hash256, root: &Hash256, vrf_y: &[u8], t: u32) -> u64 {
    let b = h_tag(
        constants::TAG_CHAL,
        &[y_prev, root, vrf_y, &le_bytes::<4>(u128::from(t))],
    );
    1 + (u64_from_le(&b[..8]) % ((N_LABELS as u64) - 1))
}

struct Transcript<'a> {
    version: u32,
    slot: u64,
    pk: &'a Pk32,
    vrf_pk: &'a Pk32,
    y_prev: &'a Hash256,
    alpha: &'a Hash256,
    vrf_y: &'a [u8],
    root: &'a Hash256,
}

fn partrec_msg(t: &Transcript<'_>) -> Hash256 {
    h_tag(
        constants::TAG_PARTREC,
        &[
            &le_bytes::<4>(u128::from(t.version)),
            t.pk,
            t.vrf_pk,
            &le_bytes::<8>(u128::from(t.slot)),
            t.y_prev,
            t.alpha,
            t.vrf_y,
            t.root,
        ],
    )
}

fn verify_sig(pk: &Pk32, msg: &Hash256, sig: &[u8; 64]) -> bool {
    match (VerifyingKey::from_bytes(pk), Signature::from_slice(sig)) {
        (Ok(vk), Ok(sig_d)) => vk.verify_strict(msg, &sig_d).is_ok(),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErr {
    VersionMismatch,
    SlotMismatch,
    ChallengesLen,
    AlphaMismatch,
    VrfVerifyFailed,
    VrfOutputMismatch,
    SeedMismatch,
    SigInvalid,
    ChalIndexMismatch,
    ChalIndexBounds,
    JOrKOutOfRange,
    MerkleLiInvalid,
    MerkleLim1Invalid,
    MerkleLjInvalid,
    MerkleLkInvalid,
    LabelEquationMismatch,
}

pub fn obex_check_partrec(
    rec: &ObexPartRec,
    slot: u64,
    parent_id: &Hash256,
    vrf: &impl EcVrfVerifier,
) -> Result<(), VerifyErr> {
    if rec.version != OBEX_ALPHA_I_VERSION {
        return Err(VerifyErr::VersionMismatch);
    }
    if rec.slot != slot {
        return Err(VerifyErr::SlotMismatch);
    }
    if rec.challenges.len() != CHALLENGES_Q {
        return Err(VerifyErr::ChallengesLen);
    }

    let alpha = obex_alpha(parent_id, slot, &rec.y_edge_prev, &rec.vrf_pk);
    if !ct_eq_hash(&alpha, &rec.alpha) {
        return Err(VerifyErr::AlphaMismatch);
    }
    let Some(vrf_y_check) = vrf.verify(&rec.vrf_pk, &alpha, &rec.vrf_pi) else {
        return Err(VerifyErr::VrfVerifyFailed);
    };
    if vrf_y_check.as_slice() != rec.vrf_y.as_slice() {
        return Err(VerifyErr::VrfOutputMismatch);
    }

    let seed_expected = obex_seed(&rec.y_edge_prev, &rec.pk_ed25519, &rec.vrf_y);
    if !ct_eq_hash(&seed_expected, &rec.seed) {
        return Err(VerifyErr::SeedMismatch);
    }

    let msg = partrec_msg(&Transcript {
        version: rec.version,
        slot: rec.slot,
        pk: &rec.pk_ed25519,
        vrf_pk: &rec.vrf_pk,
        y_prev: &rec.y_edge_prev,
        alpha: &rec.alpha,
        vrf_y: &rec.vrf_y,
        root: &rec.root,
    });
    if !verify_sig(&rec.pk_ed25519, &msg, &rec.sig) {
        return Err(VerifyErr::SigInvalid);
    }

    let last_pass = PASSES - 1;
    for (t, ch) in rec.challenges.iter().enumerate() {
        let Ok(t_u32) = u32::try_from(t) else {
            return Err(VerifyErr::ChalIndexBounds);
        };
        let i = chal_index(&rec.y_edge_prev, &rec.root, &rec.vrf_y, t_u32);
        if ch.idx != i {
            return Err(VerifyErr::ChalIndexMismatch);
        }
        if !(i > 0 && usize::try_from(i).is_ok_and(|ii| ii < N_LABELS)) {
            return Err(VerifyErr::ChalIndexBounds);
        }
        let j = idx_j(&rec.seed, i, last_pass);
        let k = idx_k(&rec.seed, i, last_pass);
        if !(j < i && k < i) {
            return Err(VerifyErr::JOrKOutOfRange);
        }
        if !merkle_verify_leaf(
            &rec.root,
            &ch.li,
            &obex_primitives::MerklePath {
                siblings: ch.pi.siblings.clone(),
                index: i,
            },
        ) {
            return Err(VerifyErr::MerkleLiInvalid);
        }
        if !merkle_verify_leaf(
            &rec.root,
            &ch.lim1,
            &obex_primitives::MerklePath {
                siblings: ch.pim1.siblings.clone(),
                index: i - 1,
            },
        ) {
            return Err(VerifyErr::MerkleLim1Invalid);
        }
        if !merkle_verify_leaf(
            &rec.root,
            &ch.lj,
            &obex_primitives::MerklePath {
                siblings: ch.pj.siblings.clone(),
                index: j,
            },
        ) {
            return Err(VerifyErr::MerkleLjInvalid);
        }
        if !merkle_verify_leaf(
            &rec.root,
            &ch.lk,
            &obex_primitives::MerklePath {
                siblings: ch.pk_.siblings.clone(),
                index: k,
            },
        ) {
            return Err(VerifyErr::MerkleLkInvalid);
        }
        let li_check = label_update(&rec.seed, i, &ch.lim1, &ch.lj, &ch.lk);
        if !ct_eq_hash(&li_check, &ch.li) {
            return Err(VerifyErr::LabelEquationMismatch);
        }
    }
    Ok(())
}

#[must_use]
pub fn obex_verify_partrec(
    rec: &ObexPartRec,
    slot: u64,
    parent_id: &Hash256,
    vrf: &impl EcVrfVerifier,
) -> bool {
    obex_check_partrec(rec, slot, parent_id, vrf).is_ok()
}

pub fn build_participation_set<'a>(
    slot: u64,
    parent_id: &Hash256,
    submissions: impl Iterator<Item = &'a ObexPartRec>,
    vrf: &impl EcVrfVerifier,
) -> (Vec<Pk32>, Hash256) {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<Pk32> = BTreeSet::new();
    let mut pks: Vec<Pk32> = Vec::new();
    for rec in submissions {
        if rec.slot != slot {
            continue;
        }
        if seen.contains(&rec.pk_ed25519) {
            continue;
        }
        if obex_verify_partrec(rec, slot, parent_id, vrf) {
            seen.insert(rec.pk_ed25519);
            pks.push(rec.pk_ed25519);
        }
    }
    pks.sort_unstable();
    let leaves: Vec<Vec<u8>> = pks
        .iter()
        .map(|pk| {
            let mut b = Vec::with_capacity(64);
            b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
            b.extend_from_slice(pk);
            b
        })
        .collect();
    let part_root = merkle_root(&leaves);
    (pks, part_root)
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("input too short")]
    Short,
    #[error("trailing bytes after decode")]
    Trailing,
    #[error("bad vector length")]
    BadLen,
    #[error("vrf_y must be 64 bytes")]
    BadVrfY,
    #[error("vrf_pi must be 80 bytes")]
    BadVrfPi,
    #[error("wrong challenges count")]
    BadChallenges,
}

fn read_exact<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], CodecError> {
    if src.len() < n {
        return Err(CodecError::Short);
    }
    let (a, b) = src.split_at(n);
    *src = b;
    Ok(a)
}
fn read_u32(src: &mut &[u8]) -> Result<u32, CodecError> {
    let b = read_exact(src, 4)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}
fn read_u64(src: &mut &[u8]) -> Result<u64, CodecError> {
    let b = read_exact(src, 8)?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}
fn read_hash(src: &mut &[u8]) -> Result<Hash256, CodecError> {
    let b = read_exact(src, 32)?;
    let mut h = [0u8; 32];
    h.copy_from_slice(b);
    Ok(h)
}
fn read_hash_vec(src: &mut &[u8]) -> Result<Vec<Hash256>, CodecError> {
    let n = read_u32(src)? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(read_hash(src)?);
    }
    Ok(v)
}

fn write_le<const W: usize>(out: &mut Vec<u8>, x: u128) {
    out.extend_from_slice(&le_bytes::<W>(x));
}
fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
}
fn write_hash(out: &mut Vec<u8>, h: &Hash256) {
    out.extend_from_slice(h);
}
fn encode_hash_vec(out: &mut Vec<u8>, v: &[Hash256]) {
    write_le::<4>(out, v.len() as u128);
    for h in v {
        write_hash(out, h);
    }
}

fn encode_challenge(out: &mut Vec<u8>, ch: &ChallengeOpen) {
    write_le::<8>(out, u128::from(ch.idx));
    write_hash(out, &ch.li);
    encode_hash_vec(out, &ch.pi.siblings);
    write_hash(out, &ch.lim1);
    encode_hash_vec(out, &ch.pim1.siblings);
    write_hash(out, &ch.lj);
    encode_hash_vec(out, &ch.pj.siblings);
    write_hash(out, &ch.lk);
    encode_hash_vec(out, &ch.pk_.siblings);
}

pub fn encode_partrec(rec: &ObexPartRec) -> Result<Vec<u8>, CodecError> {
    if rec.vrf_y.len() != 64 {
        return Err(CodecError::BadVrfY);
    }
    if rec.vrf_pi.len() != 80 {
        return Err(CodecError::BadVrfPi);
    }
    if rec.challenges.len() != CHALLENGES_Q {
        return Err(CodecError::BadChallenges);
    }
    let mut out = Vec::new();
    write_le::<4>(&mut out, u128::from(rec.version));
    write_le::<8>(&mut out, u128::from(rec.slot));
    write_bytes(&mut out, &rec.pk_ed25519);
    write_bytes(&mut out, &rec.vrf_pk);
    write_hash(&mut out, &rec.y_edge_prev);
    write_hash(&mut out, &rec.alpha);
    write_bytes(&mut out, &rec.vrf_y);
    write_bytes(&mut out, &rec.vrf_pi);
    write_hash(&mut out, &rec.seed);
    write_hash(&mut out, &rec.root);
    write_le::<4>(&mut out, rec.challenges.len() as u128);
    for ch in &rec.challenges {
        encode_challenge(&mut out, ch);
    }
    write_bytes(&mut out, &rec.sig);
    Ok(out)
}

pub fn decode_partrec(mut src: &[u8]) -> Result<ObexPartRec, CodecError> {
    let version = read_u32(&mut src)?;
    let slot = read_u64(&mut src)?;
    let pk_ed25519 = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let vrf_pk = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let y_edge_prev = read_hash(&mut src)?;
    let alpha = read_hash(&mut src)?;
    let vrf_y = {
        let b = read_exact(&mut src, 64)?;
        b.to_vec()
    };
    let vrf_pi = {
        let b = read_exact(&mut src, 80)?;
        b.to_vec()
    };
    let seed = read_hash(&mut src)?;
    let root = read_hash(&mut src)?;
    let n_ch = read_u32(&mut src)? as usize;
    if n_ch != CHALLENGES_Q {
        return Err(CodecError::BadChallenges);
    }
    let mut challenges = Vec::with_capacity(n_ch);
    for _ in 0..n_ch {
        let idx = read_u64(&mut src)?;
        let li = read_hash(&mut src)?;
        let pi = MerklePathLite {
            siblings: read_hash_vec(&mut src)?,
        };
        let lim1 = read_hash(&mut src)?;
        let pim1 = MerklePathLite {
            siblings: read_hash_vec(&mut src)?,
        };
        let lj = read_hash(&mut src)?;
        let pj = MerklePathLite {
            siblings: read_hash_vec(&mut src)?,
        };
        let lk = read_hash(&mut src)?;
        let pk_ = MerklePathLite {
            siblings: read_hash_vec(&mut src)?,
        };
        challenges.push(ChallengeOpen {
            idx,
            li,
            pi,
            lim1,
            pim1,
            lj,
            pj,
            lk,
            pk_,
        });
    }
    let sig = {
        let b = read_exact(&mut src, 64)?;
        let mut s = [0u8; 64];
        s.copy_from_slice(b);
        s
    };
    if !src.is_empty() {
        return Err(CodecError::Trailing);
    }
    Ok(ObexPartRec {
        version,
        slot,
        pk_ed25519,
        vrf_pk,
        y_edge_prev,
        alpha,
        vrf_y,
        vrf_pi,
        seed,
        root,
        challenges,
        sig,
    })
}
