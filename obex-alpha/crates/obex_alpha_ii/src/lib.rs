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

//! α‑II — Deterministic Header Engine with Beacon v1 (hash‑edge adapter)

use obex_primitives::{constants, ct_eq_hash, h_tag, le_bytes, Hash256};
use thiserror::Error;

pub const OBEX_ALPHA_II_VERSION: u32 = 2;
pub const MAX_PI_LEN: usize = 1_048_576;
pub const MAX_ELL_LEN: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent_id: Hash256,
    pub slot: u64,
    pub obex_version: u32,
    pub seed_commit: Hash256,
    pub vdf_y_core: Hash256,
    pub vdf_y_edge: Hash256,
    pub vdf_pi: Vec<u8>,
    pub vdf_ell: Vec<u8>,
    pub ticket_root: Hash256,
    pub part_root: Hash256,
    pub txroot_prev: Hash256,
}

#[must_use]
pub fn obex_header_id(h: &Header) -> Hash256 {
    h_tag(
        constants::TAG_HEADER_ID,
        &[
            &h.parent_id,
            &le_bytes::<8>(u128::from(h.slot)),
            &le_bytes::<4>(u128::from(h.obex_version)),
            &h.seed_commit,
            &h.vdf_y_core,
            &h.vdf_y_edge,
            &le_bytes::<4>(h.vdf_pi.len() as u128),
            &h.vdf_pi,
            &le_bytes::<4>(h.vdf_ell.len() as u128),
            &h.vdf_ell,
            &h.ticket_root,
            &h.part_root,
            &h.txroot_prev,
        ],
    )
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("short input")]
    Short,
    #[error("trailing")]
    Trailing,
    #[error("size cap")]
    TooLong,
}

fn read_exact<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], CodecError> {
    if src.len() < n {
        return Err(CodecError::Short);
    }
    let (a, b) = src.split_at(n);
    *src = b;
    Ok(a)
}

#[must_use]
pub fn serialize_header(h: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h.parent_id);
    out.extend_from_slice(&le_bytes::<8>(u128::from(h.slot)));
    out.extend_from_slice(&le_bytes::<4>(u128::from(h.obex_version)));
    out.extend_from_slice(&h.seed_commit);
    out.extend_from_slice(&h.vdf_y_core);
    out.extend_from_slice(&h.vdf_y_edge);
    out.extend_from_slice(&le_bytes::<4>(h.vdf_pi.len() as u128));
    out.extend_from_slice(&h.vdf_pi);
    out.extend_from_slice(&le_bytes::<4>(h.vdf_ell.len() as u128));
    out.extend_from_slice(&h.vdf_ell);
    out.extend_from_slice(&h.ticket_root);
    out.extend_from_slice(&h.part_root);
    out.extend_from_slice(&h.txroot_prev);
    out
}

pub fn deserialize_header(mut src: &[u8]) -> Result<Header, CodecError> {
    let parent_id = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let slot = u64::from_le_bytes(read_exact(&mut src, 8)?.try_into().unwrap());
    let obex_version = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap());
    let seed_commit = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let vdf_y_core = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let vdf_y_edge = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let pi_len = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap()) as usize;
    if pi_len > MAX_PI_LEN {
        return Err(CodecError::TooLong);
    }
    let vdf_pi = read_exact(&mut src, pi_len)?.to_vec();
    let ell_len = u32::from_le_bytes(read_exact(&mut src, 4)?.try_into().unwrap()) as usize;
    if ell_len > MAX_ELL_LEN {
        return Err(CodecError::TooLong);
    }
    let vdf_ell = read_exact(&mut src, ell_len)?.to_vec();
    let ticket_root = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let part_root = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    let txroot_prev = {
        let b = read_exact(&mut src, 32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        a
    };
    if !src.is_empty() {
        return Err(CodecError::Trailing);
    }
    Ok(Header {
        parent_id,
        slot,
        obex_version,
        seed_commit,
        vdf_y_core,
        vdf_y_edge,
        vdf_pi,
        vdf_ell,
        ticket_root,
        part_root,
        txroot_prev,
    })
}

pub trait TicketRootProvider {
    fn compute_ticket_root(&self, slot: u64) -> Hash256;
}
pub trait PartRootProvider {
    fn compute_part_root(&self, slot: u64) -> Hash256;
}
pub trait TxRootProvider {
    fn compute_txroot(&self, slot: u64) -> Hash256;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateErr {
    BadParentLink,
    BadSlot,
    VersionMismatch,
    VdfPiTooBig,
    VdfEllTooBig,
    BadSeedCommit,
    BeaconInvalid,
    TicketRootMismatch,
    PartRootMismatch,
    TxRootPrevMismatch,
}

pub fn validate_header(
    h: &Header,
    parent: &Header,
    tickets: &impl TicketRootProvider,
    parts: &impl PartRootProvider,
    txs: &impl TxRootProvider,
    expected_version: u32,
) -> Result<(), ValidateErr> {
    let parent_id_expected = obex_header_id(parent);
    if !ct_eq_hash(&h.parent_id, &parent_id_expected) {
        return Err(ValidateErr::BadParentLink);
    }
    if h.slot != parent.slot + 1 {
        return Err(ValidateErr::BadSlot);
    }
    if h.obex_version != expected_version {
        return Err(ValidateErr::VersionMismatch);
    }
    if h.vdf_pi.len() > MAX_PI_LEN {
        return Err(ValidateErr::VdfPiTooBig);
    }
    if h.vdf_ell.len() > MAX_ELL_LEN {
        return Err(ValidateErr::VdfEllTooBig);
    }
    // seed_commit equality
    let seed_commit_local = h_tag(
        constants::TAG_SLOT_SEED,
        &[&h.parent_id, &le_bytes::<8>(u128::from(h.slot))],
    );
    if !ct_eq_hash(&h.seed_commit, &seed_commit_local) {
        return Err(ValidateErr::BadSeedCommit);
    }
    // Beacon v1: pi/ell empty and edge = H(edge, [core])
    if !(h.vdf_pi.is_empty() && h.vdf_ell.is_empty()) {
        return Err(ValidateErr::BeaconInvalid);
    }
    let edge_check = h_tag(constants::TAG_VDF_EDGE, &[&h.vdf_y_core]);
    if !ct_eq_hash(&edge_check, &h.vdf_y_edge) {
        return Err(ValidateErr::BeaconInvalid);
    }
    // roots
    let ticket_root_local = tickets.compute_ticket_root(h.slot);
    if !ct_eq_hash(&h.ticket_root, &ticket_root_local) {
        return Err(ValidateErr::TicketRootMismatch);
    }
    let part_root_local = parts.compute_part_root(h.slot);
    if !ct_eq_hash(&h.part_root, &part_root_local) {
        return Err(ValidateErr::PartRootMismatch);
    }
    let txroot_prev_local = txs.compute_txroot(parent.slot);
    if !ct_eq_hash(&h.txroot_prev, &txroot_prev_local) {
        return Err(ValidateErr::TxRootPrevMismatch);
    }
    Ok(())
}
