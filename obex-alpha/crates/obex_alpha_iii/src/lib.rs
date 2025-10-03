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

//! α‑III — Admission Engine (canonical tx bytes, fees, TicketRecord, root)

use ed25519_dalek::{Signature, VerifyingKey};
use obex_primitives::{constants, h_tag, le_bytes, merkle_root, Hash256};

pub type Pk32 = [u8; 32];
pub type Sig64 = [u8; 64];

pub const OBEX_ALPHA_III_VERSION: u32 = 1;
pub const MIN_TX_U: u128 = 10;
pub const FLAT_SWITCH_U: u128 = 1_000;
pub const FLAT_FEE_U: u128 = 10;

#[must_use]
pub fn fee_int(amount_u: u128) -> u128 {
    assert!(amount_u >= MIN_TX_U);
    if amount_u <= FLAT_SWITCH_U {
        FLAT_FEE_U
    } else {
        amount_u.div_ceil(100)
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct AccessList {
    pub read_accounts: Vec<Pk32>,
    pub write_accounts: Vec<Pk32>,
}

fn sort_dedup(mut v: Vec<Pk32>) -> Vec<Pk32> {
    v.sort_unstable();
    v.dedup();
    v
}

#[must_use]
pub fn encode_access(a: &AccessList) -> Vec<u8> {
    let r = sort_dedup(a.read_accounts.clone());
    let w = sort_dedup(a.write_accounts.clone());
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag(constants::TAG_TX_ACCESS, &[]));
    out.extend_from_slice(&le_bytes::<4>(r.len() as u128));
    for pk in &r {
        out.extend_from_slice(pk);
    }
    out.extend_from_slice(&le_bytes::<4>(w.len() as u128));
    for pk in &w {
        out.extend_from_slice(pk);
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxBodyV1 {
    pub sender: Pk32,
    pub recipient: Pk32,
    pub nonce: u64,
    pub amount_u: u128,
    pub fee_u: u128,
    pub s_bind: u64,
    pub y_bind: Hash256,
    pub access: AccessList,
    pub memo: Vec<u8>,
}

#[must_use]
pub fn canonical_tx_bytes(tx: &TxBodyV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag(constants::TAG_TX_BODY_V1, &[]));
    out.extend_from_slice(&tx.sender);
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&le_bytes::<8>(u128::from(tx.nonce)));
    out.extend_from_slice(&le_bytes::<16>(tx.amount_u));
    out.extend_from_slice(&le_bytes::<16>(tx.fee_u));
    out.extend_from_slice(&le_bytes::<8>(u128::from(tx.s_bind)));
    out.extend_from_slice(&tx.y_bind);
    out.extend_from_slice(&encode_access(&tx.access));
    out.extend_from_slice(&le_bytes::<4>(tx.memo.len() as u128));
    out.extend_from_slice(&tx.memo);
    out
}

#[must_use]
pub fn txid(tx: &TxBodyV1) -> Hash256 {
    h_tag(constants::TAG_TX_ID, &[&canonical_tx_bytes(tx)])
}
#[must_use]
pub fn tx_commit(tx: &TxBodyV1) -> Hash256 {
    h_tag(constants::TAG_TX_COMMIT, &[&canonical_tx_bytes(tx)])
}

#[must_use]
fn verify_sig(pk: &Pk32, msg: &[u8], sig: &Sig64) -> bool {
    match (VerifyingKey::from_bytes(pk), Signature::from_slice(sig)) {
        (Ok(vk), Ok(sig_d)) => vk.verify_strict(msg, &sig_d).is_ok(),
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketRecord {
    pub ticket_id: Hash256,
    pub txid: Hash256,
    pub sender: Pk32,
    pub nonce: u64,
    pub amount_u: u128,
    pub fee_u: u128,
    pub s_admit: u64,
    pub s_exec: u64,
    pub commit_hash: Hash256,
}

#[must_use]
pub fn enc_ticket_leaf(t: &TicketRecord) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h_tag(constants::TAG_TICKET_LEAF, &[]));
    out.extend_from_slice(&t.ticket_id);
    out.extend_from_slice(&t.txid);
    out.extend_from_slice(&t.sender);
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.nonce)));
    out.extend_from_slice(&le_bytes::<16>(t.amount_u));
    out.extend_from_slice(&le_bytes::<16>(t.fee_u));
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.s_admit)));
    out.extend_from_slice(&le_bytes::<8>(u128::from(t.s_exec)));
    out.extend_from_slice(&t.commit_hash);
    out
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct AlphaIIIState {
    pub spendable_u: std::collections::BTreeMap<Pk32, u128>,
    pub reserved_u: std::collections::BTreeMap<Pk32, u128>,
    pub next_nonce: std::collections::BTreeMap<Pk32, u64>,
    pub admitted_by_slot: std::collections::BTreeMap<u64, Vec<TicketRecord>>,
    pub tickets_by_txid: std::collections::BTreeMap<Hash256, TicketRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitErr {
    BadSig,
    WrongSlot,
    WrongBeacon,
    NonceMismatch,
    BelowMinAmount,
    FeeMismatch,
    InsufficientFunds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitResult {
    Finalized(TicketRecord),
    Rejected(AdmitErr),
}

pub fn admit_single(
    tx: &TxBodyV1,
    sig: &Sig64,
    s_now: u64,
    y_prev: &Hash256,
    st: &mut AlphaIIIState,
) -> AdmitResult {
    let msg = h_tag(constants::TAG_TX_SIG, &[&canonical_tx_bytes(tx)]);
    if !verify_sig(&tx.sender, &msg, sig) {
        return AdmitResult::Rejected(AdmitErr::BadSig);
    }
    if tx.s_bind != s_now {
        return AdmitResult::Rejected(AdmitErr::WrongSlot);
    }
    if tx.y_bind != *y_prev {
        return AdmitResult::Rejected(AdmitErr::WrongBeacon);
    }
    if tx.nonce != *st.next_nonce.get(&tx.sender).unwrap_or(&0) {
        return AdmitResult::Rejected(AdmitErr::NonceMismatch);
    }
    if tx.amount_u < MIN_TX_U {
        return AdmitResult::Rejected(AdmitErr::BelowMinAmount);
    }
    if tx.fee_u != fee_int(tx.amount_u) {
        return AdmitResult::Rejected(AdmitErr::FeeMismatch);
    }
    let total = tx.amount_u.saturating_add(tx.fee_u);
    if st.spendable_u.get(&tx.sender).copied().unwrap_or(0) < total {
        return AdmitResult::Rejected(AdmitErr::InsufficientFunds);
    }

    *st.spendable_u.entry(tx.sender).or_insert(0) -= total;
    *st.reserved_u.entry(tx.sender).or_insert(0) += total;
    *st.next_nonce.entry(tx.sender).or_insert(0) += 1;

    let xid = txid(tx);
    let rec = TicketRecord {
        ticket_id: h_tag(
            constants::TAG_TICKET_ID,
            &[&xid, &le_bytes::<8>(u128::from(s_now))],
        ),
        txid: xid,
        sender: tx.sender,
        nonce: tx.nonce,
        amount_u: tx.amount_u,
        fee_u: tx.fee_u,
        s_admit: s_now,
        s_exec: s_now,
        commit_hash: tx_commit(tx),
    };
    st.admitted_by_slot
        .entry(s_now)
        .or_default()
        .push(rec.clone());
    st.tickets_by_txid.insert(rec.txid, rec.clone());
    AdmitResult::Finalized(rec)
}

#[must_use]
pub fn build_ticket_root_for_slot(s: u64, st: &AlphaIIIState) -> (Vec<Vec<u8>>, Hash256) {
    let mut list = st.admitted_by_slot.get(&s).cloned().unwrap_or_default();
    list.sort_by(|a, b| a.txid.cmp(&b.txid));
    let leaves: Vec<Vec<u8>> = list.iter().map(enc_ticket_leaf).collect();
    let root = merkle_root(&leaves);
    (leaves, root)
}
