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

//! α‑T — Tokenomics (emission, NLB fee splits, DRP, sys tx ordering)

use obex_primitives::{constants, h_tag, Hash256};
use primitive_types::U256;
use std::sync::LazyLock as Lazy;

pub const OBEX_ALPHA_T_VERSION: u32 = 1;
pub const UOBX_PER_OBX: u128 = 100_000_000;
pub const TOTAL_SUPPLY_OBX: u128 = 1_000_000;
pub const TOTAL_SUPPLY_UOBX: u128 = TOTAL_SUPPLY_OBX * UOBX_PER_OBX;

pub const SLOT_MS: u64 = 100;
pub const SLOTS_PER_SEC: u64 = 1_000 / SLOT_MS;
pub const PROTOCOL_YEAR_SEC: u64 = 365 * 86_400;
pub const SLOTS_PER_YEAR: u64 = PROTOCOL_YEAR_SEC * SLOTS_PER_SEC;
pub const YEARS_PER_HALVING: u64 = 5;
pub const SLOTS_PER_HALVING: u128 = (SLOTS_PER_YEAR as u128) * (YEARS_PER_HALVING as u128);
pub const HALVING_COUNT: u32 = 20;
pub const LAST_EMISSION_SLOT: u128 = (SLOTS_PER_YEAR as u128) * 100;

fn pow2_u256(n: u32) -> U256 {
    U256::from(1u8) << n
}
static TWO_POW_N_MINUS1: Lazy<U256> = Lazy::new(|| pow2_u256(HALVING_COUNT - 1));
static TWO_POW_N: Lazy<U256> = Lazy::new(|| pow2_u256(HALVING_COUNT));
static R0_NUM: Lazy<U256> = Lazy::new(|| U256::from(TOTAL_SUPPLY_UOBX) * *TWO_POW_N_MINUS1);
static R0_DEN: Lazy<U256> =
    Lazy::new(|| U256::from(SLOTS_PER_HALVING) * (*TWO_POW_N - U256::from(1u8)));

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct EmissionState {
    pub total_emitted_u: u128,
    pub acc_num: U256,
}

#[inline]
fn period_index(slot_1based: u128) -> u32 {
    let periods = (slot_1based - 1) / SLOTS_PER_HALVING;
    u32::try_from(periods).expect("period index overflow")
}

fn reward_den_for_period(p: u32) -> U256 {
    *R0_DEN * pow2_u256(p)
}

pub fn on_slot_emission(
    st: &mut EmissionState,
    slot_1based: u128,
    mut credit_emission: impl FnMut(u128),
) {
    if slot_1based == 0 || slot_1based > LAST_EMISSION_SLOT {
        return;
    }
    let p = period_index(slot_1based);
    let den = reward_den_for_period(p);
    st.acc_num += *R0_NUM;
    let payout_u256 = st.acc_num / den;
    if payout_u256 > U256::zero() {
        let payout = payout_u256.as_u128();
        let remaining = TOTAL_SUPPLY_UOBX - st.total_emitted_u;
        let pay = payout.min(remaining);
        if pay > 0 {
            credit_emission(pay);
            st.total_emitted_u = st.total_emitted_u.saturating_add(pay);
            st.acc_num -= U256::from(pay) * den;
        }
    }
    if slot_1based == LAST_EMISSION_SLOT {
        let remaining = TOTAL_SUPPLY_UOBX.saturating_sub(st.total_emitted_u);
        if remaining > 0 {
            credit_emission(remaining);
            st.total_emitted_u = TOTAL_SUPPLY_UOBX;
            st.acc_num = U256::zero();
        }
        assert!(st.total_emitted_u == TOTAL_SUPPLY_UOBX);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysTxKind {
    EscrowCredit,
    VerifierCredit,
    TreasuryCredit,
    Burn,
    RewardPayout,
    EmissionCredit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysTx {
    pub kind: SysTxKind,
    pub slot: u64,
    pub pk: Hash256,
    pub amt: u128,
}

#[must_use]
fn reward_rank(y: &Hash256, pk: &Hash256) -> Hash256 {
    h_tag(constants::TAG_REWARD_RANK, &[y, pk])
}

#[must_use]
pub fn canonical_sys_tx_order(sys_txs: Vec<SysTx>, y_edge_s: &Hash256) -> Vec<SysTx> {
    let mut rewards: Vec<SysTx> = sys_txs
        .iter()
        .copied()
        .filter(|t| matches!(t.kind, SysTxKind::RewardPayout))
        .collect();
    let mut others: Vec<SysTx> = sys_txs
        .into_iter()
        .filter(|t| !matches!(t.kind, SysTxKind::RewardPayout))
        .collect();
    others.sort_by_key(|tx| match tx.kind {
        SysTxKind::EscrowCredit => 0,
        SysTxKind::EmissionCredit => 1,
        SysTxKind::VerifierCredit => 2,
        SysTxKind::TreasuryCredit => 3,
        SysTxKind::Burn => 4,
        SysTxKind::RewardPayout => 5,
    });
    rewards.sort_by(|a, b| reward_rank(y_edge_s, &a.pk).cmp(&reward_rank(y_edge_s, &b.pk)));
    others.extend(rewards);
    others
}
