#![allow(unused)]
use obex_alpha_t::*;

#[test]
fn emission_monotone_and_terminal_flush() {
    let mut st = EmissionState::default();
    let mut last = 0u128;
    for s in 1u128..=1_000 {
        on_slot_emission(&mut st, s, |_| {});
        assert!(st.total_emitted_u >= last);
        last = st.total_emitted_u;
    }
    on_slot_emission(&mut st, LAST_EMISSION_SLOT, |_| {});
    assert_eq!(st.total_emitted_u, TOTAL_SUPPLY_UOBX);
}

#[test]
fn sys_tx_ordering_canonical() {
    let y = [0u8; 32];
    let mut txs = vec![
        SysTx {
            kind: SysTxKind::Burn,
            slot: 1,
            pk: [1u8; 32],
            amt: 5,
        },
        SysTx {
            kind: SysTxKind::RewardPayout,
            slot: 1,
            pk: [2u8; 32],
            amt: 7,
        },
        SysTx {
            kind: SysTxKind::EscrowCredit,
            slot: 1,
            pk: [3u8; 32],
            amt: 9,
        },
        SysTx {
            kind: SysTxKind::VerifierCredit,
            slot: 1,
            pk: [4u8; 32],
            amt: 2,
        },
        SysTx {
            kind: SysTxKind::TreasuryCredit,
            slot: 1,
            pk: [5u8; 32],
            amt: 3,
        },
        SysTx {
            kind: SysTxKind::EmissionCredit,
            slot: 1,
            pk: [6u8; 32],
            amt: 11,
        },
        SysTx {
            kind: SysTxKind::RewardPayout,
            slot: 1,
            pk: [7u8; 32],
            amt: 13,
        },
    ];
    let ordered = canonical_sys_tx_order(std::mem::take(&mut txs), &y);
    assert!(matches!(ordered[0].kind, SysTxKind::EscrowCredit));
    assert!(matches!(ordered[1].kind, SysTxKind::EmissionCredit));
    assert!(matches!(ordered[2].kind, SysTxKind::VerifierCredit));
    assert!(matches!(ordered[3].kind, SysTxKind::TreasuryCredit));
    assert!(matches!(ordered[4].kind, SysTxKind::Burn));
    assert!(matches!(ordered[5].kind, SysTxKind::RewardPayout));
}
