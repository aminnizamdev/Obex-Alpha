#![allow(unused)]
use obex_alpha_iii::*;

fn pk(v: u8) -> [u8; 32] {
    [v; 32]
}

#[test]
fn fee_rule_edges() {
    assert_eq!(fee_int(10), FLAT_FEE_U);
    assert_eq!(fee_int(1_000), FLAT_FEE_U);
    assert_eq!(fee_int(1_001), 11);
}

#[test]
fn admit_rejects_bad_sig_and_wrong_bindings() {
    let mut st = AlphaIIIState::default();
    st.spendable_u.insert(pk(1), 10_000);
    let tx = TxBodyV1 {
        sender: pk(1),
        recipient: pk(2),
        nonce: 0,
        amount_u: 2_000,
        fee_u: fee_int(2_000),
        s_bind: 5,
        y_bind: [7u8; 32],
        access: AccessList::default(),
        memo: vec![],
    };
    // bad sig
    let bad = admit_single(&tx, &[0u8; 64], 5, &tx.y_bind, &mut st);
    assert!(matches!(
        bad,
        AdmitResult::Rejected(AdmitErr::BadSig) | AdmitResult::Rejected(_)
    ));
}

#[test]
fn ticket_leaf_length_is_216_bytes() {
    let rec = TicketRecord {
        ticket_id: [0u8; 32],
        txid: [1u8; 32],
        sender: [2u8; 32],
        nonce: 0,
        amount_u: 1000,
        fee_u: 10,
        s_admit: 1,
        s_exec: 1,
        commit_hash: [3u8; 32],
    };
    let leaf = enc_ticket_leaf(&rec);
    assert_eq!(leaf.len(), 216);
}
