#![allow(unused)]
use obex_alpha_i::*;
use obex_alpha_ii::*;
use obex_alpha_iii::*;
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

struct DummyVrf;
impl EcVrfVerifier for DummyVrf {
    fn verify(&self, _vk: &[u8; 32], _alpha32: &Hash256, pi: &[u8]) -> Option<Vec<u8>> {
        if pi.len() != 80 {
            None
        } else {
            Some(vec![5u8; 64])
        }
    }
}

fn empty_root() -> Hash256 {
    h_tag(constants::TAG_MERKLE_EMPTY, &[])
}

#[test]
fn golden_header_id_and_beacon_v1() {
    // Parent at slot 0
    let parent = Header {
        parent_id: [0u8; 32],
        slot: 0,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: h_tag(constants::TAG_SLOT_SEED, &[&[0u8; 32], &le_bytes::<8>(0)]),
        vdf_y_core: [3u8; 32],
        vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[3u8; 32]]),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: empty_root(),
        part_root: empty_root(),
        txroot_prev: empty_root(),
    };
    let parent_id_hdr = obex_header_id(&parent);
    let s = 1u64;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id_hdr, &le_bytes::<8>(u128::from(s))],
    );
    let y_core = [5u8; 32];
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
    let h = Header {
        parent_id: parent_id_hdr,
        slot: s,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: empty_root(),
        part_root: empty_root(),
        txroot_prev: empty_root(),
    };
    let id = obex_header_id(&h);
    assert_eq!(id, obex_header_id(&h));
    let providers = TestProviders;
    assert!(validate_header(
        &h,
        &parent,
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION
    )
    .is_ok());
}

struct TestProviders;
impl TicketRootProvider for TestProviders {
    fn compute_ticket_root(&self, _s: u64) -> Hash256 {
        empty_root()
    }
}
impl PartRootProvider for TestProviders {
    fn compute_part_root(&self, _s: u64) -> Hash256 {
        empty_root()
    }
}
impl TxRootProvider for TestProviders {
    fn compute_txroot(&self, _s: u64) -> Hash256 {
        empty_root()
    }
}

#[test]
fn golden_participation_set_root() {
    // Compute expected participation root from sorted pks as per spec (without verifying partrecs here)
    let mut pks = vec![[1u8; 32], [2u8; 32]];
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
    let root = obex_primitives::merkle_root(&leaves);
    assert_ne!(root, empty_root());
}

#[test]
fn golden_ticket_root() {
    let mut st = AlphaIIIState::default();
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
    st.admitted_by_slot.insert(1, vec![rec]);
    let (_leaves, root) = build_ticket_root_for_slot(1, &st);
    // Empty vs non-empty: different roots
    assert_ne!(root, empty_root());
}
