#![allow(unused)]
use obex_alpha_ii::*;
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

struct Zero;
impl TicketRootProvider for Zero {
    fn compute_ticket_root(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}
impl PartRootProvider for Zero {
    fn compute_part_root(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}
impl TxRootProvider for Zero {
    fn compute_txroot(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}

fn mk_parent() -> Header {
    Header {
        parent_id: [9u8; 32],
        slot: 7,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [1u8; 32],
        vdf_y_core: [2u8; 32],
        vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[2u8; 32]]),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: [0u8; 32],
        part_root: [0u8; 32],
        txroot_prev: [0u8; 32],
    }
}

#[test]
fn beacon_v1_edge_mismatch_rejected() {
    let parent = mk_parent();
    let providers = Zero;
    let parent_id_hdr = obex_header_id(&parent);
    let s = parent.slot + 1;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id_hdr, &le_bytes::<8>(u128::from(s))],
    );
    let y_core = [5u8; 32];
    let y_edge_wrong = [6u8; 32];
    let h = Header {
        parent_id: parent_id_hdr,
        slot: s,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge_wrong,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: [0u8; 32],
        part_root: [0u8; 32],
        txroot_prev: [0u8; 32],
    };
    let err = validate_header(
        &h,
        &parent,
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION,
    )
    .unwrap_err();
    assert!(matches!(err, ValidateErr::BeaconInvalid));
}

#[test]
fn beacon_v1_nonempty_proofs_rejected() {
    let parent = mk_parent();
    let providers = Zero;
    let parent_id_hdr = obex_header_id(&parent);
    let s = parent.slot + 1;
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
        vdf_pi: vec![1, 2, 3],
        vdf_ell: vec![],
        ticket_root: [0u8; 32],
        part_root: [0u8; 32],
        txroot_prev: [0u8; 32],
    };
    let err = validate_header(
        &h,
        &parent,
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ValidateErr::BeaconInvalid | ValidateErr::VdfPiTooBig
    ));
}
