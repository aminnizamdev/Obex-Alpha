#![allow(unused)]
use obex_alpha_ii::{
    obex_header_id, validate_header, Header, PartRootProvider, TicketRootProvider, TxRootProvider,
    OBEX_ALPHA_II_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, Hash256};

struct ZeroRoots;
impl TicketRootProvider for ZeroRoots {
    fn compute_ticket_root(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}
impl PartRootProvider for ZeroRoots {
    fn compute_part_root(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}
impl TxRootProvider for ZeroRoots {
    fn compute_txroot(&self, _s: u64) -> Hash256 {
        [0u8; 32]
    }
}

fn empty_root() -> Hash256 {
    h_tag(constants::TAG_MERKLE_EMPTY, &[])
}

#[test]
fn header_build_validate_beacon_v1_roundtrip() {
    let parent = Header {
        parent_id: [9u8; 32],
        slot: 7,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: [1u8; 32],
        vdf_y_core: [2u8; 32],
        vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[2u8; 32]]),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: empty_root(),
        part_root: empty_root(),
        txroot_prev: empty_root(),
    };
    let parent_id_hdr = obex_header_id(&parent);
    let s = parent.slot + 1;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id_hdr, &le_bytes::<8>(u128::from(s))],
    );
    let y_core = h_tag(constants::TAG_VDF_YCORE, &[&[5u8; 32]]);
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
    let providers = ZeroRoots;
    let h = Header {
        parent_id: parent_id_hdr,
        slot: s,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: providers.compute_ticket_root(s),
        part_root: providers.compute_part_root(s),
        txroot_prev: providers.compute_txroot(parent.slot),
    };
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
