#![allow(unused)]
use obex_alpha_ii::{
    obex_header_id, validate_header, Header, PartRootProvider, TicketRootProvider, TxRootProvider,
    OBEX_ALPHA_II_VERSION,
};
use obex_alpha_iii::{enc_ticket_leaf, TicketRecord};
use obex_primitives::{constants, h_tag, le_bytes, merkle_root, Hash256};

struct FixedProviders {
    ticket_root: Hash256,
    part_root: Hash256,
    txroot_prev: Hash256,
}
impl TicketRootProvider for FixedProviders {
    fn compute_ticket_root(&self, _s: u64) -> Hash256 {
        self.ticket_root
    }
}
impl PartRootProvider for FixedProviders {
    fn compute_part_root(&self, _s: u64) -> Hash256 {
        self.part_root
    }
}
impl TxRootProvider for FixedProviders {
    fn compute_txroot(&self, _s: u64) -> Hash256 {
        self.txroot_prev
    }
}

fn part_root_from_pks(pks: &mut Vec<[u8; 32]>) -> Hash256 {
    pks.sort_unstable();
    pks.dedup();
    let leaves: Vec<Vec<u8>> = pks
        .iter()
        .map(|pk| {
            let mut b = Vec::with_capacity(64);
            b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
            b.extend_from_slice(pk);
            b
        })
        .collect();
    merkle_root(&leaves)
}

#[test]
fn validate_header_with_nonempty_roots() {
    // Parent at slot 0
    let parent = Header {
        parent_id: [0u8; 32],
        slot: 0,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit: h_tag(constants::TAG_SLOT_SEED, &[&[0u8; 32], &le_bytes::<8>(0)]),
        vdf_y_core: [2u8; 32],
        vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[2u8; 32]]),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        part_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
    };
    let parent_id_hdr = obex_header_id(&parent);
    let s = 1u64;

    // Build ticket leaves/root
    let rec = TicketRecord {
        ticket_id: [0u8; 32],
        txid: [1u8; 32],
        sender: [2u8; 32],
        nonce: 0,
        amount_u: 1000,
        fee_u: 10,
        s_admit: s,
        s_exec: s,
        commit_hash: [3u8; 32],
    };
    let ticket_leaves: Vec<Vec<u8>> = vec![enc_ticket_leaf(&rec)];
    let ticket_root = merkle_root(&ticket_leaves);

    // Build part root from two pks
    let mut pks = vec![[1u8; 32], [2u8; 32]];
    let part_root = part_root_from_pks(&mut pks);

    // Build header with fixed roots
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
        ticket_root,
        part_root,
        txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
    };
    let providers = FixedProviders {
        ticket_root,
        part_root,
        txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
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

    // Flip a root to ensure mismatch is detected
    let mut bad = h.clone();
    bad.ticket_root[0] ^= 1;
    assert!(validate_header(
        &bad,
        &parent,
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION
    )
    .is_err());
}
