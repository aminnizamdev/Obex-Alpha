use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obex_alpha_ii::{
    obex_header_id, validate_header, Header, PartRootProvider, TicketRootProvider, TxRootProvider,
    OBEX_ALPHA_II_VERSION,
};
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

fn bench_validate_header(c: &mut Criterion) {
    let parent = Header {
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
    };
    let providers = Zero;
    let parent_id_hdr = obex_header_id(&parent);
    let s = parent.slot + 1;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id_hdr, &le_bytes::<8>(u128::from(s))],
    );
    let h = Header {
        parent_id: parent_id_hdr,
        slot: s,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: [5u8; 32],
        vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[5u8; 32]]),
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: [0u8; 32],
        part_root: [0u8; 32],
        txroot_prev: [0u8; 32],
    };
    c.bench_function("validate_header", |b| {
        b.iter(|| {
            let _ = validate_header(
                black_box(&h),
                black_box(&parent),
                &providers,
                &providers,
                &providers,
                OBEX_ALPHA_II_VERSION,
            )
            .unwrap();
        });
    });
}

criterion_group!(benches, bench_validate_header);
criterion_main!(benches);
