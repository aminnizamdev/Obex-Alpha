use criterion::{black_box, criterion_group, criterion_main, Criterion};
use obex_alpha_i::*;
use obex_primitives::Hash256;

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

fn bench_alpha_i_verify(c: &mut Criterion) {
    let vrf = DummyVrf;
    let slot = 1u64;
    let parent_id = [0u8; 32];
    let mut rec = ObexPartRec {
        version: OBEX_ALPHA_I_VERSION,
        slot,
        pk_ed25519: [1u8; 32],
        vrf_pk: [2u8; 32],
        y_edge_prev: [3u8; 32],
        alpha: [4u8; 32],
        vrf_y: vec![5u8; 64],
        vrf_pi: vec![6u8; 80],
        seed: [7u8; 32],
        root: [8u8; 32],
        challenges: Vec::new(),
        sig: [13u8; 64],
    };
    rec.challenges = (0..CHALLENGES_Q)
        .map(|_| ChallengeOpen {
            idx: 1,
            li: [9u8; 32],
            pi: MerklePathLite { siblings: vec![] },
            lim1: [10u8; 32],
            pim1: MerklePathLite { siblings: vec![] },
            lj: [11u8; 32],
            pj: MerklePathLite { siblings: vec![] },
            lk: [12u8; 32],
            pk_: MerklePathLite { siblings: vec![] },
        })
        .collect();
    c.bench_function("alpha_i_verify_q96", |b| {
        b.iter(|| {
            let _ = obex_verify_partrec(
                black_box(&rec),
                black_box(slot),
                black_box(&parent_id),
                &vrf,
            );
        });
    });
}

criterion_group!(benches, bench_alpha_i_verify);
criterion_main!(benches);
