#![allow(unused)]
use obex_alpha_i::*;

#[test]
fn partrec_roundtrip_minimal() {
    let mut challenges = Vec::with_capacity(CHALLENGES_Q);
    for _ in 0..CHALLENGES_Q {
        challenges.push(ChallengeOpen {
            idx: 1,
            li: [9u8; 32],
            pi: MerklePathLite { siblings: vec![] },
            lim1: [10u8; 32],
            pim1: MerklePathLite { siblings: vec![] },
            lj: [11u8; 32],
            pj: MerklePathLite { siblings: vec![] },
            lk: [12u8; 32],
            pk_: MerklePathLite { siblings: vec![] },
        });
    }
    let rec = ObexPartRec {
        version: OBEX_ALPHA_I_VERSION,
        slot: 1,
        pk_ed25519: [1u8; 32],
        vrf_pk: [2u8; 32],
        y_edge_prev: [3u8; 32],
        alpha: [4u8; 32],
        vrf_y: vec![5u8; 64],
        vrf_pi: vec![6u8; 80],
        seed: [7u8; 32],
        root: [8u8; 32],
        challenges,
        sig: [13u8; 64],
    };
    let bytes = encode_partrec(&rec).expect("encode");
    assert!(bytes.len() <= MAX_PARTREC_SIZE);
    let dec = decode_partrec(&bytes).expect("decode");
    assert_eq!(dec.version, rec.version);
    let bytes2 = encode_partrec(&dec).expect("encode2");
    assert_eq!(bytes, bytes2);
}
