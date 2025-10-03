#![allow(unused)]
use obex_alpha_i::{decode_partrec, encode_partrec, CHALLENGES_Q};
use obex_alpha_ii::{deserialize_header, obex_header_id};
use obex_alpha_iii::enc_ticket_leaf;
use obex_primitives::merkle_root;
use obex_primitives::{constants, h_tag, le_bytes, Hash256};
use std::{env, fs, path::PathBuf};
struct DummyProviders;
impl obex_alpha_ii::TicketRootProvider for DummyProviders {
    fn compute_ticket_root(&self, _s: u64) -> Hash256 {
        h_tag(constants::TAG_MERKLE_EMPTY, &[])
    }
}
impl obex_alpha_ii::PartRootProvider for DummyProviders {
    fn compute_part_root(&self, _s: u64) -> Hash256 {
        h_tag(constants::TAG_MERKLE_EMPTY, &[])
    }
}
impl obex_alpha_ii::TxRootProvider for DummyProviders {
    fn compute_txroot(&self, _s: u64) -> Hash256 {
        h_tag(constants::TAG_MERKLE_EMPTY, &[])
    }
}

fn goldens_dir() -> Option<PathBuf> {
    if let Ok(p) = env::var("GOLDENS_DIR") {
        return Some(PathBuf::from(p));
    }
    let local = PathBuf::from("tests/golden");
    if local.exists() {
        Some(local)
    } else {
        None
    }
}

fn read_bytes(p: &PathBuf) -> Option<Vec<u8>> {
    fs::read(p).ok()
}

#[test]
fn conformance_header_and_beacon_v1() {
    let Some(root) = goldens_dir() else {
        eprintln!("goldens missing; skipping");
        return;
    };
    let hdr_path = root.join("header/header.bin");
    let id_path = root.join("header/header_id.bin");
    let Some(hdr_bytes) = read_bytes(&hdr_path) else {
        eprintln!("no header.bin");
        return;
    };
    let Some(id_bytes) = read_bytes(&id_path) else {
        eprintln!("no header_id.bin");
        return;
    };
    let header = deserialize_header(&hdr_bytes).expect("decode header");
    // Beacon v1 checks
    assert!(header.vdf_pi.is_empty() && header.vdf_ell.is_empty());
    let edge = h_tag(constants::TAG_VDF_EDGE, &[&header.vdf_y_core]);
    assert_eq!(edge, header.vdf_y_edge);
    // Header ID
    let id = obex_header_id(&header);
    assert_eq!(id.as_slice(), id_bytes.as_slice());
}

#[test]
fn conformance_alpha_i_partrec_roundtrip() {
    let Some(root) = goldens_dir() else {
        eprintln!("goldens missing; skipping");
        return;
    };
    let bytes_path = root.join("alpha_i/partrec.bin");
    let Some(bytes) = read_bytes(&bytes_path) else {
        eprintln!("no partrec.bin");
        return;
    };
    let rec = decode_partrec(&bytes).expect("decode");
    assert_eq!(rec.challenges.len(), CHALLENGES_Q);
    let re = encode_partrec(&rec).expect("encode");
    assert_eq!(re, bytes);
}

#[test]
fn conformance_alpha_iii_ticket_root() {
    let Some(root) = goldens_dir() else {
        eprintln!("goldens missing; skipping");
        return;
    };
    let leaves_path = root.join("alpha_iii/ticket_leaves.bin");
    let root_path = root.join("alpha_iii/ticket_root.bin");
    let Some(concat) = read_bytes(&leaves_path) else {
        eprintln!("no ticket_leaves.bin");
        return;
    };
    let Some(root_bytes) = read_bytes(&root_path) else {
        eprintln!("no ticket_root.bin");
        return;
    };
    let mut leaves = Vec::new();
    // Leaf length = 248 (see BYTE_LAYOUTS.md)
    const L: usize = 248;
    if concat.len() % L != 0 {
        panic!("bad leaves concat length");
    }
    let mut i = 0usize;
    while i < concat.len() {
        leaves.push(concat[i..i + L].to_vec());
        i += L;
    }
    let local_root = merkle_root(&leaves);
    assert_eq!(local_root.as_slice(), root_bytes.as_slice());
}

#[test]
fn conformance_negatives() {
    let Some(root) = goldens_dir() else {
        eprintln!("goldens missing; skipping");
        return;
    };
    // 1) vdf y_edge mismatch
    if let (Some(y_core), Some(bad_edge)) = (
        read_bytes(&root.join("vdf/y_core.bin")),
        read_bytes(&root.join("negatives/vdf_bad_y_edge.bin")),
    ) {
        let calc = h_tag(constants::TAG_VDF_EDGE, &[y_core.as_slice()]);
        assert_ne!(calc.as_slice(), bad_edge.as_slice());
    }
    // 2) header with non-empty pi should fail validate against a dummy parent
    if let Some(bad_hdr) = read_bytes(&root.join("negatives/header_bad_pi.bin")) {
        let h = deserialize_header(&bad_hdr).expect("decode bad header");
        // Create dummy parent with matching slot-1 and id
        let parent = obex_alpha_ii::Header {
            parent_id: [0u8; 32],
            slot: h.slot.saturating_sub(1),
            obex_version: h.obex_version,
            seed_commit: h_tag(
                constants::TAG_SLOT_SEED,
                &[&h.parent_id, &le_bytes::<8>(u128::from(h.slot))],
            ),
            vdf_y_core: [2u8; 32],
            vdf_y_edge: h_tag(constants::TAG_VDF_EDGE, &[&[2u8; 32]]),
            vdf_pi: vec![],
            vdf_ell: vec![],
            ticket_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
            part_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
            txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        };
        let providers = DummyProviders;
        let res = obex_alpha_ii::validate_header(
            &h,
            &parent,
            &providers,
            &providers,
            &providers,
            h.obex_version,
        );
        assert!(res.is_err());
    }
    // 3) truncated partrec must fail to decode
    if let Some(trunc) = read_bytes(&root.join("negatives/partrec_truncated.bin")) {
        assert!(decode_partrec(&trunc).is_err());
    }
}
