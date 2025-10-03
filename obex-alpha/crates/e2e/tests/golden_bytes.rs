#![allow(unused)]
use obex_alpha_i::{decode_partrec, encode_partrec};
use obex_alpha_ii::{obex_header_id, serialize_header, Header, OBEX_ALPHA_II_VERSION};
use obex_primitives::{constants, h_tag, le_bytes, merkle_root, Hash256};
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/golden");
    p
}

#[test]
fn golden_alpha_i_partrec_roundtrip_bytes() {
    let mut p = golden_dir();
    p.push("alpha_i/partrec.bin");
    let bytes = fs::read(p).expect("read partrec.bin");
    let rec = decode_partrec(&bytes).expect("decode partrec");
    let enc = encode_partrec(&rec).expect("encode partrec");
    assert_eq!(bytes, enc, "partrec bytes must roundtrip exactly");
}

#[test]
fn golden_header_bytes_and_id_match() {
    let mut dir = golden_dir();
    // Read VDF goldens
    let y_core = {
        let mut p = dir.clone();
        p.push("vdf/y_core.bin");
        let b = fs::read(p).expect("read y_core.bin");
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    let y_edge_file = {
        let mut p = dir.clone();
        p.push("vdf/y_edge.bin");
        let b = fs::read(p).expect("read y_edge.bin");
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    // Build expected header per GenGoldens: parent_id=0, slot=1, empty roots
    let parent_id = [0u8; 32];
    let slot = 1u64;
    let seed_commit = h_tag(
        constants::TAG_SLOT_SEED,
        &[&parent_id, &le_bytes::<8>(u128::from(slot))],
    );
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
    assert_eq!(y_edge, y_edge_file, "y_edge must equal H(edge,[y_core])");
    let header = Header {
        parent_id,
        slot,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        part_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
    };
    let hdr_bytes = serialize_header(&header);
    let hdr_id = obex_header_id(&header);
    // Compare to goldens
    let mut p_hdr = dir.clone();
    p_hdr.push("header/header.bin");
    let hdr_bin_file = fs::read(p_hdr).expect("read header.bin");
    assert_eq!(hdr_bytes, hdr_bin_file, "header bytes must match golden");
    let mut p_id = dir.clone();
    p_id.push("header/header_id.bin");
    let hdr_id_file = fs::read(p_id).expect("read header_id.bin");
    assert_eq!(hdr_id.as_slice(), hdr_id_file.as_slice(), "header id must match golden");
}

#[test]
fn golden_alpha_iii_ticket_root_matches() {
    let mut dir = golden_dir();
    let mut p_leaves = dir.clone();
    p_leaves.push("alpha_iii/ticket_leaves.bin");
    let buf = fs::read(p_leaves).expect("read ticket_leaves.bin");
    let mut p_root = dir.clone();
    p_root.push("alpha_iii/ticket_root.bin");
    let root_bytes = fs::read(p_root).expect("read ticket_root.bin");
    let mut expected_root = [0u8; 32];
    expected_root.copy_from_slice(&root_bytes);
    // Split leaves by canonical length 216 and compute root
    const LEAF_LEN: usize = 216;
    assert!(buf.len() % LEAF_LEN == 0, "concat length must be multiple of 216");
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(buf.len() / LEAF_LEN);
    let mut i = 0usize;
    while i < buf.len() {
        leaves.push(buf[i..i + LEAF_LEN].to_vec());
        i += LEAF_LEN;
    }
    let root = merkle_root(&leaves);
    assert_eq!(root, expected_root, "ticket root must match golden");
}


