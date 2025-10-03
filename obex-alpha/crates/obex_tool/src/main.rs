#![forbid(unsafe_code)]
#![deny(warnings)]

use clap::{Parser, Subcommand};
use obex_alpha_i::{decode_partrec, encode_partrec};
use obex_alpha_ii::{obex_header_id, serialize_header, Header, OBEX_ALPHA_II_VERSION};
use obex_alpha_iii::{enc_ticket_leaf, TicketRecord};
use obex_primitives::merkle_root;
use obex_primitives::{constants, h_tag, le_bytes};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "obex-tool")]
#[command(about = "OBEX Alpha tooling", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Re-encode a canonical ObexPartRec and print length
    PartrecLen {
        #[arg(value_name = "HEX")]
        hex: String,
    },
    /// Generate beacon v1 and header goldens into --out directory
    GenGoldens {
        #[arg(long)]
        out: PathBuf,
    },
    /// Run a short burn-in across N nodes to check HeaderID divergence
    BurnIn {
        #[arg(long, default_value_t = 1000)]
        slots: u64,
        #[arg(long, value_delimiter = ',')]
        nodes: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::PartrecLen { hex } => {
            let bytes = hex::decode(hex).expect("hex");
            let rec = decode_partrec(&bytes).expect("decode");
            let enc = encode_partrec(&rec).expect("encode");
            println!("{}", enc.len());
        }
        Commands::GenGoldens { out } => {
            fs::create_dir_all(out.join("vdf")).expect("mkdir vdf");
            fs::create_dir_all(out.join("header")).expect("mkdir header");
            fs::create_dir_all(out.join("alpha_i")).expect("mkdir alpha_i");
            fs::create_dir_all(out.join("alpha_iii")).expect("mkdir alpha_iii");
            // vdf set (beacon v1)
            let parent_id = [0u8; 32];
            let s = 1u64;
            let seed_commit = h_tag(
                constants::TAG_SLOT_SEED,
                &[&parent_id, &le_bytes::<8>(u128::from(s))],
            );
            let y_core = [3u8; 32];
            let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
            fs::write(out.join("vdf/seed_commit.bin"), seed_commit).expect("write");
            fs::write(out.join("vdf/y_core.bin"), y_core).expect("write");
            fs::write(out.join("vdf/y_edge.bin"), y_edge).expect("write");
            fs::write(out.join("vdf/pi.bin"), &[] as &[u8]).expect("write");
            fs::write(out.join("vdf/ell.bin"), &[] as &[u8]).expect("write");
            // header set
            let header = Header {
                parent_id,
                slot: s,
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
            fs::write(out.join("header/header.bin"), hdr_bytes).expect("write");
            fs::write(out.join("header/header_id.bin"), hdr_id).expect("write");
            // alpha_i: minimal partrec bytes (non-cryptographic; for decode/roundtrip tests)
            let mut challenges = Vec::new();
            for _ in 0..obex_alpha_i::CHALLENGES_Q {
                challenges.push(obex_alpha_i::ChallengeOpen {
                    idx: 1,
                    li: [9u8; 32],
                    pi: obex_alpha_i::MerklePathLite { siblings: vec![] },
                    lim1: [10u8; 32],
                    pim1: obex_alpha_i::MerklePathLite { siblings: vec![] },
                    lj: [11u8; 32],
                    pj: obex_alpha_i::MerklePathLite { siblings: vec![] },
                    lk: [12u8; 32],
                    pk_: obex_alpha_i::MerklePathLite { siblings: vec![] },
                });
            }
            let rec = obex_alpha_i::ObexPartRec {
                version: obex_alpha_i::OBEX_ALPHA_I_VERSION,
                slot: s,
                pk_ed25519: [1u8; 32],
                vrf_pk: [2u8; 32],
                y_edge_prev: [3u8; 32],
                alpha: h_tag(
                    constants::TAG_ALPHA,
                    &[
                        &parent_id,
                        &le_bytes::<8>(u128::from(s)),
                        &[3u8; 32],
                        &[2u8; 32],
                    ],
                ),
                vrf_y: vec![5u8; 64],
                vrf_pi: vec![6u8; 80],
                seed: h_tag(constants::TAG_SEED, &[&[3u8; 32], &[1u8; 32], &[5u8; 64]]),
                root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
                challenges,
                sig: [13u8; 64],
            };
            let partrec_bytes = obex_alpha_i::encode_partrec(&rec).expect("encode partrec");
            fs::write(out.join("alpha_i/partrec.bin"), &partrec_bytes).expect("write");
            // alpha_iii: ticket leaves and root
            let rec3 = TicketRecord {
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
            let leaves: Vec<Vec<u8>> = vec![enc_ticket_leaf(&rec3)];
            let root = merkle_root(&leaves);
            let mut concat = Vec::new();
            for l in &leaves {
                concat.extend_from_slice(l);
            }
            fs::write(out.join("alpha_iii/ticket_leaves.bin"), concat).expect("write");
            fs::write(out.join("alpha_iii/ticket_root.bin"), root).expect("write");
            // negatives
            let neg = out.join("negatives");
            fs::create_dir_all(&neg).expect("mkdir negatives");
            // 1) vdf y_edge mismatch
            let mut bad_edge = y_edge;
            bad_edge[0] ^= 1;
            fs::write(neg.join("vdf_bad_y_edge.bin"), bad_edge).expect("write");
            // 2) vdf non-empty pi
            fs::write(neg.join("vdf_nonempty_pi.bin"), vec![1u8]).expect("write");
            // 3) header with non-empty pi
            let mut bad_header = header.clone();
            bad_header.vdf_pi = vec![1u8];
            let bad_hdr_bytes = serialize_header(&bad_header);
            fs::write(neg.join("header_bad_pi.bin"), bad_hdr_bytes).expect("write");
            // 4) partrec truncated
            let mut trunc = partrec_bytes.clone();
            if !trunc.is_empty() {
                trunc.pop();
            }
            fs::write(neg.join("partrec_truncated.bin"), trunc).expect("write");
            println!("goldens (and negatives) written to {}", out.display());
        }
        Commands::BurnIn { slots, nodes } => {
            assert!(!nodes.is_empty(), "--nodes must list at least one base URL");
            // Fetch parent header (slot 0) from first node
            let client = reqwest::blocking::Client::new();
            let base = nodes[0].trim_end_matches('/');
            #[derive(serde::Deserialize)]
            struct HeaderDto {
                parent_id: [u8; 32],
                slot: u64,
                obex_version: u32,
                seed_commit: [u8; 32],
                vdf_y_core: [u8; 32],
                vdf_y_edge: [u8; 32],
                vdf_pi: Vec<u8>,
                vdf_ell: Vec<u8>,
                ticket_root: [u8; 32],
                part_root: [u8; 32],
                txroot_prev: [u8; 32],
            }
            impl From<HeaderDto> for Header {
                fn from(d: HeaderDto) -> Self {
                    Header {
                        parent_id: d.parent_id,
                        slot: d.slot,
                        obex_version: d.obex_version,
                        seed_commit: d.seed_commit,
                        vdf_y_core: d.vdf_y_core,
                        vdf_y_edge: d.vdf_y_edge,
                        vdf_pi: d.vdf_pi,
                        vdf_ell: d.vdf_ell,
                        ticket_root: d.ticket_root,
                        part_root: d.part_root,
                        txroot_prev: d.txroot_prev,
                    }
                }
            }
            let parent_dto: HeaderDto = client
                .get(format!("{}/header/0", base))
                .send()
                .expect("get parent")
                .json::<HeaderDto>()
                .expect("json dto");
            let parent: Header = parent_dto.into();
            let mut cur = parent;
            for s in 1..=slots {
                // Build trivial header with empty roots and beacon v1
                let seed_commit = obex_primitives::h_tag(
                    obex_primitives::constants::TAG_SLOT_SEED,
                    &[&obex_alpha_ii::obex_header_id(&cur), &obex_primitives::le_bytes::<8>(s as u128)],
                );
                let y_core = [3u8; 32];
                let y_edge = obex_primitives::h_tag(obex_primitives::constants::TAG_VDF_EDGE, &[&y_core]);
                let hdr = Header {
                    parent_id: obex_alpha_ii::obex_header_id(&cur),
                    slot: cur.slot + 1,
                    obex_version: OBEX_ALPHA_II_VERSION,
                    seed_commit,
                    vdf_y_core: y_core,
                    vdf_y_edge: y_edge,
                    vdf_pi: vec![],
                    vdf_ell: vec![],
                    ticket_root: obex_primitives::h_tag(obex_primitives::constants::TAG_MERKLE_EMPTY, &[]),
                    part_root: obex_primitives::h_tag(obex_primitives::constants::TAG_MERKLE_EMPTY, &[]),
                    txroot_prev: obex_primitives::h_tag(obex_primitives::constants::TAG_MERKLE_EMPTY, &[]),
                };
                let id0 = obex_alpha_ii::obex_header_id(&hdr);
                // Post to all nodes and fetch back
                for n in &nodes {
                    let b = n.trim_end_matches('/');
                    let dto = serde_json::json!({
                        "parent_id": hdr.parent_id,
                        "slot": hdr.slot,
                        "obex_version": hdr.obex_version,
                        "seed_commit": hdr.seed_commit,
                        "vdf_y_core": hdr.vdf_y_core,
                        "vdf_y_edge": hdr.vdf_y_edge,
                        "vdf_pi": hdr.vdf_pi,
                        "vdf_ell": hdr.vdf_ell,
                        "ticket_root": hdr.ticket_root,
                        "part_root": hdr.part_root,
                        "txroot_prev": hdr.txroot_prev,
                    });
                    client.post(format!("{}/header", b)).json(&dto).send().expect("post header");
                    let got_dto: HeaderDto = client
                        .get(format!("{}/header/{}", b, hdr.slot))
                        .send()
                        .expect("get header")
                        .json::<HeaderDto>()
                        .expect("json dto");
                    let back: Header = got_dto.into();
                    let idn = obex_alpha_ii::obex_header_id(&back);
                    assert_eq!(id0, idn, "HeaderID divergence at slot {} on {}", hdr.slot, b);
                }
                cur = hdr;
            }
            println!("burn-in complete: {} slots, {} nodes, zero divergence", slots, nodes.len());
        }
    }
}
