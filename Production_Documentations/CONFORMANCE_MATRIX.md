Conformance Matrix (Spec → Code → Test)

Purpose
- Ensures every normative rule in the spec is implemented and tested, with exact code anchors.

Legend
- S: Spec section; C: Code function/path; T: Test(s)/goldens.

Examples

S CONSENSUS_SPEC.md/Hashing →
- C `crates/obex_primitives/src/lib.rs::h_tag`, `consensus.rs::h_tag`
- T `crates/obex_primitives/tests/kats.rs` (tag ASCII checks)

S α‑I/Alpha derivation →
- C `crates/obex_alpha_i/src/lib.rs::obex_alpha`
- T `crates/obex_alpha_i/tests/gating.rs`

S α‑I/PartRec codec →
- C `crates/obex_alpha_i/src/lib.rs::encode_partrec/decode_partrec`
- T `crates/obex_alpha_i/tests/golden.rs` (round‑trip)

S α‑II/HeaderID (field‑wise hash, not serialized bytes) →
- C `crates/obex_alpha_ii/src/lib.rs::obex_header_id`
- T `crates/obex_alpha_ii/tests/golden_header.rs`

S α‑III/Access encoding →
- C `crates/obex_alpha_iii/src/lib.rs::encode_access`
- T `crates/obex_alpha_iii/tests/gating.rs`

S α‑T/System tx ordering →
- C `crates/obex_alpha_t/src/lib.rs::canonical_sys_tx_order`
- T `crates/obex_alpha_t/tests/golden.rs`

S α‑II/seed_commit equality →
- C `crates/obex_alpha_ii/src/lib.rs::validate_header`
- T `crates/e2e/tests/equalities.rs::validate_header_with_nonempty_roots`

S α‑II/beacon v1 adapter (pi/ell empty, edge == H(edge,[core])) →
- C `crates/obex_alpha_ii/src/lib.rs::validate_header`
- T `crates/obex_alpha_ii/tests/negatives.rs::{beacon_v1_edge_mismatch_rejected, beacon_v1_nonempty_proofs_rejected}`

S α‑II/ticket_root equality →
- C `crates/obex_alpha_ii/src/lib.rs::validate_header`
- T `crates/e2e/tests/equalities.rs::validate_header_with_nonempty_roots`

S α‑II/part_root equality →
- C `crates/obex_alpha_ii/src/lib.rs::validate_header`
- T `crates/e2e/tests/equalities.rs::validate_header_with_nonempty_roots`

S α‑II/txroot_prev equality →
- C `crates/obex_alpha_ii/src/lib.rs::validate_header`
- T `crates/e2e/tests/equalities.rs::validate_header_with_nonempty_roots`

S α‑III/Fee rule edges →
- C `crates/obex_alpha_iii/src/lib.rs::fee_int`
- T `crates/obex_alpha_iii/tests/admission.rs::fee_rule_edges`

S α‑III/Ticket leaf size (enc_ticket_leaf == 216 bytes) →
- C `crates/obex_alpha_iii/src/lib.rs::enc_ticket_leaf`
- T `crates/obex_alpha_iii/tests/admission.rs::ticket_leaf_length_is_216_bytes`

S α‑T/Emission terminal flush →
- C `crates/obex_alpha_t/src/lib.rs::on_slot_emission`
- T `crates/obex_alpha_t/tests/tokenomics.rs::emission_monotone_and_terminal_flush`

S DoS caps (α‑I size, α‑II VDF size caps) →
- C `crates/obex_alpha_i/src/lib.rs::MAX_PARTREC_SIZE`, `crates/obex_alpha_ii/src/lib.rs::{MAX_PI_LEN, MAX_ELL_LEN}`
- T `crates/obex_alpha_i/tests/fuzz_decode.rs`, `crates/obex_alpha_ii/tests/negatives.rs`


