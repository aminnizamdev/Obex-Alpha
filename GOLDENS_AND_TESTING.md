Golden Vectors & Testing Strategy

Golden Directories
- tests/golden/vdf/: seed_commit.bin (32), y_core.bin (32), y_edge.bin (32), pi.bin (0), ell.bin (0), negatives/*
- tests/golden/alpha_i/: pk.bin, vrf_output.bin (64), vrf_proof.bin (80), root.bin, partrec.bin, P_s.root.bin, negatives/*
- tests/golden/alpha_iii/: ticket_leaves.bin (concat), ticket_root.bin, fee_edges.json, negatives/*
- tests/golden/header/: header.bin (serialized), header_id.bin, negatives/*

Rules
- Goldens are authoritative; tests recompute and compare byte‑for‑byte.
- Negatives mutate exactly one field; tests assert rejection (for beacon v1 include y_edge ≠ H(obex.vdf.edge, [y_core]) and non‑zero pi/ell).

Unit Tests
- Hashing/tagging, Merkle empty/duplicate‑last, α‑I indices/label equations, α‑III fee edges, α‑T invariants.

Fuzzing (manual/nightly)
- registration_decode, registration_verify; add header_decode, tx_decode, vdf_transcript.

E2E 3‑slot Pipeline
- Build/validate chain over slots s−1, s, s+1 with fixed inputs; assert exactly one valid header per (parent,s).

Performance Gates
- vdf_verify ≤ 10 ms; α‑I verify (Q=96) ≤ 60–70 ms; ticket_root ≤ 20 ms; header_validate ≤ 100 ms (reference box).


