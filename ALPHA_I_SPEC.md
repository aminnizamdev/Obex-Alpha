α‑I — Participation Engine Specification

Overview
- Provides VRF‑salted RAM‑hard verification with Q=96 challenges and a canonical participation record (ObexPartRec). Produces the participation set P_s and commitment part_root_s.

Parameters (as implemented)
- MEM_MIB = 512, LABEL_BYTES = 32, N_LABELS = 16,777,216 (2^24), PASSES = 3, CHALLENGES_Q = 96.
- MAX_PARTREC_SIZE = 600,000 bytes (pre‑crypto cap).

VRF
- Suite: RFC 9381 ECVRF‑EDWARDS25519‑SHA512‑TAI.
- Encodings: pk 32, proof π 80, output y 64 bytes.
- Alpha (32 bytes): alpha32 = H("obex.alpha", [ parent_id(32), LE(slot,8), y_edge_prev(32), vrf_pk(32) ]).
- Verifier interface returns Option<[u8;64]>; None on any failure.

Seed & Labeling
- seed = H("obex.seed", [ y_edge_prev, pk_ed25519, vrf_y ]).
- idx_j = f(seed,i,p,0x00); idx_k = f(seed,i,p,0x01) via tag "obex.idx" with LE(i,8), LE(p,4), and a domain byte.
- lbl_i = H("obex.lbl", [ seed, LE(i,8), l_{i-1}, l_j, l_k ]).

Challenge Index
- i_t = 1 + ( LE64( H("obex.chal", [ y_edge_prev, root, vrf_y, LE(t,4) ])[..8] ) mod (N_LABELS − 1) ).

Merkle
- Root over 32‑byte labels with duplicate‑last; empty = H("obex.merkle.empty", []).
- Leaf = H("obex.merkle.leaf", [ label ]). Node = H("obex.merkle.node", [ L||R ]).
- Verify leaf at index using siblings list and index parity per level.

Canonical Participation Record (ObexPartRec)
- Encoding (all integers LE; order exact):
  1) version: u32
  2) slot: u64
  3) pk_ed25519: [u8;32]
  4) vrf_pk: [u8;32]
  5) y_edge_prev: [u8;32]
  6) alpha: [u8;32]
  7) vrf_y: [u8;64]
  8) vrf_pi: [u8;80]
  9) seed: [u8;32]
 10) root: [u8;32]
 11) challenges_count: u32 (=96)
 12) for each of 96 challenges (ChallengeOpen):
     - idx: u64
     - li: [u8;32]; pi_siblings_len: u32; siblings: 32×len
     - lim1: [u8;32]; pim1_len: u32; siblings: 32×len
     - lj: [u8;32]; pj_len: u32; siblings: 32×len
     - lk: [u8;32]; pk_len: u32; siblings: 32×len
 13) sig: [u8;64] (Ed25519 verify_strict over transcript)

Transcript for Signature
- msg = H("obex.partrec", [ LE(version,4), pk_ed25519(32), vrf_pk(32), LE(slot,8), y_edge_prev(32), alpha(32), vrf_y(64), root(32) ]).

Verification Steps
1) Bounds: size ≤ MAX_PARTREC_SIZE; version, slot, challenges count.
2) alpha recompute; VRF verify → y check; seed recompute.
3) Signature verify_strict over transcript.
4) For each challenge: range checks; Merkle verify li at i, lim1 at i−1, lj at j, lk at k; label equation l_i = lbl(seed,i,l_{i−1},l_j,l_k).

Participation Set & Root
- Deduplicate pk_ed25519 across valid records for slot s; sort ascending.
- Leaf bytes for set: H("obex.part.leaf", []) || pk; root = Merkle over leaves.

Reject Reasons (stable)
- VersionMismatch, SlotMismatch, ChallengesLen, AlphaMismatch, VrfVerifyFailed, VrfOutputMismatch, SeedMismatch, SigInvalid, ChalIndexMismatch, ChalIndexBounds, JOrKOutOfRange, MerkleLiInvalid, MerkleLim1Invalid, MerkleLjInvalid, MerkleLkInvalid, LabelEquationMismatch, Oversize.

Golden Artifacts (α‑I)
- partrec.bin (full), vrf_output.bin (64), vrf_proof.bin (80), root.bin (32), P_s.root.bin (32), negatives/* (corrupt size/indices/labels/signature).


