OBEX Alpha — Public Testnet Plan (Byte‑Precise, Production‑Grade)

Status: Draft for implementation; aligned to current α‑I/II/III/T crates. This plan does not change any existing files; it specifies exactly what to freeze, implement, and verify to reach a world‑class public testnet.

Table of Contents
- Scope and Principles
- Consensus Discipline (Hashing, Tags, Endianness)
- One Source of Truth (Constants and Versions)
- α‑I Participation (VRF + RAM‑Hard + Merkle)
- α‑II Header (Deterministic Equalities + VDF Adapter)
- VDF Backend Freeze (Wesolowski) — Transcript, Sizes, KATs
- α‑III Admission (Tx Canonical Bytes, Fees, Tickets, Root)
- α‑T Tokenomics (Emission, NLB Fee Splits, DRP, SysTx Order)
- Networking & Availability Policy (Header‑First + Fetch)
- Golden Vectors (Format and Coverage)
- Testing Strategy (Unit, Fuzz, E2E, Golden, Perf Gates)
- Observability (Metrics, Logs, Reject Codes)
- Genesis & Packaging (Configs, Binaries, Devnet → Public Testnet)
- Solo Developer Workflow (No CI)
- Execution Roadmap (Tasks and Milestones)
- Appendices (Tag Registry, Sizes, Byte Layouts)

—

Scope and Principles
- Objective: Launch a deterministic, equality‑validated, VRF‑based public testnet, with frozen hashing/tagging rules, reproducible byte encodings, and comprehensive golden vectors.
- Non‑goals: Smart contract layer, permanent storage engine selection, P2P opcodes beyond minimum viable header‑first gossip.
- Guidance: Favor current α‑I/II/III/T code as normative; reconcile docs to code where divergences exist.

—

Consensus Discipline (Hashing, Tags, Endianness)
- Hash function: SHA3‑256 only in consensus paths.
- Domain separation: Every consensus hash uses a stable ASCII tag in the `obex.*` namespace.
- Length framing: H(tag, parts[]) = SHA3‑256( UTF8(tag) || Σ ( LE(|p|,8) || p ) ).
- Endianness: Keep existing little‑endian fixed‑width integer encodings throughout (u32/u64/u128 as implemented in α‑crates and primitives). Length fields used by serializers are u32 LE.
- Zero unsafe: `#![forbid(unsafe_code)]`, reject on warnings.

—

One Source of Truth (Constants and Versions)
Authoritative definitions live in `crates/obex_primitives`:
- Tag registry: see Appendix A.
- Version constants (as of code today):
  - OBEX_ALPHA_I_VERSION = 1 (u32)
  - OBEX_ALPHA_II_VERSION = 2 (u32)
  - OBEX_ALPHA_III_VERSION = 1 (u32)
  - OBEX_ALPHA_T_VERSION = 1 (u32)
- α‑I parameters (as implemented):
  - MEM_MIB = 512
  - LABEL_BYTES = 32
  - N_LABELS = (MEM_MIB · 1,048,576) / 32 = 16,777,216 (2^24)
  - PASSES = 3
  - CHALLENGES_Q = 96
  - MAX_PARTREC_SIZE = 600,000 bytes
- α‑II caps (as implemented):
  - MAX_PI_LEN = 1,048,576 (example cap)
  - MAX_ELL_LEN = 65,536 (example cap)
- α‑III fees (as implemented):
  - MIN_TX_UOBX = 10 (μOBX)
  - FLAT_SWITCH_UOBX = 1,000 (μOBX)
  - FLAT_FEE_UOBX = 10 (μOBX)
  - Percent branch = ceil(1%)

Action: Consolidate these into a single module re‑exported by each α‑crate (no code changes are required to adopt this plan; consolidation occurs when we implement).

—

α‑I Participation (VRF + RAM‑Hard + Merkle)
VRF
- Suite: RFC 9381 ECVRF‑EDWARDS25519‑SHA512‑TAI.
- Encodings: pk = 32 bytes, proof π = 80 bytes, output β/y = 64 bytes.
- Alpha derivation (exact as code):
  - alpha32 = H("obex.alpha", [ parent_id(32), LE(slot,8), y_edge_prev(32), vrf_pk(32) ]).
- Verifier adapter: returns Option<[u8;64]>; reject on any parse/verification failure.

Seed and Labeling
- seed = H("obex.seed", [ y_edge_prev(32), pk_ed25519(32), vrf_y(64) ]).
- Label update (per pass):
  - lbl_i = H("obex.lbl", [ seed(32), LE(i,8), l_{i-1}(32), l_j(32), l_k(32) ]).
- Index derivations (deterministic within pass):
  - j = idx_j(seed, i, pass) via H("obex.idx", [ seed, LE(i,8), LE(pass,4), [0x00] ]).
  - k = idx_k(seed, i, pass) via H("obex.idx", [ seed, LE(i,8), LE(pass,4), [0x01] ]).
  - Challenge index per t: i_t = 1 + (LE64(H("obex.chal", [ y_edge_prev, root, vrf_y, LE(t,4) ])[..8]) mod (N_LABELS − 1)).

Merkle
- Binary tree, duplicate‑last when odd; empty root = H("obex.merkle.empty", []).
- Leaf hash = H("obex.merkle.leaf", [ label ]) (label is 32 bytes).
- Node hash = H("obex.merkle.node", [ left(32) || right(32) ]).
- Verification walks siblings from leaf up; constant‑time equality for roots.

Participation Record (ObexPartRec)
- Fields (current canonical codec; sizes are exact, LE for integers):
  - version: u32 LE (= OBEX_ALPHA_I_VERSION)
  - slot: u64 LE
  - pk_ed25519: [u8;32]
  - vrf_pk: [u8;32]
  - y_edge_prev: [u8;32]
  - alpha: [u8;32]
  - vrf_y: [u8;64]
  - vrf_pi: [u8;80]
  - seed: [u8;32]
  - root: [u8;32]
  - challenges: u32 LE count (= 96), then 96 × ChallengeOpen
  - sig: [u8;64] (Ed25519 over transcript H("obex.partrec", [...]))
- ChallengeOpen (current layout):
  - idx: u64 LE
  - li: [u8;32], pi_siblings: u32 LE len + siblings×32
  - lim1: [u8;32], pim1_siblings: u32 LE len + siblings×32
  - lj: [u8;32], pj_siblings: u32 LE len + siblings×32
  - lk: [u8;32], pk_siblings: u32 LE len + siblings×32
- DoS cap: total bytes ≤ 600,000. Enforce before decode/crypto.

Verification (exact equalities)
1) Version/slot/challenges count match.
2) alpha == H("obex.alpha", ...).
3) VRF verifies and vrf_y matches consensus form.
4) seed == H("obex.seed", ...).
5) Ed25519 signature over transcript is valid (verify_strict).
6) For each challenge: indices in range; Merkle verifications for i, i−1, j, k succeed; label equation holds.

Participation Root P_s
- Build from unique ed25519 pk set for slot s; sort ascending; leaves = H("obex.part.leaf", []) || pk; root = Merkle(leaves).

—

α‑II Header (Deterministic Equalities + VDF Adapter)
Canonical header struct (as implemented)
- parent_id: [u8;32]
- slot: u64 LE
- obex_version: u32 LE (= OBEX_ALPHA_II_VERSION)
- seed_commit: [u8;32] where seed_commit == H("obex.slot.seed", [ parent_id, LE(slot,8) ])
- vdf_y_core: [u8;32] (placeholder size; final size depends on VDF backend)
- vdf_y_edge: [u8;32]
- vdf_pi: Vec<u8> with u32 LE length
- vdf_ell: Vec<u8> with u32 LE length
- ticket_root: [u8;32]
- part_root: [u8;32]
- txroot_prev: [u8;32]

Header ID (current)
- obex_header_id(h) = H("obex.header.id", [ field‑wise values with explicit lengths ])

Validation (must all hold)
1) Parent link: h.parent_id == obex_header_id(parent).
2) Slot: h.slot == parent.slot + 1.
3) Version: h.obex_version == OBEX_ALPHA_II_VERSION.
4) Size caps: |vdf_pi| ≤ MAX_PI_LEN; |vdf_ell| ≤ MAX_ELL_LEN.
5) seed_commit equality: computed from (parent_id, slot) as above.
6) Beacon verification (adapter): verify(inputs) == true.
7) ticket_root equality: equals locally recomputed ticket_root for slot s.
8) part_root equality: equals locally recomputed part_root for slot s.
9) txroot_prev equality: equals local txroot for slot s−1.

—

 Beacon v1 (Hash‑Edge) — Frozen for Testnet
 Goal: Use a zero‑overhead beacon adapter for testnet: y_edge = H("obex.vdf.edge", [ y_core ]), with empty pi/ell.

 Transcript and Encodings (normative for testnet)
 - y_core: 32 bytes (Hash256) supplied by beacon provider.
 - y_edge: 32 bytes where y_edge == H("obex.vdf.edge", [ y_core ]).
 - pi: empty (0 bytes). ell: empty (0 bytes).

Time Parameter T (calibration)
- Provide a small CLI (obex‑vdf‑cal) to measure a reference machine; set T conservatively; commit value and vectors.

 Verifier contract (single function)
 ```
 bool beacon_v1_verify(
   y_core: &[u8;32],
   y_edge: &[u8;32],
   pi: &[u8],  // MUST be empty
   ell: &[u8], // MUST be empty
 )
 ```
 - Steps: (1) assert pi.len()==0 and ell.len()==0; (2) check y_edge == H("obex.vdf.edge", [ y_core ]).

 Golden vectors (Beacon v1)
 - Files: seed_commit.bin (32), y_core.bin (32), y_edge.bin (32), pi.bin (0), ell.bin (0), plus negatives (y_edge mismatch; non‑empty pi/ell).

—

α‑III Admission (Tx Canonical Bytes, Fees, Tickets, Root)
Tx Body V1 (as implemented)
- Canonical bytes = H("obex.tx.body.v1", []) || sender(32) || recipient(32) || LE(nonce,8) || LE(amount_u,16) || LE(fee_u,16) || LE(s_bind,8) || y_bind(32) || encode_access(access) || LE(memo_len,4) || memo.
- TxID = H("obex.tx.id", [ canonical_tx_bytes ]).
- TxCommit = H("obex.tx.commit", [ canonical_tx_bytes ]).
- Signature message = H("obex.tx.sig", [ canonical_tx_bytes ]); verify_strict.

Fee Rule (as implemented)
- If amount_u ≤ 1,000 → fee = 10; else fee = ceil(amount_u / 100). All integers are u128; avoid overflow by saturating ops where relevant.

TicketRecord (as implemented)
- Fields: ticket_id(32), txid(32), sender(32), nonce(u64 LE), amount_u(u128 LE), fee_u(u128 LE), s_admit(u64 LE), s_exec(u64 LE), commit_hash(32).
- Leaf encoding: H("obex.ticket.leaf", []) || all fields in canonical order; ticket_root = Merkle over encoded leaves, sorted by txid.

Admission Process
1) Verify signature, slot binding (s_bind == s_now), beacon binding (y_bind == y_prev), nonce match, min amount, fee rule, and sufficient funds.
2) Update state maps: spendable, reserved, next_nonce, admitted_by_slot, tickets_by_txid.
3) Build per‑slot ticket_root deterministically.

—

α‑T Tokenomics (Emission, NLB Fee Splits, DRP, SysTx Order)
Emission
- Accumulator method with halving; terminal slot residual flush to guarantee total supply reached exactly.
- Constants and arithmetic match current α‑T implementation (U256 accumulators where needed).

Fee Splits (NLB)
- Epoch snapshots keyed by slot/epoch length; fee escrow accounting; release proportional splits subject to escrow cap; burn accounted into effective supply.

DRP Distribution
- Baseline + lottery K winners, unique indices derived from beacon; reward_rank ordering for deterministic payout ordering; burn remainders.

System Tx Canonical Order
- Order: ESCROW_CREDIT → EMISSION_CREDIT → VERIFIER_CREDIT → TREASURY_CREDIT → BURN → REWARD_PAYOUT (reward payouts sorted by reward_rank).

—

Networking & Availability Policy (Header‑First + Fetch)
Principles
- Header‑first validation; fetch bodies/proofs on demand to recompute roots locally; do not trust remote roots.

Endpoints (minimum viable)
- GET /alpha_i/{slot}/{pk} → canonical `ObexPartRec` bytes (enforce ≤ MAX_PARTREC_SIZE). One per pk per peer per slot.
- GET /alpha_iii/{slot} → concatenated canonical `TicketRecord` bytes for slot s.
- Optional: GET /tx/{id} → canonical tx bytes used in admission for audit.

DoS Controls
- Rate‑limit re‑requests; cap outstanding fetches per slot; enforce size caps before decode.

—

Golden Vectors (Format and Coverage)
Directory: tests/golden/
- vdf/: delta_bits.hex, g.bin, T.bin (LE8), seed_commit.bin, y_core.bin, y_edge.bin, ell.bin, pi.bin, negatives/*.
- alpha_i/: pk.bin, vrf_output.bin, vrf_proof.bin, root.bin, partrec.bin, P_s.root.bin, negatives/*.
- alpha_iii/: ticket_leaves.bin (concat), ticket_root.bin, fee_edges.json, negatives/*.
- header/: header.bin (serialized), header_id.bin, negatives/*.

Rules
- All goldens are exact; tests recompute and assert byte‑for‑byte equality; negatives must fail.

—

Testing Strategy (Unit, Fuzz, E2E, Golden, Perf Gates)
Unit tests
- Cover hashing/tagging, Merkle edge cases (empty, duplicate‑last), α‑I indices/label equations, α‑III fee edges, α‑T arithmetic invariants, header build/validate round‑trip.

Fuzzing (nightly/manual)
- Decode paths: partrec, header, tx; Merkle verification; VDF transcript parse. Reject oversize early; must not panic.

E2E 3‑slot Pipeline
- Parent slot s−1: fixed txroot_{s−1} from golden.
- Slot s: build P_s from fixed partrecs; build tickets from fixed tx set; compute roots; construct header; validate.
- Slot s+1: repeat with different seeds; assert single valid header per (parent,s).

Performance Gates (reference box)
- vdf_verify ≤ 10 ms
- α‑I verify (Q=96) ≤ 60–70 ms
- ticket_root build ≤ 20 ms
- header_validate (end‑to‑end) ≤ 100 ms
- Hard floor for low‑end CPUs ≤ 2× reference (documented separately)

—

Observability (Metrics, Logs, Reject Codes)
Metrics (OpenMetrics)
- headers_validated_total, headers_rejected_total{reason}
- vdf_verify_ms_histogram, alpha_i_verify_ms_histogram, ticket_root_ms_histogram
- fetch_failures_total{endpoint,reason}

Logs (structured JSON)
- INFO default; include header_id, slot, parent_id, and reject reason code.

Reject Codes (stable enums)
- HeaderReject: VersionMismatch, BadParentLink, BadSlot, VdfPiTooBig, VdfEllTooBig, BadSeedCommit, BeaconInvalid, TicketRootMismatch, PartRootMismatch, TxRootPrevMismatch.
- AlphaIReject: VersionMismatch, SlotMismatch, ChallengesLen, AlphaMismatch, VrfVerifyFailed, VrfOutputMismatch, SeedMismatch, SigInvalid, ChalIndexMismatch, ChalIndexBounds, JOrKOutOfRange, MerkleLiInvalid, MerkleLim1Invalid, MerkleLjInvalid, MerkleLkInvalid, LabelEquationMismatch, Oversize.

—

Genesis & Packaging (Configs, Binaries, Devnet → Public Testnet)
Genesis (TOML)
- network_id, genesis_header_id, OBEX_ALPHA_*_VERSION, VDF params (Δ bits, g.bin base64, T LE8), fee constants.

Node binary (obex‑node)
- Header‑first validator with minimal HTTP server for fetch endpoints; persistent store for headers and slot artifacts; slot scheduler.

Tooling (obex‑tool)
- Encode/decode inspectors; golden generator; vector verifier; KAT dump.

Devnet → Public testnet
- Spin 5 nodes (3 ref hardware, 2 low‑end); run 10k slots with zero divergence; publish peers/telemetry.

—

Solo Developer Workflow (No CI)
Run before tagging or regenerating goldens (PowerShell example):
```
cargo fmt --all; \
cargo clippy --all-targets --all-features -D warnings; \
cargo build --locked; \
cargo test --workspace --all-features; \
cargo test -p e2e -- --ignored golden
```
Optional nightly fuzz:
```
cargo fuzz run registration_decode -- -runs=100000
cargo fuzz run registration_verify -- -runs=100000
```

—

Execution Roadmap (Tasks and Milestones)
Milestone 1 — Consensus Freeze & Spec Alignment
- Consolidate constants/tags into a single module; update docs to match code (LE encodings, tag strings, versions).
- Audit for any stray non‑`obex.*` tags and correct.

Milestone 2 — VDF Backend Freeze
- Implement verifier adapter (Wesolowski) with fixed sizes and transcript; calibrate T on reference box; commit vectors and parameters.

Milestone 3 — Golden Vectors & E2E Pipeline
- Generate full golden set (α‑I, α‑III, header, VDF); implement 3‑slot pipeline test; negative vectors.

Milestone 4 — Node + Networking
- Implement `obex‑node` with header‑first flow, fetch endpoints, storage, scheduler, metrics/logs.

Milestone 5 — Performance & Burn‑In
- Add benches with gates; run 10k‑slot burn‑in on 5‑node devnet; resolve regressions.

Milestone 6 — Public Testnet Packaging
- Produce static binaries (x86_64, aarch64) + SHA256; publish `genesis.toml`, peers; open telemetry dashboard; tag release.

—

Appendix A — Tag Registry (must match code)
- obex.merkle.leaf
- obex.merkle.node
- obex.merkle.empty
- obex.alpha
- obex.part.leaf
- obex.partrec
- obex.seed
- obex.l0
- obex.lbl
- obex.idx
- obex.chal
- obex.vrfy
- obex.header.id
- obex.slot.seed
- obex.vdf.ycore
- obex.vdf.edge
- obex.tx.access
- obex.tx.body.v1
- obex.tx.id
- obex.tx.commit
- obex.tx.sig
- obex.txid.leaf
- obex.ticket.id
- obex.ticket.leaf
- obex.sys.tx
- obex.reward.draw
- obex.reward.rank

Appendix B — Sizes and Encodings (selected)
- Hash256 = [u8;32] (SHA3‑256).
- Integers on wire: little‑endian; widths per field (u32/u64/u128); variable byte vectors prefixed by u32 LE length.
- VRF: pk 32, π 80, y 64.
- α‑I DoS cap: partrec bytes ≤ 600,000.
- α‑II caps: |pi| ≤ 1,048,576; |ell| ≤ 65,536 (until VDF sizes frozen).
- Ticket leaf: domain tag (32) + concatenated fields per α‑III `enc_ticket_leaf`.

Appendix C — Example Equality Checks (pseudocode)
```
assert h.parent_id == obex_header_id(parent)
assert h.slot == parent.slot + 1
assert h.obex_version == OBEX_ALPHA_II_VERSION
assert len(h.vdf_pi) <= MAX_PI_LEN
assert len(h.vdf_ell) <= MAX_ELL_LEN
assert h.seed_commit == H("obex.slot.seed", [h.parent_id, LE(h.slot,8)])
assert beacon.verify(h) == true
assert h.ticket_root == provider.ticket_root(h.slot)
assert h.part_root == provider.part_root(h.slot)
assert h.txroot_prev == provider.txroot(parent.slot)
```

—

Notes
- This plan intentionally mirrors the current α‑crates’ behavior to minimize risk and time‑to‑testnet. Where prior documents differ (endianness, header ID definition, path lengths), the code is treated as normative for testnet. Any deliberate change must regenerate goldens and bump the corresponding α‑version.


