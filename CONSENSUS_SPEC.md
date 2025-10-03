OBEX Alpha — Consensus Specification (Normative)

Scope
- This document freezes consensus rules for hashing, domain tags, encodings, endianness, and Merkle behavior. All α‑I/II/III/T engines must conform byte‑for‑byte.

Hashing Discipline
- Hash function: SHA3‑256 with 32‑byte output.
- Domain separation: every consensus hash uses an ASCII tag in the `obex.*` namespace.
- Length framing: H(tag, parts[]) = SHA3_256( UTF8(tag) || Σ ( LE(|p|,8) || p ) ).
- Constant‑time equality: 32‑byte digests compared with constant‑time equality.

Endianness & Integer Widths
- All on‑wire integers are little‑endian (LE).
- Widths: u32 (4 bytes), u64 (8 bytes), u128 (16 bytes). Length prefixes for variable bytes are u32 LE.

Tag Registry (must match code)
- obex.merkle.leaf, obex.merkle.node, obex.merkle.empty
- obex.alpha, obex.part.leaf, obex.partrec, obex.seed, obex.l0, obex.lbl, obex.idx, obex.chal, obex.vrfy
- obex.header.id, obex.slot.seed, obex.vdf.ycore, obex.vdf.edge
- obex.tx.access, obex.tx.body.v1, obex.tx.id, obex.tx.commit, obex.tx.sig, obex.txid.leaf
- obex.ticket.id, obex.ticket.leaf
- obex.sys.tx, obex.reward.draw, obex.reward.rank

Merkle Rules
- Binary tree; when a level has odd length, duplicate the last node.
- Empty root = H("obex.merkle.empty", []).
- Leaf = H("obex.merkle.leaf", [ payload ]), where payload is the canonical leaf bytes (32‑byte label for α‑I; tagged ticket leaf bytes for α‑III).
- Node = H("obex.merkle.node", [ left(32) || right(32) ]).
- Authentication path: siblings from leaf to root; recomputation places the current hash left or right by leaf index parity per level.

Header Identity (α‑II)
- HeaderID = H("obex.header.id", [ field‑wise values and lengths as defined in α‑II spec ]). The ID is a hash of field values, not of serialization bytes.

Reject Semantics
- Fail‑closed: any mismatch or size violation rejects the object.
- Enforce size caps before any cryptographic verification.

Versions (as implemented)
- OBEX_ALPHA_I_VERSION = 1 (u32)
- OBEX_ALPHA_II_VERSION = 2 (u32)
- OBEX_ALPHA_III_VERSION = 1 (u32)
- OBEX_ALPHA_T_VERSION = 1 (u32)

DoS Bounds (global)
- Enforce α‑I record size ≤ 600,000 bytes prior to decode.
- Enforce α‑II `vdf_pi` ≤ MAX_PI_LEN, `vdf_ell` ≤ MAX_ELL_LEN prior to beacon verification.
- Enforce header serialized bytes ≤ implementation cap (≤ 4 KiB recommended).


