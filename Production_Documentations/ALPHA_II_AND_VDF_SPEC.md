α‑II — Header & Beacon (VDF) Specification

Header Object
- Fields:
  - parent_id: [u8;32]
  - slot: u64 LE
  - obex_version: u32 LE (= OBEX_ALPHA_II_VERSION)
  - seed_commit: [u8;32] where seed_commit == H("obex.slot.seed", [ parent_id, LE(slot,8) ])
  - vdf_y_core: [u8;32] (Hash256 per current implementation)
  - vdf_y_edge: [u8;32] (Hash256 per current implementation)
  - vdf_pi: bytes with u32 LE length prefix (cap MAX_PI_LEN)
  - vdf_ell: bytes with u32 LE length prefix (cap MAX_ELL_LEN)
  - ticket_root: [u8;32]
  - part_root: [u8;32]
  - txroot_prev: [u8;32]

Header Identity
- HeaderID = H("obex.header.id", [
  parent_id,
  LE(slot,8),
  LE(obex_version,4),
  seed_commit,
  vdf_y_core,
  vdf_y_edge,
  LE(|vdf_pi|,4), vdf_pi,
  LE(|vdf_ell|,4), vdf_ell,
  ticket_root,
  part_root,
  txroot_prev
]).

Build Header (s = parent.slot + 1)
- Inputs: seed_commit, y_core, y_edge, pi, ell; providers for ticket_root(s), part_root(s), txroot(s−1).
- Set parent_id = HeaderID(parent).

Validation (must pass all)
1) parent_id equality; 2) slot == parent.slot + 1; 3) version match.
4) size caps for vdf_pi, vdf_ell.
5) seed_commit recompute and equality.
6) Beacon verify(inputs) == true.
7) ticket_root(participation/admission) equalities; 8) txroot_prev equality.

Beacon v1 — Hash‑Edge Adapter (frozen for testnet)
Definition (normative)
- Sizes: `vdf_y_core` and `vdf_y_edge` are 32 bytes (Hash256). `vdf_pi` length MUST be 0. `vdf_ell` length MUST be 0.
- Equality: `vdf_y_edge == H("obex.vdf.edge", [ vdf_y_core ])`.

Validation additions
- Enforce `vdf_pi.len() == 0` and `vdf_ell.len() == 0`.
- Enforce the hash‑edge equality above.

Future VDF
- A class‑group Wesolowski backend can be added in a future network version bump with new goldens. That change will require explicit versioning and coordinated rollout; it is out of scope for testnet v1.

Verifier Contract
```
fn vdf_verify(
  seed_commit: &[u8;32],
  T_le: [u8;8],
  y_core: &[u8],
  y_edge: &[u8],
  pi: &[u8],
  ell: &[u8],
) -> bool
```
- Steps: size checks → transcript → ell → Wesolowski multi‑exp check → boolean.

Calibration & KATs
- Calibrate T on a reference machine; set conservative T; publish vectors: (seed_commit, T, g, y_core, y_edge, pi, ell) with negatives (corrupted size/ell/T/edge).


