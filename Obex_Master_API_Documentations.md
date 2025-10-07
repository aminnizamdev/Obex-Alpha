Obex Master API Documentations

Status: Current implementation (v1)
Audience: Wallet and explorer developers, operators, SDK authors

1. Overview

This document describes all HTTP APIs implemented by the Obex Alpha node, including legacy endpoints and the versioned `/v1` surface intended for wallets and explorers. It reflects the current codebase precisely and avoids assumptions beyond what is implemented.

2. Conventions and Semantics

- Encoding
  - 32‑byte values (hashes, public keys) are rendered as lowercase hex with a `0x` prefix (64 hex chars after `0x`).
  - Large integers (amounts, fees) in JSON are serialized as decimal strings.
  - Slots are 64‑bit unsigned integers.

- Error model (v1)
  - All `/v1` endpoints return a uniform JSON error envelope on non‑2xx:
    - `{ code: number, error: string, message: string, details: object }` with an appropriate HTTP status.

- Pagination (v1)
  - Range endpoints use `?limit=` (default 100, max 500) and `?cursor=` (base64‑encoded opaque token) to page result sets deterministically.

- Caching (v1)
  - Read endpoints use `ETag` and `Cache-Control: public, max-age=5`. If `If-None-Match` matches the current ETag, `304 Not Modified` is returned.

- Streaming
  - `/v1/subscribe` uses Server‑Sent Events (SSE) and is not cacheable.

3. Legacy Endpoints (compatibility)

- `GET /alpha_i/{slot}/{pk}`
  - Returns raw canonical α‑I `ObexPartRec` bytes for the given slot and participant PK (Ed25519, 32 bytes).
  - Content is binary; size cap enforced in the node.

- `GET /alpha_iii/{slot}`
  - Returns concatenated α‑III `TicketRecord` leaves (each 216 bytes) for the slot.
  - Content is binary; leaves are concatenated without separators.

- `GET /header/{slot}`
  - Returns a header DTO for the slot.

- `POST /header`
  - Submits a header DTO; the node validates parent link, slot increment, version, seed_commit, beacon v1 constraints, and all root equalities.

- `POST /advance`
  - Deterministically builds the next header from the local store and persists it.

- `GET /metrics`
  - OpenMetrics text with counts and average latencies for validation/fetch/build.

- `GET /healthz`
  - Readiness: 200 OK when genesis is present and the node is operational.

4. Versioned API (`/v1`)

4.1 Chain and Headers

- `GET /v1/info`
  - Response: `{ chain_id, genesis_hash, obex_version, slots_per_sec, head?: { slot, header_id }, address_format: "ed25519-hex" }`
  - ETag/Cache‑Control enabled.

- `GET /v1/head`
  - Response: `{ slot, header_id }` (current head). ETag/Cache‑Control enabled.

- `GET /v1/headers?from=&to=&limit=&cursor=`
  - Returns `{ items: Header[], next_cursor?: string }` where `Header` includes hex fields for roots and derived `header_id`.
  - `cursor` is a base64 string; `limit` ≤ 500. ETag/Cache‑Control enabled.

- `GET /v1/slot/{slot}`
  - Returns `{ slot, header: Header, counts: { tickets, participants } }`.
  - ETag/Cache‑Control enabled.

4.2 Tickets (α‑III)

- `GET /v1/alpha_iii/{slot}?limit=&cursor=`
  - Returns `{ slot, items: Ticket[], next_cursor?: string }`.
  - Ticket view fields (from 216‑byte leaf):
    - `{ ticket_id, txid, sender, nonce, amount_u, fee_u, s_admit, s_exec, commit_hash }` (hex strings for 32‑byte fields).
  - ETag/Cache‑Control enabled.

- `GET /v1/ticket/{txid}`
  - Resolves a ticket by `txid` → `{ slot, ticket: Ticket, proof: Proof }`.
  - ETag/Cache‑Control enabled.

- `GET /v1/proof/ticket/{slot}/{txid}`
  - Returns ticket inclusion `Proof` for the slot: `{ leaf, siblings: string[], index, root }`.
  - ETag/Cache‑Control enabled.

4.3 Participation (α‑I)

- `GET /v1/alpha_i_index/{slot}`
  - Returns `{ slot, participants: string[], count }` where each participant is a 32‑byte hex PK.
  - ETag/Cache‑Control enabled.

- `GET /v1/proof/participant/{slot}/{pk}`
  - Returns participant inclusion `Proof`: `{ leaf, siblings, index, root }`.
  - ETag/Cache‑Control enabled.

4.4 Wallet Lifecycle

- `GET /v1/account/{pk}`
  - Returns `{ pk, spendable_u, reserved_u, next_nonce }`.
  - Current implementation maintains `next_nonce` from observed tickets; `spendable_u`/`reserved_u` are present but not fully updated by ledger execution.
  - ETag/Cache‑Control enabled.

- `POST /v1/tx`
  - Body: `{ tx_body_v1: { sender, recipient, nonce, amount_u, fee_u, s_bind, y_bind, memo? }, signature }`.
    - `sender`, `recipient`, `y_bind` are 32‑byte hex strings.
    - `nonce`: u64; `amount_u`, `fee_u`: decimal strings.
    - `signature`: 64‑byte Ed25519 signature (hex).
  - Behavior: builds canonical TxBodyV1 bytes, verifies Ed25519 signature over `TAG_TX_SIG || canonical_tx_bytes`. On success returns `{ txid, commit_hash, accepted: true }` and sets tx status `pending`. (Note: execution/balances are not materialized yet.)

- `GET /v1/tx/{txid}`
  - Returns `{ txid, status: "pending"|"admitted"|"rejected"|"unknown", slot? }`.
  - ETag/Cache‑Control enabled.

- `GET /v1/fees`
  - Fee rule disclosure:
    - `{ min_tx_u, flat_switch_u, flat_fee_u, rule: "flat-or-1percent" }`.
  - ETag/Cache‑Control enabled.

4.5 Observability, Peers, Search

- `GET /v1/peers`
  - Returns `{ count, peers: string[] }` (public subset for observability). ETag/Cache‑Control enabled.

- `GET /v1/search?q=`
  - Resolves identifier to one of: `{ type: "slot"|"header"|"tx"|"account", ... }` with associated fields. ETag/Cache‑Control enabled.

- `GET /v1/stats/supply`
  - Returns supply schedule snapshot `{ slots_elapsed, scheduled_emitted_u, total_supply_u, halving_period_years }`.
  - ETag/Cache‑Control enabled.

- `GET /v1/stats/participation?from=&to=`
  - Returns `{ items: [ { slot, count } ... ] }`. ETag/Cache‑Control enabled.

- `GET /v1/stats/fees?from=&to=`
  - Returns `{ items: [ { slot, total_fees_u } ... ] }` (fees currently reported as zero). ETag/Cache‑Control enabled.

- `GET /v1/subscribe`
  - SSE stream of JSON lines: `{"type":"newHead",...}`, `{"type":"ticketAdmitted",...}`.

5. DTOs (selected)

- Header (view):
  - `{ parent_id, slot, obex_version, seed_commit, vdf_y_core, vdf_y_edge, vdf_pi, vdf_ell, ticket_root, part_root, txroot_prev, header_id }`

- Ticket (view):
  - `{ ticket_id, txid, sender, nonce, amount_u, fee_u, s_admit, s_exec, commit_hash }`

- Inclusion `Proof`:
  - `{ leaf, siblings: string[], index, root }`

6. Limitations and Notes

- Account balances are not executed; `next_nonce` is inferred from observed tickets. `spendable_u`/`reserved_u` are placeholders.
- Tx submission verifies signatures and canonical bytes and records status `pending`. Admission to a slot and full ledger updates are outside the current node’s scope.
- Raw (legacy) endpoints return binary payloads without JSON wrapping; consumers must parse formats per the specs.

7. OpenAPI and SDKs

- The OpenAPI 3.1 document `API_OPENAPI_v1.yaml` describes all `/v1` endpoints and DTOs and can be used to generate client SDKs (TypeScript/Rust/Go examples are listed in `README.md`).

8. Versioning and Compatibility

- Legacy endpoints remain for compatibility. New development should target `/v1`.
- Any future breaking changes will be reflected via a new versioned path (e.g., `/v2`).


