OBEX API Plan v2 — Wallets and Explorer (Normative)

Status: Draft v2 (normative for implementation)
Audience: Node/API implementers, SDK authors, wallet and explorer developers
Scope: Public HTTP/WS API for OBEX Alpha testnet (header‑first node)

1. Principles and Versioning
- Goals
  - Provide a stable, minimal, and complete surface for wallets and explorers.
  - Preserve consensus invariants: all data/verifications are reproducible from headers + bodies.
  - Favor deterministic JSON DTOs, explicit encodings, and pagination.
- API Versioning
  - Path prefix: /v1 for new endpoints. Existing legacy endpoints remain without prefix for backwards compatibility during Alpha.
  - Breaking changes increment the major version (/v2, /v3). Non‑breaking changes may add fields with additive semantics.
  - Clients MUST declare Accept: application/json; version=1 or use explicit /v1 prefix.

2. Types and Encodings (Normative)
- Hex
  - All byte arrays are lowercase 0x‑prefixed hex.
  - 32‑byte hashes/public keys: 64 hex chars (plus 0x prefix).
  - 64‑byte signatures: 128 hex chars (plus 0x prefix).
- Integers
  - slot: uint64 (JSON number). If client lacks 64‑bit safety, request strings via query param (?ints=string) [optional].
  - amount_u, fee_u, totals: uint128 represented as decimal strings in JSON (e.g., "1000000").
- DTO Field Naming: snake_case for JSON fields.

3. Error Model (Normative)
- JSON error shape for all non‑2xx responses:
  {
    "code": 1001,
    "error": "header_rejected",
    "message": "Bad parent link",
    "details": { "slot": 42, "reason": "BadParentLink" },
    "request_id": "..."
  }
- HTTP status codes: 400 (bad request), 404 (not found), 409 (conflict), 422 (semantic validation), 429 (rate limit), 500/503.
- Stable numeric codes aligned to node JSON log codes when applicable.

4. Pagination, Caching, Compression (Normative)
- Pagination
  - cursor: opaque string (URL‑safe base64). limit: 1..500 (default 100). Deterministic ordering.
  - Responses include next_cursor when more data exists.
- Caching
  - ETag/If‑None‑Match on all GETs for headers/tickets/participants. Cache‑Control: public, max‑age=5 for slot‑scoped resources.
- Compression
  - Servers SHOULD support gzip and br. Clients SHOULD send Accept‑Encoding.

5. Security, CORS, Limits (Normative)
- CORS
  - GET endpoints: Access‑Control‑Allow‑Origin: *. POST /tx: allow configured origins.
- Rate Limits
  - Semaphores already applied to POST ingests. Public gateways SHOULD enforce IP‑based RPS ceilings on heavy GETs.
- Timeouts
  - Servers SHOULD time‑limit requests; clients SHOULD retry with exponential backoff.

6. Existing Endpoints (Legacy)
- GET /header/{slot}
  - Returns a header DTO (legacy path). New: /v1/header/{slot}.
- POST /header
  - Submit header, validate, and store.
- POST /advance
  - Dev‑only: advance local header using local state.
- GET /alpha_iii/{slot}
  - Concatenated 216‑byte ticket leaves (binary). New JSON form added below.
- POST /alpha_iii/{slot}
  - Ingest concatenated α‑III leaves.
- GET /alpha_i_index/{slot}
  - Participant PK index (legacy form). New JSON form below.
- GET/POST /alpha_i/{slot}/{pk}
  - Fetch/ingest α‑I participation record for a key.
- GET /metrics, GET /healthz

7. New Wallet‑Critical Endpoints (/v1)

7.1 GET /v1/info
- Purpose: Basic chain and node descriptor.
- Response 200 application/json
  {
    "chain_id": "obex-alpha-testnet",
    "genesis_hash": "0x…",
    "obex_version": 2,
    "slots_per_sec": 10,
    "head": { "slot": 12345, "header_id": "0x…" },
    "address_format": "ed25519-hex"
  }

7.2 GET /v1/fees
- Purpose: Fee rule disclosure for client UX.
- Response 200
  {
    "min_tx_u": "10",
    "flat_switch_u": "1000",
    "flat_fee_u": "10",
    "rule": "flat-or-1percent"
  }

7.3 GET /v1/account/{pk}
- Purpose: Wallet account snapshot.
- Response 200
  {
    "pk": "0x…",
    "spendable_u": "100000000",
    "reserved_u": "0",
    "next_nonce": 12,
    "updated_at_slot": 12344
  }
- Notes: Requires node to maintain a minimal balances/nonce view from admitted tickets.

7.4 POST /v1/tx
- Purpose: Submit transaction.
- Request application/json
  {
    "tx_body_v1": {
      "sender": "0x…",
      "recipient": "0x…",
      "nonce": 12,
      "amount_u": "1000000",
      "fee_u": "10000",
      "s_bind": 12345,
      "y_bind": "0x…",
      "access": {
        "read_accounts": ["0x…"],
        "write_accounts": ["0x…"]
      },
      "memo": "0x68656c6c6f"
    },
    "signature": "0x<64-bytes-hex>"
  }
- Response 200
  { "txid": "0x…", "commit_hash": "0x…", "accepted": true }
- Errors: 422 on signature/body canonicalization mismatch, fee rule violations, wrong binds.

7.5 GET /v1/tx/{txid}
- Purpose: Transaction status and proof.
- Response 200
  {
    "status": "pending|admitted|rejected",
    "slot": 12345,
    "ticket": { /* TicketRecord JSON view */ },
    "proof": {
      "slot": 12345,
      "leaf": "0x…",
      "siblings": ["0x…"],
      "index": 17,
      "root": "0x…"
    }
  }
  or 404 if unknown.

7.6 WS/SSE /v1/subscribe
- Purpose: Real‑time updates for wallets.
- Events (JSON lines)
  { "type": "newHead", "slot": 12345, "header_id": "0x…" }
  { "type": "txStatus", "txid": "0x…", "status": "admitted", "slot": 12345 }
  { "type": "accountDelta", "pk": "0x…", "spendable_u": "+1000", "reserved_u": "-1000", "slot": 12345 }

8. New Explorer‑Critical Endpoints (/v1)

8.1 GET /v1/head
- Purpose: Shallow head info for bootstrap.
- Response 200 { "slot": 12345, "header_id": "0x…" }

8.2 GET /v1/headers?from=&to=&cursor=&limit=
- Purpose: Header range with pagination.
- Response 200
  {
    "items": [ { /* header DTO */ } ],
    "next_cursor": "…"
  }

8.3 GET /v1/slot/{slot}
- Purpose: Slot summary.
- Response 200
  {
    "slot": 12345,
    "header": { /* header DTO */ },
    "counts": { "tickets": 1024, "participants": 256 }
  }

8.4 GET /v1/alpha_iii/{slot}
- Purpose: Tickets for a slot, with dual format.
- Query: format=binary|json (default json), cursor, limit
- Response 200 (json)
  {
    "slot": 12345,
    "items": [
      {
        "ticket_id": "0x…",
        "txid": "0x…",
        "sender": "0x…",
        "nonce": 12,
        "amount_u": "1000000",
        "fee_u": "10000",
        "s_admit": 12345,
        "s_exec": 12345,
        "commit_hash": "0x…"
      }
    ],
    "next_cursor": "…"
  }
- Response 200 (binary): identical to legacy endpoint for compatibility.

8.5 GET /v1/ticket/{txid}
- Purpose: Resolve a ticket by txid.
- Response 200 { "slot": 12345, "ticket": {…}, "proof": {…} }

8.6 GET /v1/alpha_i_index/{slot}
- Purpose: Participant list (JSON), with counts.
- Response 200 { "slot": 12345, "participants": ["0x…"], "count": 256 }

8.7 GET /v1/participant/{slot}/{pk}
- Purpose: Retrieve α‑I record summary + proof.
- Response 200
  {
    "slot": 12345,
    "pk": "0x…",
    "record": { /* abbreviated ObexPartRec fields */ },
    "proof": { "siblings": ["0x…"], "index": 7, "root": "0x…" }
  }

8.8 GET /v1/proof/ticket/{slot}/{txid}
- Purpose: Standalone inclusion proof for a ticket leaf.
- Response 200 { "leaf": "0x…", "siblings": ["0x…"], "index": 17, "root": "0x…" }

8.9 GET /v1/proof/participant/{slot}/{pk}
- Purpose: Standalone inclusion proof for participant leaf.
- Response 200 { "leaf": "0x<part_leaf>", "siblings": ["0x…"], "index": 7, "root": "0x…" }

8.10 GET /v1/search?q=
- Purpose: Resolve identifiers (txid|header_id|pk|slot).
- Response 200
  {
    "query": "…",
    "result": { "type": "tx|header|account|slot", … }
  }

8.11 GET /v1/stats/supply
- Purpose: Emission schedule snapshot.
- Response 200
  {
    "slots_elapsed": 1234567,
    "scheduled_emitted_u": "…",
    "total_supply_u": "100000000000000",
    "halving_period_years": 5
  }
- Note: Distribution depends on participation; this endpoint reflects schedule math.

8.12 GET /v1/stats/participation?from=&to=
- Purpose: Per‑slot participation counts.
- Response 200 { "items": [ { "slot": 12340, "count": 128 }, … ] }

8.13 GET /v1/stats/fees?from=&to=
- Purpose: Aggregated fee metrics per slot or interval.
- Response 200 { "items": [ { "slot": 12345, "total_fees_u": "…" } ] }

8.14 GET /v1/peers (public subset)
- Purpose: Observability for explorers.
- Response 200 { "count": 5, "peers": [ { "url": "https://…" } ] }

9. DTO Definitions (Abbreviated)

9.1 Header DTO
{
  "parent_id": "0x…",
  "slot": 12345,
  "obex_version": 2,
  "seed_commit": "0x…",
  "vdf_y_core": "0x…",
  "vdf_y_edge": "0x…",
  "vdf_pi": "",
  "vdf_ell": "",
  "ticket_root": "0x…",
  "part_root": "0x…",
  "txroot_prev": "0x…",
  "header_id": "0x…" // derived
}

9.2 TicketRecord JSON View
{
  "ticket_id": "0x…",
  "txid": "0x…",
  "sender": "0x…",
  "nonce": 12,
  "amount_u": "…",
  "fee_u": "…",
  "s_admit": 12345,
  "s_exec": 12345,
  "commit_hash": "0x…"
}

9.3 Participant Leaf JSON View
{
  "pk": "0x…"
}

9.4 Inclusion Proof DTO
{
  "leaf": "0x…",
  "siblings": ["0x…"],
  "index": 17,
  "root": "0x…"
}

10. Subscriptions (WS/SSE) Details
- Endpoint: /v1/subscribe (SSE) or /v1/ws (WebSocket). SSE recommended for simplicity.
- Event types: newHead, txStatus, ticketAdmitted, accountDelta.
- Keep‑alive: server sends comment ping every 15s.

11. Admin/Operator Endpoints (Optional, Auth‑Gated)
- GET /v1/peers (full), POST /v1/peers, DELETE /v1/peers/{id}
- POST /v1/snapshot, POST /v1/prune, GET /v1/db/stats
- Access control: token‑based or local‑only by default.

12. Observability
- Metrics: expose per‑endpoint latency histograms, per‑peer labels for puller. Unit tests MUST ensure metric name stability.
- Logs: continue structured JSON with stable codes and include request_id (echo back to clients).

13. OpenAPI and SDKs
- Provide an OpenAPI 3.1 spec for all /v1 endpoints with component schemas for DTOs.
- Auto‑generate TypeScript and Rust SDKs from the spec; publish examples for wallet/explorer bootstrap.

14. Backwards Compatibility Plan
- Maintain legacy endpoints until /v1 is broadly adopted. Mark legacy as deprecated in server headers: Deprecation: true; Sunset: <date>.
- Introduce /v1 gradually; ensure both binary and JSON ticket endpoints coexist for one release.

15. Examples

15.1 GET /v1/info
200 OK
{
  "chain_id": "obex-alpha-testnet",
  "genesis_hash": "0x6e…",
  "obex_version": 2,
  "slots_per_sec": 10,
  "head": { "slot": 4242, "header_id": "0xa1…" },
  "address_format": "ed25519-hex"
}

15.2 GET /v1/alpha_iii/4242?format=json&limit=2
200 OK
{
  "slot": 4242,
  "items": [ { "ticket_id": "0x…", "txid": "0x…", "sender": "0x…", "nonce": 1, "amount_u": "1000", "fee_u": "10", "s_admit": 4242, "s_exec": 4242, "commit_hash": "0x…" }, { "ticket_id": "0x…", "txid": "0x…", "sender": "0x…", "nonce": 2, "amount_u": "500", "fee_u": "10", "s_admit": 4242, "s_exec": 4242, "commit_hash": "0x…" } ],
  "next_cursor": "eyJzbG90Ijo0MjQyLCJvZmZzZXQiOjJ9"
}

15.3 POST /v1/tx
Request
{
  "tx_body_v1": { "sender": "0x…", "recipient": "0x…", "nonce": 12, "amount_u": "1000000", "fee_u": "10000", "s_bind": 4242, "y_bind": "0x…", "access": { "read_accounts": [], "write_accounts": [] }, "memo": "0x" },
  "signature": "0x…"
}
Response 200
{ "txid": "0x…", "commit_hash": "0x…", "accepted": true }

— End of API Plan v2 —


