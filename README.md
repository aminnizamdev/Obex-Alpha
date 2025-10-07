Obex Alpha — Public Testnet Rebuild (Byte‑Precise)

Overview

Obex Alpha is a spec‑first, byte‑precise rebuild of a public testnet protocol. This repository contains:

- Source code for the consensus engines and node implementation under `obex-alpha/`
- Complete, implementation‑ready specifications and plans in the repository root (see “Documentation Index”)

All consensus‑critical behavior is implemented with `#![forbid(unsafe_code)]` and `#![deny(warnings)]`. Hashing, tagging, endianness, sizes, and equality checks are specified and enforced in code and tests. Golden vectors are included and verified byte‑for‑byte in tests.

Repository structure

- `obex-alpha/` — Rust workspace
  - `crates/obex_primitives` — Tagged SHA3‑256 hashing, LE framing, binary Merkle
  - `crates/obex_alpha_i` — α‑I Participation engine, VRF adapter, PartRec codec/verify
  - `crates/obex_alpha_ii` — α‑II Header engine, field‑wise HeaderID, beacon v1 adapter
  - `crates/obex_alpha_iii` — α‑III Admission (canonical tx bytes, fees, tickets, root)
  - `crates/obex_alpha_t` — α‑T Tokenomics (emission accumulator, sys tx ordering)
  - `crates/obex_node` — Minimal HTTP node: header‑first validation, storage, metrics
  - `crates/obex_tool` — CLI tooling: generate goldens, burn‑in, utilities
  - `genesis/` — Example `genesis.toml`
  - `scripts/` — Devnet helpers (PowerShell)
  - `tests/golden/` — Golden artifacts for conformance
- Spec & ops documents live at the repository root (see below)

Consensus and Engines (as implemented)

- Hashing & tags (`crates/obex_primitives`)
  - SHA3‑256; domain separation via ASCII tags in the `obex.*` namespace
  - Length framing: H(tag, parts) = SHA3_256( UTF8(tag) || Σ( LE(|p|,8) || p ) )
  - Binary Merkle with duplicate‑last; constant‑time hash equality

- α‑I Participation (`crates/obex_alpha_i`)
  - RFC 9381 ECVRF(Ed25519/SHA512/TAI) adapter returning 64‑byte output for 80‑byte proof
  - Deterministic alpha/seed/label/index functions and challenge selection (Q=96)
  - Canonical `ObexPartRec` codec with strict size cap (≤ 600,000 bytes)
  - Full verifier: VRF, signature over transcript, Merkle proofs and label equation for each challenge

- α‑II Header (`crates/obex_alpha_ii`)
  - Field‑wise `Header` with `obex_header_id(h)` derived from field values and explicit lengths
  - Beacon v1 (hash‑edge) adapter: `vdf_pi.len() == 0`, `vdf_ell.len() == 0`, `y_edge == H(obex.vdf.edge, [y_core])`
  - Deterministic validation: parent link, slot, version, size caps, seed_commit equality, beacon, and root equalities

- α‑III Admission (`crates/obex_alpha_iii`)
  - Canonical TxBodyV1 bytes, deterministic fee rule (flat ≤ 1,000; else ceil(1%))
  - Admission state updates; `TicketRecord` encoding and per‑slot ticket root (sorted by txid)

- α‑T Tokenomics (`crates/obex_alpha_t`)
  - Emission accumulator with terminal flush to exact total supply
  - Canonical system transaction ordering; reward ranking determinism

Node (`crates/obex_node`)

Responsibilities

- Header‑first validation of incoming headers:
  - Parent link, slot, version checks
  - Size caps (header, α‑I record, VDF buffers)
  - Seed_commit equality and beacon v1 equality
  - Root equalities via local providers (tickets, participation, previous txroot)
- Storage: sled‑backed key/value store for headers and artifacts; in‑memory maps for request handling
- HTTP API: minimal endpoints for body fetch and header operations
- Observability: JSON logs (structured), OpenMetrics endpoint, health check

HTTP API (legacy + v1)

Legacy endpoints (kept for compatibility):

- `GET /alpha_i/{slot}/{pk}` → raw canonical α‑I `ObexPartRec` bytes (size‑capped)
- `GET /alpha_iii/{slot}` → concatenated canonical `TicketRecord` leaf bytes (216‑byte leaves)
- `GET /header/{slot}` → JSON header DTO
- `POST /header` → accept header DTO; validate parent link, slot, version, seed_commit, beacon v1, and root equalities
- `POST /advance` → deterministically build next header from local state and persist
- `GET /metrics` → OpenMetrics text (validation counts, average latencies, fetch counts, root build timings)
- `GET /healthz` → readiness check (genesis present)

Versioned `/v1` endpoints (wallets + explorers):

- Chain/head
  - `GET /v1/info` → { chain_id, genesis_hash, obex_version, slots_per_sec, head, address_format }
  - `GET /v1/head` → { slot, header_id }
  - `GET /v1/headers?from=&to=&limit=&cursor=` → paginated headers (cursor is base64)
  - `GET /v1/slot/{slot}` → { header, counts: { tickets, participants } }

- Tickets (α‑III)
  - `GET /v1/alpha_iii/{slot}?limit=&cursor=` → JSON ticket list (216‑byte leaf fields rendered), with cursor pagination
  - `GET /v1/ticket/{txid}` → resolve ticket by txid with inclusion proof
  - `GET /v1/proof/ticket/{slot}/{txid}` → Merkle inclusion proof for the ticket leaf

- Participation (α‑I)
  - `GET /v1/alpha_i_index/{slot}` → JSON list of participant PKs for the slot
  - `GET /v1/proof/participant/{slot}/{pk}` → Merkle inclusion proof for participant PK leaf

- Wallet lifecycle
  - `GET /v1/account/{pk}` → { spendable_u, reserved_u, next_nonce } (spendable/reserved scaffolding present; next_nonce derived from observed tickets)
  - `POST /v1/tx` → submit TxBodyV1 + Ed25519 signature; verifies canonical bytes (TAG_TX_SIG || canonical_tx_bytes) and returns { txid, commit_hash, accepted }
  - `GET /v1/tx/{txid}` → { status: pending|admitted|rejected, slot? }
  - `GET /v1/fees` → fee rule disclosure { min_tx_u, flat_switch_u, flat_fee_u, rule }

- Observability/ops
  - `GET /v1/peers` → public peer list snapshot
  - `GET /v1/search?q=` → resolve txid|header_id|pk|slot → typed result
  - `GET /v1/stats/supply` / `participation` / `fees` → basic summaries
  - `GET /v1/subscribe` → Server‑Sent Events (SSE): `newHead`, `ticketAdmitted`

API semantics:

- Error model: all `/v1` handlers return a uniform JSON error envelope `{ code, error, message, details }` with appropriate HTTP status.
- Pagination: `cursor` (base64) + `limit` (default 100, max 500) on range list endpoints.
- Caching: `ETag` + `Cache-Control: public, max-age=5` on read endpoints (non‑streaming).
- Encodings: all 32‑byte hashes/keys as `0x`‑prefixed lowercase hex; large integers (
  amounts/fees) serialized as decimal strings.

OpenAPI and SDKs

- OpenAPI 3.1 spec is provided at `API_OPENAPI_v1.yaml` covering all `/v1` endpoints and DTOs.
- Generate SDKs with OpenAPI Generator (examples):
  - TypeScript (fetch):
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g typescript-fetch -o sdk/ts`
  - Rust:
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g rust -o sdk/rust`
  - Go:
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g go -o sdk/go`

OpenAPI and SDKs

- OpenAPI 3.1 spec is provided at `API_OPENAPI_v1.yaml` documenting all `/v1` endpoints and DTOs.
- Generate SDKs with OpenAPI Generator (examples):
  - TypeScript (fetch):
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g typescript-fetch -o sdk/ts`
  - Rust:
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g rust -o sdk/rust`
  - Go:
    - `npx @openapitools/openapi-generator-cli generate -i API_OPENAPI_v1.yaml -g go -o sdk/go`

Header‑first puller (current behavior)

- On header acceptance, if `ticket_root` is non‑empty, the node triggers background fetch of α‑III ticket leaves from configured peers (with per‑peer concurrency, timeouts, backoff, and temporary banlist). Fetched bytes are persisted to sled and the ticket root is recomputed from disk to re‑validate; JSON logs record success/fail per peer and root mismatch warnings.
- α‑I participation pulling is available via index/body endpoints; ingestion is push‑based by default.

Local equalities providers

- Ticket root provider:
  - Computes a Merkle root from concatenated canonical `TicketRecord` leaf bytes for the given slot
- Participation root provider:
  - Verifies canonical α‑I records for the slot from the local store and builds the sorted pk set and root
- Previous txroot provider (txroot_prev):
  - Computes a Merkle root over `Tag("obex.txid.leaf") || txid` values present in α‑III leaves at slot s−1, sorted by txid

CLI (node)

```
obex-node --listen 127.0.0.1:8080 \
          --data-dir data/obex-node \
          --peers http://127.0.0.1:8081,http://127.0.0.1:8082 \
          --max-partrec-concurrency 16 \
          --max-ticket-concurrency 8 \
          --http_timeout_ms 2000
```

Build and run

Prerequisites: Rust stable toolchain.

```
cargo build --locked
cargo test --workspace --all-features

# Run the node (defaults provided)
cd obex-alpha
cargo run -p obex_node -- --listen 127.0.0.1:8080 --data-dir data/obex-node
```

Windows devnet (PowerShell)

```
# Start a 5-node local devnet in release mode
obex-alpha\scripts\devnet.ps1

# Stop the devnet
obex-alpha\scripts\stop-devnet.ps1
```

Tooling (`obex_tool`)

```
# Re-encode a canonical ObexPartRec HEX and print length
cargo run -p obex_tool -- PartrecLen <HEX>

# Generate goldens (vdf, header, alpha_i, alpha_iii, negatives) into a directory
cargo run -p obex_tool -- GenGoldens --out obex-alpha/tests/golden

# Burn-in determinism across nodes (checks HeaderID divergence)
cargo run -p obex_tool -- BurnIn --slots 1000 --nodes http://127.0.0.1:8081,http://127.0.0.1:8082
```

Testing and goldens

- Unit tests cover hashing/tagging, Merkle rules, α‑I indices/label equation, α‑III fee rule, α‑T invariants
- Fuzz tests ensure decode functions do not panic (α‑I PartRec, α‑II header)
- Golden tests assert byte‑for‑byte equality for:
  - `vdf/*` (beacon v1 set)
  - `header/header.bin` and `header/header_id.bin`
  - `alpha_i/partrec.bin` round‑trip
  - `alpha_iii/ticket_leaves.bin` → `ticket_root.bin`

Conformance matrix

- `CONFORMANCE_MATRIX.md` links spec requirements to concrete code locations and tests for α‑I/II/III/T engines and global rules (size caps, beacon adapter, equalities). The matrix is filled for all implemented behaviors.

Performance gates

- Targets are defined in `PERF_GATES.md` (e.g., α‑I verify ≤ 70 ms; header validate ≤ 100 ms on a reference box). Benchmarks exist for α‑I verify and header validation; record results externally and gate runs per the document.

Security and DoS controls

- `#[forbid(unsafe_code)]` and warnings denied across consensus crates
- Pre‑crypto size caps enforced for α‑I records and VDF buffers; constant‑time hash equality
- Request handling uses concurrency semaphores on ingest endpoints; HTTP timeouts for background fetch
- JSON logs include stable codes; OpenMetrics endpoint reports counts and averages

Documentation index

- `SPEC_INDEX.md` — Navigation for all specs and plans
- `CONSENSUS_SPEC.md` — Hashing, domain tags, encodings, Merkle rules
- `ALPHA_I_SPEC.md` — α‑I VRF/seed/labels, participation record, set/root
- `ALPHA_II_AND_VDF_SPEC.md` — Header spec, field‑wise HeaderID, beacon v1
- `ALPHA_III_SPEC.md` — Canonical tx bytes, fees, tickets, root
- `ALPHA_T_SPEC.md` — Emission, fee splits (NLB), DRP, sys tx ordering
- `NETWORKING_AND_AVAILABILITY.md` — Header‑first policy, endpoints, limits
- `GOLDENS_AND_TESTING.md` — Golden vectors, unit/fuzz/e2e strategy
- `BYTE_LAYOUTS.md` — Canonical byte layouts and offsets
- `GOLDEN_MANIFEST.md` — Golden files, sizes, checksums plan
- `CONFORMANCE_MATRIX.md` — Spec → Code → Test coverage
- `OPS_SECURITY_PERF_BUILD.md` — Ops posture and build workflow
- `PERF_GATES.md` — Performance targets and gating policy
- `PUBLIC_TESTNET_PLAN.md` — Execution plan and milestones
- `NODE_AND_GENESIS.md` — Node responsibilities, storage, scheduler, genesis
- `SECURITY_THREAT_MODEL.md` — Threats, mitigations, invariants
- `IMPLEMENTATION_CHECKLIST.md` — Tasks to rebuild without drift

Release and packaging

- Produce static binaries (platforms as needed), SHA256 sums, and a signed `genesis.toml` with frozen version constants and the genesis header id
- Publish peer seeds and operator guide; include metrics and health scraping guidance

License

- Dual‑licensed under MIT or Apache‑2.0 (see crate manifests)

Status and limitations (current code)

- Header‑first validation is complete; background pull is implemented for α‑III ticket leaves with client timeouts and logging
- α‑I record pulling is not enabled by default
- Per‑peer quotas/backoff/banlist for pull‑based fetching can be added without changing public endpoints


