Node, Genesis & Packaging

Node (obex‑node)
- Responsibilities: header‑first validation, fetch bodies/proofs, recompute roots, schedule slots, persist headers/state, expose minimal HTTP endpoints, metrics/logs.
- Storage: append‑only headers by slot; participation set cache; per‑slot ticket sets.
- Scheduler: tick every SLOT_MS; process incoming headers out‑of‑order by caching until parent available.

Genesis
- genesis.toml contents:
  - network_id (string)
  - genesis_header_id (hex)
  - versions: α‑I/II/III/T
  - VDF: delta_bits, g (base64), T (LE8)
  - Fees: min/flat/switch

Packaging
- Static binaries for linux‑x86_64 and aarch64; provide SHA256 sums; publish genesis.toml and peer seeds.
- Dockerfile/Compose to run a 5‑node devnet locally.

Operator Guide
- Startup: `obex-node --genesis genesis.toml --data-dir ... --listen 0.0.0.0:PORT`.
- Telemetry: scrape `/metrics` (OpenMetrics format) or log tail JSON.
- Health: consistent header IDs across nodes per slot.


