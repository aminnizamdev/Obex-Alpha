Networking & Availability Policy (Header‑First)

Goals
- Deterministic header validation with body/proof fetch on demand; bounded resource usage; reproducible roots locally.

Header‑First Flow
1) Receive header candidate h.
2) Check parent link, slot, version, size caps.
3) Verify seed_commit; run beacon.verify (after size checks).
4) If any root non‑empty: fetch required bodies to recompute locally.

HTTP Endpoints (minimal)
- GET /alpha_i/{slot}/{pk} → application/octet‑stream
  - Returns canonical ObexPartRec bytes for participant pk at slot.
  - Reject if size > MAX_PARTREC_SIZE.
- GET /alpha_iii/{slot} → application/octet‑stream
  - Returns concatenated canonical ticket bytes (TicketRecord leaf bytes) for slot.
- Optional GET /tx/{txid} for audit.

Backpressure & Limits
- Per peer per slot: ≤ 1 ObexPartRec per pk; max concurrent fetches per slot configurable.
- Rate‑limit re‑requests; exponential backoff on failures.

Failure Handling
- Missing bodies or invalid bodies → header invalid/unverifiable; do not finalize.

Logging & Metrics
- Log fetch start/end with slot and header_id; count failures by endpoint and reason.


