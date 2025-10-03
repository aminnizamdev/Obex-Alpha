HTTP API Endpoints (Minimal Testnet)

GET /alpha_i/{slot}/{pk}
- Request: slot (u64 decimal), pk (hex 64)
- Response: application/octet-stream; body = canonical ObexPartRec bytes
- Status:
  - 200 OK: body present
  - 404 Not Found: no record for pk at slot
  - 413 Payload Too Large: record exceeds MAX_PARTREC_SIZE

GET /alpha_iii/{slot}
- Request: slot (u64 decimal)
- Response: application/octet-stream; body = concatenated TicketRecord leaf bytes for slot
- Status:
  - 200 OK: body present (may be empty)
  - 404 Not Found: no tickets recorded for slot

GET /tx/{txid} (optional)
- Request: txid (hex 64)
- Response: canonical tx bytes

Metrics (optional)
- GET /metrics → OpenMetrics text; includes header validation counts, timings, fetch failures.

Notes
- All binary payloads are consensus‑canonical encodings; clients must apply size caps before decode.


