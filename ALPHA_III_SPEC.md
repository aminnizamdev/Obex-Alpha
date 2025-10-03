α‑III — Admission Engine Specification

Canonical Transaction Bytes (TxBodyV1)
- Bytes = H("obex.tx.body.v1", []) ||
  sender(32) || recipient(32) || LE(nonce,8) || LE(amount_u,16) || LE(fee_u,16) ||
  LE(s_bind,8) || y_bind(32) || encode_access(access) || LE(memo_len,4) || memo.

Access List Encoding
- access_bytes = H("obex.tx.access", []) || LE(|read|,4) || read_accounts*32 || LE(|write|,4) || write_accounts*32.
- Sort & dedup read and write lists before encoding.

Identifiers & Signature
- txid = H("obex.tx.id", [ canonical_tx_bytes ]).
- commit_hash = H("obex.tx.commit", [ canonical_tx_bytes ]).
- Signature message = H("obex.tx.sig", [ canonical_tx_bytes ]); Ed25519 verify_strict with sender pk.

Fee Rule (u128 arithmetic)
- If amount_u ≤ 1,000 → fee = 10; else fee = ceil(amount_u / 100).
- Reject if provided fee_u != computed.

Admission State & Steps
- Maps: spendable_u[pk], reserved_u[pk], next_nonce[pk], admitted_by_slot[s], tickets_by_txid.
- Steps for tx at slot s_now with beacon y_prev:
  1) verify signature; 2) s_bind == s_now; 3) y_bind == y_prev;
  4) nonce == next_nonce[sender]; 5) amount_u ≥ MIN_TX_UOBX; 6) fee_u matches rule;
  7) spendable ≥ amount_u + fee_u → move to reserved; increment nonce.
- Result: Finalized(TicketRecord) or Rejected(reason).

TicketRecord & Root
- TicketRecord fields: ticket_id(32), txid(32), sender(32), LE(nonce,8), LE(amount_u,16), LE(fee_u,16), LE(s_admit,8), LE(s_exec,8), commit_hash(32).
- ticket_id = H("obex.ticket.id", [ txid, LE(s_admit,8) ]).
- Leaf = H("obex.ticket.leaf", []) || canonical fields; per‑slot root = Merkle over leaves sorted by txid.

Reject Reasons
- BadSig, WrongSlot, WrongBeacon, NonceMismatch, BelowMinAmount, FeeMismatch, InsufficientFunds.

Golden Artifacts (α‑III)
- ticket_leaves.bin (concat), ticket_root.bin, fee_edges.json with edge cases, negatives/* (bad fee, bad nonce, bad signature).


