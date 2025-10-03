Byte Layouts (Offsets & Sizes)

Notation
- LE(n): n-byte little-endian integer; [x;y]: inclusive-exclusive byte range.
- Tags are 32-byte SHA3-256 digests of the domain tag strings applied by H(...); when included literally we denote them as TagBytes(tag).

α‑I — ObexPartRec (encode_partrec)
Order and sizes (all integers little-endian):
1) version: LE(4)                [0;4)
2) slot: LE(8)                   [4;12)
3) pk_ed25519: 32                [12;44)
4) vrf_pk: 32                    [44;76)
5) y_edge_prev: 32               [76;108)
6) alpha: 32                     [108;140)
7) vrf_y: 64                     [140;204)
8) vrf_pi: 80                    [204;284)
9) seed: 32                      [284;316)
10) root: 32                     [316;348)
11) challenges_len: LE(4)        [348;352) (=96)
12) challenges: repeated blocks, each:
    a) idx: LE(8)
    b) li: 32; pi_len: LE(4); pi_siblings: 32×pi_len
    c) lim1: 32; pim1_len: LE(4); pim1_siblings: 32×pim1_len
    d) lj: 32; pj_len: LE(4); pj_siblings: 32×pj_len
    e) lk: 32; pk_len: LE(4); pk_siblings: 32×pk_len
13) sig: 64                      [end-64; end)

Transcript bytes (for signature msg):
msg = H("obex.partrec", [ LE(version,4), pk_ed25519(32), vrf_pk(32), LE(slot,8), y_edge_prev(32), alpha(32), vrf_y(64), root(32) ])

α‑III — TicketRecord Leaf (enc_ticket_leaf)
LeafBytes = TagBytes("obex.ticket.leaf") ||
  ticket_id(32) || txid(32) || sender(32) || LE(nonce,8) || LE(amount_u,16) || LE(fee_u,16) || LE(s_admit,8) || LE(s_exec,8) || commit_hash(32)

α‑III — Access Encoding
access_bytes = TagBytes("obex.tx.access") || LE(|read|,4) || read_accounts*32 || LE(|write|,4) || write_accounts*32

α‑III — Tx Canonical Bytes
tx_bytes = TagBytes("obex.tx.body.v1") || sender(32) || recipient(32) || LE(nonce,8) || LE(amount_u,16) || LE(fee_u,16) || LE(s_bind,8) || y_bind(32) || access_bytes || LE(memo_len,4) || memo

α‑II — Header Serialization (serialize_header)
1) parent_id: 32
2) slot: LE(8)
3) obex_version: LE(4)
4) seed_commit: 32
5) vdf_y_core: 32 (placeholder; to be updated if VDF sizes fixed larger)
6) vdf_y_edge: 32
7) |vdf_pi|: LE(4) then vdf_pi bytes
8) |vdf_ell|: LE(4) then vdf_ell bytes
9) ticket_root: 32
10) part_root: 32
11) txroot_prev: 32

HeaderID inputs use the same field order, but lengths for vdf buffers are included explicitly as LE(4) before their data.

Merkle Node Concatenation
- For node hash: cat = left(32) || right(32) → H("obex.merkle.node", [ cat ])

Note
- Offsets for variable-length sections depend on sibling counts; verify bounds against MAX_PARTREC_SIZE and per-field length prefixes before parsing.


