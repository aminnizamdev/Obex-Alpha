Implementation Checklist (Rebuild Without Drift)

Consensus & Constants
- [ ] Freeze tags and constants (CONSENSUS_SPEC.md) as single source of truth.
- [ ] Audit all hashes use `obex.*` tags.

α‑I
- [ ] Implement VRF adapter (RFC 9381) returning 64‑byte y for 80‑byte π.
- [ ] Implement alpha/seed/label/index functions verbatim.
- [ ] Implement encode/decode_partrec with size cap; transcript and signature verify.
- [ ] Implement build_participation_set and root.
- [ ] KATs: partrec round‑trip; negative cases.

α‑II + VDF
- [ ] Implement header struct, serializer, `obex_header_id` as field‑wise hash.
- [ ] Implement providers and validation equalities.
- [ ] Implement VDF `vdf_verify` adapter; calibrate T; add vectors.

α‑III
- [ ] Implement canonical tx bytes, ids, commit, signature.
- [ ] Implement fee rule; admission flow; ticket leaves and root.

α‑T
- [ ] Implement emission accumulator; NLB fee splits; DRP; sys tx ordering.

Networking
- [ ] Implement header‑first pipeline and HTTP endpoints per NETWORKING_AND_AVAILABILITY.md.

Goldens & Tests
- [ ] Generate vdf, alpha_i, alpha_iii, header goldens; add negatives.
- [ ] Add E2E 3‑slot pipeline test; benches with gates.

Packaging
- [ ] Produce genesis.toml, binaries, SHA256; publish peers.

Release
- [ ] Burn‑in 10k slots on 5‑node devnet; zero divergence; tag release.


