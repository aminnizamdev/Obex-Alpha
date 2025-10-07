Security Threat Model

Assets
- Consensus rules (hashing, tags, encodings), headers, participation records, ticket records, system txs.

Adversaries
- Byzantine peers (invalid headers/bodies), DoSers (oversize, floods), forgers (invalid VRF/signatures), replayers.

Threats & Mitigations
- Oversize bodies → Pre-crypto size caps (α‑I, VDF buffers, header size).
- Invalid encodings → Canonical codecs; exact length checks; reject trailing bytes.
- Forged VRF/signatures → RFC 9381 ECVRF verify; Ed25519 verify_strict; constant-time compares.
- Header forks → Deterministic equalities; exactly one valid header per (parent, slot).
- Replay/missing data → Header-first; fetch and recompute locally; reject unverifiable.
- Resource exhaustion → Rate limits; per-slot fetch caps; backoff; bounded caches; sorted deterministic builders.

Operational
- Logs omit secrets; structured JSON with reason codes; metrics expose rates not payloads.

Disclosure
- Security contact and responsible disclosure policy published in README.


