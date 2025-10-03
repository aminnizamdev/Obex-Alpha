OBEX Alpha — Spec Index (Public Testnet Rebuild)

Use this index to navigate the complete, byte-precise specs and rebuild plan. The original folder `OBEX.ALPHA v1 - BACKUP LATEST 30092025 2134/` is frozen and serves as the authoritative reference implementation. These documents do not modify it; they provide a faithful, implementation-ready blueprint to rebuild from scratch without drift.

Core
- CONSENSUS_SPEC.md — Hashing, tags, endianness, Merkle rules, versions, DoS bounds
- ALPHA_I_SPEC.md — Participation (VRF, seed/labels, challenges, ObexPartRec, P_s root)
- ALPHA_II_AND_VDF_SPEC.md — Header spec and VDF freeze plan (Wesolowski)
- ALPHA_III_SPEC.md — Admission (canonical tx bytes, fees, TicketRecord, root)
- ALPHA_T_SPEC.md — Tokenomics (emission, NLB fee splits, DRP, system tx order)

System & Testing
- NETWORKING_AND_AVAILABILITY.md — Header-first flow, endpoints, limits
- GOLDENS_AND_TESTING.md — Golden artifacts, unit/fuzz/e2e, rules
- BYTE_LAYOUTS.md — Exact byte layouts with offsets for all consensus objects
- GOLDEN_MANIFEST.md — Files, lengths, and checksums for goldens
- CONFORMANCE_MATRIX.md — Mapping of spec requirements to code functions

Node & Ops
- NODE_AND_GENESIS.md — Node responsibilities, storage, scheduler, genesis
- API_ENDPOINTS.md — HTTP API request/response shapes and status codes
- ERRORS_AND_CODES.md — Stable reject enums and numeric codes
- PERF_GATES.md — Bench targets, hardware profiles, acceptance gates
- SECURITY_THREAT_MODEL.md — Threats, mitigations, invariants
- OPS_SECURITY_PERF_BUILD.md — Ops posture and local build workflow (no CI)

Plan
- PUBLIC_TESTNET_PLAN.md — End-to-end execution plan and milestones
- IMPLEMENTATION_CHECKLIST.md — Concrete task list to rebuild without drift

Note on Tag Names
- All consensus hashes must use tags in the `obex.*` namespace as listed in CONSENSUS_SPEC.md and SPEC_FREEZE.md. During rebuild, audit that helper functions do not use un-namespaced variants.


