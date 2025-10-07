Performance Gates & Reference Hardware

Reference Box
- CPU: i5-12400 or Ryzen 5 5600; RAM: 16 GB; OS: Linux x86-64; Rust stable.

Targets (95th percentile)
- vdf_verify: ≤ 10 ms
- α‑I verify (Q=96): ≤ 70 ms
- ticket_root build (200 leaves): ≤ 20 ms
- header_validate end‑to‑end: ≤ 100 ms

Low-End Floor
- Allow up to 2× reference (document measured values).

Benchmarking
- Use Criterion; assert under gates in non-dev bench mode; export summaries.

Regression Policy
- If a gate is exceeded, investigate and either optimize or bump the gate with justification (requires new tag before public net).


