Ops, Security, Performance, Build Workflow

Security
- No `unsafe`; constant‑time verification where applicable; fail‑fast size caps before crypto.
- Key hygiene: zeroize secrets in tooling; consensus paths never carry private keys.
- Reporting: security contact, responsible disclosure (see README Security).

Performance
- Benchmarks with gates on reference hardware; document floor on low‑end.
- Profile α‑I hot paths (Merkle verify, label equation) and header validation.

Build Workflow (Solo, No CI)
- Before tagging or regenerating goldens:
  1) cargo fmt --all
  2) cargo clippy --all-targets --all-features -D warnings
  3) cargo build --locked
  4) cargo test --workspace --all-features
  5) cargo test -p e2e -- --ignored golden
- Optional nightly fuzz for decode paths.

Release Checklist
- Freeze constants; regenerate goldens; tag release; publish binaries + SHA256; publish genesis and peers.


