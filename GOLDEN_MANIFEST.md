Golden Manifest (Files, Sizes, Checksums)

Purpose
- This manifest lists every golden artifact required for byte-precise conformance. Use it to generate, verify, and publish goldens.

Format
- JSON index `tests/golden/index.json` with entries:
```
{
  "vdf": {
    "seed_commit.bin":  { "bytes": 32,     "sha256": "..." },
    "y_core.bin":       { "bytes": 32,     "sha256": "..." },
    "y_edge.bin":       { "bytes": 32,     "sha256": "..." },
    "pi.bin":           { "bytes": 0,      "sha256": "..." },
    "ell.bin":          { "bytes": 0,      "sha256": "..." }
  },
  "alpha_i": {
    "pk.bin":           { "bytes": 32, "sha256": "..." },
    "vrf_output.bin":   { "bytes": 64, "sha256": "..." },
    "vrf_proof.bin":    { "bytes": 80, "sha256": "..." },
    "root.bin":         { "bytes": 32, "sha256": "..." },
    "partrec.bin":      { "bytes": "<=600000", "sha256": "..." },
    "P_s.root.bin":     { "bytes": 32, "sha256": "..." }
  },
  "alpha_iii": {
    "ticket_leaves.bin": { "bytes": "var", "sha256": "..." },
    "ticket_root.bin":   { "bytes": 32, "sha256": "..." }
  },
  "header": {
    "header.bin":     { "bytes": "<=4096", "sha256": "..." },
    "header_id.bin":  { "bytes": 32, "sha256": "..." }
  },
  "negatives": [ "..." ]
}
```

Rules
- All files are immutable once published for a given testnet tag; any change requires new tag and version bump where applicable.


