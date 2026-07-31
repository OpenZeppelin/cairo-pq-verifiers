# PQ verifier benchmark summary

_Generated 2026-07-31 12:36._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 12,809,640 | 12.8096% | 104,854 | 10.4854% | 89 | yes |
| Falcon-512 direct (no hint) | 23,005,760 | 23.0058% | 205,781 | 20.5781% | 60 | yes |
| Falcon-512 SHAKE-256 (standard) | 50,163,668 | 50.1637% | 312,892 | 31.2892% | 89 | yes |
| Falcon-512 SHAKE-256 direct (standard, no hint) | 60,359,788 | 60.3598% | 413,819 | 41.3819% | 60 | yes |
| Falcon-512 Poseidon (native) | 12,045,449 | 12.0454% | 97,681 | 9.7681% | 89 | yes |
| SLH-DSA-SHA2-128s | 1,803,067,376 | 1803.0674% | 4,271,878 | 427.1878% | 493 | no |
| SLH-DSA-SHAKE-128s | 410,340,991 | 410.341% | 843,750 | 84.375% | 493 | no |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
