# KB-LVA: Kernel Borderlands Linux Vulnerability Archive

*Preserving Linux vulnerability reproduction artifacts for research, analysis and reproducibility.*

KB-LVA is an independent research dataset project within the Kernel Borderlands ecosystem. It discovers,
acquires, preserves, classifies and curates Linux vulnerability proof-of-concepts and reproduction
artifacts, with enough provenance and verification evidence for other researchers to study and reproduce
them. The primary deliverable is a machine-readable dataset of actual PoC source files (where
redistribution is permitted) plus vulnerability records, provenance, compatibility, integrity hashes,
license status and verification evidence.

Finding a CVE does not mean finding a usable reproduction artifact. KB-LVA records where an artifact came
from, what it is, whether it matches the CVE, whether it is still available, and whether anyone has
reproduced it.

## Status

Milestone M0 (foundation) is in place, with the M1 discovery baseline committed.

| Metric (initial scan, 2026-11-03) | Value |
| --- | --- |
| CVEs scanned | 148 |
| Raw source hits | 5,102 |
| Unique discovered artifacts | 4,447 |
| Unique reproduction candidates | 617 |
| Artifacts acquired | 0 |
| Lab-validated reproductions | 0 |

617 candidates are leads, not confirmed exploits.

## Data lifecycle

1. **Discovery**: the scanner identifies CVEs and candidate artifacts.
2. **Import**: scanner JSON is normalized.
3. **Classification**: direct source file, repository lead, patch, advisory, reproducer or other.
4. **Deduplication**: duplicates merged without losing discovery references.
5. **Acquisition approval**: a human selects the exact artifacts to retrieve.
6. **Source retrieval**: from original repositories at immutable commits.
7. **Integrity and provenance**: hashes, URLs, commits, authorship, license.
8. **Source review**: what the artifact demonstrates and whether it belongs.
9. **Laboratory validation**: isolated, disposable environments.
10. **Dataset release**: versioned, citable snapshots.

Artifact states: `DISCOVERED`, `RETRIEVED`, `SOURCE_REVIEWED`, `LAB_VALIDATED`, or `REJECTED`. Acquisition
is not validation, and merging a PR is not validation.

## Repository layout

| Path | Purpose |
| --- | --- |
| `discovery/` | Registry, immutable scanner snapshots, normalized records, import reports |
| `acquisition/` | Candidates, approval manifests, rejections, logs |
| `corpus/` | Curated source files by category |
| `metadata/` | JSONL dataset layers |
| `schemas/` | JSON Schemas |
| `manifests/` | SHA-256 manifests and release manifests |
| `tools/` | Pipeline code |
| `documentation/` | Methodology and policies |
| `tests/` | Tests |
| `.github/` | Workflows and templates |

Every folder has its own README.

## Automation

GitHub Actions prepares changes; a human decides. Import, approval, acquisition and validation are
separate stages. Automation works on `automation/*` branches and opens pull requests against `main`.
It never compiles or executes PoCs and never marks anything lab-validated.

## Principles

Artifact-centric, provenance-preserving, classification-driven, reproducibility-aware,
integrity-preserving, license-conscious, machine-readable, human-reviewed, independent of Kernel
Borderlands, and versioned.

## Not in scope

KB-LVA is not a vulnerability scanner, a CVE database replacement, an exploit-development framework, an
attack platform, a PoC execution engine, a disclosure platform, a Kernel Borderlands defence component, or
a benchmark. It can supply curated artifacts to benchmarks such as KB-AL-150, but does not depend on them.

## Licensing and safety

Collected artifacts keep their original licenses and attribution; a public repository does not grant
redistribution rights. Where a license is unknown or restrictive, only metadata and a source reference are
kept. Do not run anything from this archive outside an isolated lab. See `documentation/`.

The repository's own license has not been chosen yet.
