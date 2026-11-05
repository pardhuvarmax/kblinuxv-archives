# acquisition/candidates

What the pipeline considers for acquisition.

- `candidates.json`: every reproduction candidate with its triage level (`ready`, `needs-review`, `needs-resolution`) and flags, from `kblva triage`. Triage is heuristic and name-based, not a code review.
- `repo-licenses.json`: repository licenses looked up so far (GitHub API, metadata only). `null` means no license.
- One folder per batch, named `first-batch`, `second-batch`, ...: the proposal, what was approved and retrieved, the CVE restriction if any, and a README. `kblva run` fills these in; `kblva arrange` regenerates them.

| Folder | Batch | Date | Files |
| --- | --- | --- | --- |
| [`first-batch/`](first-batch/) | 001 | 2026-11-03 | 15 |
| [`second-batch/`](second-batch/) | 002 | 2026-11-03 | 23 |
| [`third-batch/`](third-batch/) | 003 | 2026-11-05 | 15 |

Nothing is approved until it is in `acquisition/approved/approved-artifacts.yaml`.
