# internal/batches

Arranges `acquisition/candidates/` into one folder per batch (`first-batch/`, `second-batch/`, ...; `batch-021` after twentieth). Each holds `proposed.md`, `approved.md` (generated from the acquisition log and metadata), `cves.txt` when a run was restricted to certain CVEs, and a README. `Arrange` also moves the flat files older versions wrote, never overwriting an existing file, and is safe to re-run.
