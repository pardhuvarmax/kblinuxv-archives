# internal/importer

`kblva import`: merges every snapshot in `discovery/raw/` per CVE into `discovery/normalized/` and writes `discovery/reports/import-report.md`. `golden_test.go` re-runs it on the committed snapshots and fails if the output differs from the committed data.
