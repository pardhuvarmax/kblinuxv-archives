# internal/docs

Generates the README for each CVE folder and artifact folder under `corpus/`, and the navigation READMEs and index under the git-ignored `local-only/`. It also rewrites the status block between `<!-- kblva:status:start -->` and `<!-- kblva:status:end -->` in the root README from `internal/stats`; the CLI refreshes it after every command that changes the data. A test fails if the committed block is out of date. Offline: it reads `metadata/` and the files on disk.
