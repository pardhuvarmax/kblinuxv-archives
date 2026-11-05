# internal/pipeline

The full batch flow behind `kblva run`: preflight, resolve, select, approval, acquire, metadata, docs, review sheet, checks, and the pull request. Cancelling or a dry run leaves `main` clean and stashes refreshed data. It never merges.
