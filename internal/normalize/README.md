# internal/normalize

Pure functions that turn scanner hits into artifact and vulnerability records: URL canonicalization, source parsing (file, repository, commit, other), language detection, deduplication, and stable artifact IDs (`LVA-<year>-<number>-<seq>`). An issued ID never changes.
