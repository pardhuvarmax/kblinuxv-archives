# tools/discovery

`import_results.py` reads every snapshot in `discovery/raw/` and writes `discovery/normalized/` plus the import report; `normalize.py` holds the pure normalization functions (deduplication by file URL, artifact IDs, pinned-commit parsing).
