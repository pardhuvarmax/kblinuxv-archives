# internal/validate

Schema validation of every JSONL file against `schemas/`, hash verification against `manifests/SHA256SUMS`, and policy checks: evidenced states, allow-listed licenses for stored files, size cap, and nothing under `local-only/` tracked by git. Reads files only.
