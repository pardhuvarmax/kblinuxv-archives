# internal

The `kblva` implementation, one package per concern. Packages depend downward only: `cli` calls `pipeline`, which calls the stage packages, which share `data`, `policy` and `pyjson`.

| Package | Purpose |
| --- | --- |
| `pyjson` | JSON encoder that matches Python's `json.dumps`, so regenerated data files are byte-identical |
| `data` | Record types, JSONL/JSON I/O, repository paths, registry and approval-manifest readers |
| `policy` | Fixed rules: redistributable licenses, size cap, states |
| `normalize` | Scanner hits to artifact and vulnerability records; stable IDs |
| `importer` | Merges snapshots into `discovery/normalized/` and writes the import report |
| `triage` | Ready / needs-review / needs-resolution; batch proposal and selection |
| `gh` | GitHub REST client (repository info, licenses, file trees; metadata only) |
| `resolve` | Repository leads to specific files, as a new immutable snapshot |
| `acquire` | Pinned-commit retrieval; `corpus/` for licensed files, `local-only/` for the rest |
| `meta` | NVD and registry data into `metadata/vulnerabilities.jsonl` |
| `docs` | Folder READMEs for `corpus/` and `local-only/` |
| `review` | Static review sheets and recorded human verdicts |
| `validate` | Schemas, hashes and policy checks |
| `pipeline` | The full batch flow from selection to a pull request |
| `ui` | Terminal styling, tables, spinners |
| `cli` | The cobra command tree |

Nothing here executes, compiles or imports downloaded artifacts.
