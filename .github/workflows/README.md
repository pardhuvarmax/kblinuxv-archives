# .github/workflows

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `discovery-import.yml` | manual, or new snapshot under `discovery/raw/` | Import and normalize scanner output |
| `acquisition.yml` | manual, after an approval manifest is committed | Retrieve approved source files and open a PR |
| `validation.yml` | pull request | Validate schemas, metadata and hashes |
| `pull-request-checks.yml` | pull request | Policy checks before merge |

Rules: no workflow compiles or executes acquired PoCs, none sets `LAB_VALIDATED`, and write permissions are
granted only to the workflows that need them. Pin third-party actions to reviewed commit SHAs. Never use
`pull_request_target` to run untrusted code.

`validation.yml` (schemas and tests) and `pull-request-checks.yml` (hash integrity and policy) are real and read-only.
`discovery-import.yml` and `acquisition.yml` are still skeletons that run a placeholder step; acquisition runs locally for now.
