# .github/workflows

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `validation.yml` | pull request | Schemas and Python tests |
| `pull-request-checks.yml` | pull request | Stored-file hashes and policy |
| `go.yml` | pull request, push to `main` | gofmt, vet, tests, build, and `kblva validate` on the real dataset |

All three are read-only (`contents: read`) and never execute or compile anything under `corpus/`. Pin third-party actions to reviewed commit SHAs, and never use `pull_request_target` to run untrusted code.

Importing discovery output and acquiring artifacts are not workflows: they run locally with `kblva run`, because unlicensed files must stay on the author's machine (`local-only/`) and approval happens at a terminal prompt.

`workflows_test.go` (in `internal/validate`) parses every file here, so a file GitHub would reject cannot reach `main`.
