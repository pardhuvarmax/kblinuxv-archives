# kblva command reference

`kblva` is the KB-LVA pipeline as one Go binary. Build it with `make build` (`bin/kblva`) or `make install`. Run it from anywhere inside the repository, or point at it with `--root`.

Global flags: `--root DIR`, `--json` (machine-readable output where supported), `--no-color`. Shell completion: `kblva completion bash|zsh|fish`.

## Run a batch

```
kblva doctor            # check git, gh, tokens and .gitignore
kblva run --size 15     # resolve, select, ask, pull, document, check, open a PR
```

`kblva run` stages:

1. **Preflight**: clean, up-to-date `main`; creates `automation/acquisition-<date>-<NNN>`. Refuses to start if an earlier batch branch is still unmerged.
2. **Resolve**: repository leads become specific files (file trees only, nothing downloaded), then re-import and re-triage.
3. **Select**: one file per CVE; CVEs with no stored artifact first; licensed repositories preferred; helper files and tools excluded.
4. **Approval**: an interactive list of the proposed files. `x` toggles a file, `ctrl+a` clears all, `enter` confirms, `ctrl+c` cancels. `--yes` approves everything without asking.
5. **Pull**: files at pinned commits. Licensed files go to `corpus/`; every other file goes to the git-ignored `local-only/`.
6. **Document**: NVD metadata, folder READMEs, a static review sheet.
7. **Check**: schemas, hashes, policy.
8. **Pull request**: commit, push, `gh pr create`. It never merges.

`--dry-run` stops before approval. Cancelling or `--dry-run` leaves `main` clean and stashes any refreshed data (`git stash list`) instead of deleting it. Other flags: `--cves FILE` restricts the batch to those CVEs, `--skip-resolve` skips step 2.

## Individual stages

| Command | What it does |
| --- | --- |
| `status` | Dashboard: registry, candidates, retrieved artifacts, states, local-only files |
| `show ID` | An artifact (by ID) or a CVE |
| `import` | Merge scanner snapshots into `discovery/normalized/`; issued artifact IDs never change |
| `triage` | `ready` / `needs-review` / `needs-resolution` into `acquisition/candidates/candidates.json` |
| `resolve` | Repository leads to specific files, as a new snapshot (then run `import` and `triage`) |
| `propose` | Write a proposal file: one ready file per CVE; `--licenses` looks up repository licenses |
| `approve` | Approve by ID, or every row of a `--proposal` file |
| `acquire` | Pull approved files; `--sync-local` refills missing `local-only/` files and checks their hashes |
| `meta` | Build `metadata/vulnerabilities.jsonl` from NVD and the registry |
| `docs` | Generate the folder READMEs (`corpus/` and `local-only/`) |
| `review sheet` | Static facts and red flags per artifact (never a verdict) |
| `review record` | Record your verdict: `--accept`, or `--reject --reason TEXT` |
| `review status` | Count artifacts per verification state |
| `validate` | Schemas, hashes and policy; or `validate schema|hashes|policy` |

## What it will not do

It never executes or compiles anything it downloads, never sets `SOURCE_REVIEWED` or `LAB_VALIDATED` by itself, never merges, and never commits anything under `local-only/`. Unlicensed files are fetched for local research only.

## Environment

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | GitHub API token (falls back to the logged-in `gh`) |
| `NVD_API_KEY` | Optional: raises the NVD rate limit |
