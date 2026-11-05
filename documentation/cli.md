# kblva command reference

`kblva` is the KB-LVA pipeline as one Go binary. Build it with `make build` (`bin/kblva`) or `make install`. Run it from anywhere inside the repository, or point at it with `--root`.

## Install

System-wide, like any pacman package (installs `/usr/bin/kblva`, bash/zsh/fish completions, man pages and docs):

```
cd packaging/arch && makepkg -f
sudo pacman -U kblva-*.pkg.tar.zst
kblva config set-root /path/to/this/repository    # once; then kblva works from any directory
```

Per-user alternative: `make install` puts the binary in `$(go env GOPATH)/bin`. Upgrade a package install by pulling, rebuilding and running `pacman -U` again; remove it with `sudo pacman -R kblva`.

`kblva` finds the repository by: `--root`, the working directory (searching upward), `$KBLVA_ROOT`, then the path saved by `kblva config set-root`. `kblva config show` says which one it used.

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

`kblva run` keeps `acquisition/candidates/` tidy on its own: each batch gets a folder (`first-batch`, `second-batch`, `third-batch`, ...) holding `proposed.md` (what was proposed, with licenses), `approved.md` (what was retrieved, with outcomes), `cves.txt` if you restricted the run, and a README. `candidates.json` and `repo-licenses.json` (every repository license looked up so far) stay at the top level.

## Individual stages

| Command | What it does |
| --- | --- |
| `status` | Dashboard: registry, candidates, retrieved artifacts, states, local-only files |
| `show ID` | An artifact (by ID) or a CVE |
| `add-cve CVE...` | Register new CVEs from NVD (component, subsystem and class inferred and flagged with `~`), scan them, file the snapshot, import and triage. `--dry-run` shows the entries, `--no-scan` registers only, `--pr` does it on a `data/add-*` branch and opens a PR, `--component/--subsystem/--class` override the guesses |
| `scan CVE...` | Scan CVEs already in the registry (drives `kb_poc_discovery.py`), file the snapshot, import and triage |
| `import` | Merge scanner snapshots into `discovery/normalized/`; issued artifact IDs never change |
| `triage` | `ready` / `needs-review` / `needs-resolution` into `acquisition/candidates/candidates.json` |
| `resolve` | Repository leads to specific files, as a new snapshot (then run `import` and `triage`) |
| `propose` | Write a proposal into the next batch's folder (`<ordinal>-batch/proposed.md`): one ready file per CVE; `--licenses` looks up repository licenses |
| `arrange` | Arrange `acquisition/candidates/` into `first-batch/`, `second-batch/`, ... (moves old flat files, regenerates `approved.md` and READMEs; `run` does this itself) |
| `approve` | Approve by ID, or every row of a `--proposal` file |
| `acquire` | Pull approved files; `--sync-local` refills missing `local-only/` files and checks their hashes |
| `meta` | Build `metadata/vulnerabilities.jsonl` from NVD and the registry |
| `docs` | Generate the folder READMEs (`corpus/` and `local-only/`) |
| `review sheet` | Static facts and red flags per artifact (never a verdict) |
| `review record` | Record your verdict: `--accept`, or `--reject --reason TEXT` |
| `review status` | Count artifacts per verification state |
| `keys` | `set`, `list`, `get`, `delete`, `import`, `test`: API keys stored encrypted (system keyring or passphrase file) |
| `config` | `set-root [PATH]`, `show`, `unset-root`: remember the repository so kblva runs from anywhere |
| `validate` | Schemas, hashes and policy; or `validate schema|hashes|policy` |

## Scanning new CVEs

`kblva add-cve CVE-YYYY-NNNN` replaces the by-hand routine of editing `registry.yaml`, running the scanner and placing its output. The scanner stays a separate Python component (`kb_poc_discovery.py`, git-ignored). `kblva` finds it in the repository root and uses `<repo>/.venv/bin/python` if present (create it with `python3 -m venv .venv && .venv/bin/pip install pyyaml requests`); override with `--scanner`, `--python` or `$KBLVA_PYTHON`. The scan reads public metadata only and takes minutes because the public indexes are rate-limited; `--show-scanner-output` streams its progress. Each scan becomes an immutable snapshot under `discovery/raw/` with a README and checksums. Registry entries are only appended, re-parsed afterwards, and restored if one would break the file. To pull files for the new CVEs, run `kblva run`.

## API keys

Keep `NVD_API_KEY` and `GITHUB_TOKEN` encrypted instead of in a shell profile:

```
kblva keys set NVD_API_KEY      # typed without echo (or: pbpaste | kblva keys set NVD_API_KEY --stdin)
kblva keys list                 # where each key is available from; never the values
kblva keys test                 # makes one request each to confirm the keys are accepted
kblva keys import               # move exported variables into the store, then delete the export lines
kblva keys delete NVD_API_KEY
```

The default store is the system keyring (the Secret Service: GNOME Keyring, KWallet, ...): the OS encrypts it and unlocks it at login, so nothing is typed per command. Without a keyring, `keys set` uses a file encrypted with a passphrase (scrypt + AES-256-GCM, mode 0600, `~/.config/kblva/keys.enc`); the passphrase is asked for only when a stored key is needed. `--backend keyring|file` forces one.

kblva looks for a key in the environment variable first, then the keyring, then the file, so an exported variable still wins. A key is never accepted as a command-line argument (shell history, `ps`) and never printed unless you run `keys get`. `GITHUB_TOKEN` falls back to your `gh` login. `KBLVA_NO_KEYRING=1` disables the keyring.

## What it will not do

It never executes or compiles anything it downloads, never sets `SOURCE_REVIEWED` or `LAB_VALIDATED` by itself, never merges, and never commits anything under `local-only/`. Unlicensed files are fetched for local research only.

## Environment

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | GitHub API token (falls back to the logged-in `gh`) |
| `NVD_API_KEY` | Optional: raises the NVD rate limit. Prefer `kblva keys set` |
| `KBLVA_NO_KEYRING` | Set to skip the system keyring |
