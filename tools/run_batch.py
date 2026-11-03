"""Run one full acquisition batch, from candidate selection to a pull request you merge.

    python tools/run_batch.py [--size 15] [--cves FILE] [--dry-run] [--yes] [--skip-resolve]

Stages (each is an existing tool; this script only sequences them):
  1. preflight        on a clean, up-to-date main
  2. resolve          turn repository leads into specific files (metadata only), then re-import
  3. select           one file per CVE, CVEs without a stored artifact first, licensed repos preferred
  4. APPROVAL         you approve, drop IDs, or cancel at a terminal prompt (--yes skips it)
  5. acquire          pull approved files at pinned commits; unlicensed ones go to git-ignored local-only/
  6. metadata+docs    vulnerability metadata from NVD, folder READMEs, static review sheets
  7. checks           schemas, hashes, policy, tests
  8. pull request     branch automation/acquisition-<date>-<NNN>, commit, push, open the PR

It never executes or compiles anything it downloads, never marks anything reviewed or lab-validated, and never
merges. Needs GITHUB_TOKEN (or a logged-in `gh`).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools/acquisition"))
from acquire_artifacts import SPDX_ALLOW  # noqa: E402
from extract_candidates import propose_batch, repo_licenses  # noqa: E402


def jl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()] if path.is_file() else []


def next_batch_number(root: Path) -> str:
    nums = [int(m.group(1)) for f in (root / "acquisition/logs").glob("acquisition-*-*.md")
            if (m := re.search(r"-(\d{3})\.md$", f.name))]
    return f"{max(nums, default=0) + 1:03d}"


def select_batch(cands: list[dict], vulns: dict, stored_cves: set[str], done_ids: set[str], size: int,
                 licenses: dict | None = None, only: set[str] | None = None) -> list[dict]:
    """Pool: ready, not yet approved or retrieved. CVEs with no stored artifact come first, then the rest."""
    pool = [c for c in cands if c["artifact_id"] not in done_ids and (only is None or c["cve"] in only)]
    fresh = [c for c in pool if c["cve"] not in stored_cves]
    batch = propose_batch(fresh, vulns, size, licenses)
    if len(batch) < size:
        used = {c["cve"] for c in batch}
        batch += propose_batch([c for c in pool if c["cve"] in stored_cves and c["cve"] not in used],
                               vulns, size - len(batch), licenses)
    return batch


def show(batch: list[dict], licenses: dict) -> None:
    print(f"\n{'#':>2}  {'artifact':<20} {'CVE':<16} {'lang':<7} {'license':<12} repository / file")
    for i, c in enumerate(batch, 1):
        lic = licenses.get(c["repository"]) or "none"
        mark = "" if lic in SPDX_ALLOW else "  (-> local-only)"
        print(f"{i:>2}  {c['artifact_id']:<20} {c['cve']:<16} {(c['language'] or '?'):<7} {lic:<12} "
              f"{c['repository']} / {c['filename']}{mark}")


def approve(batch: list[dict], licenses: dict, auto: bool) -> list[dict] | None:
    """Terminal approval gate. Returns the approved subset, or None if cancelled."""
    if auto:
        print("\n--yes given: approving all.")
        return batch
    if not sys.stdin.isatty():
        print("\nNo terminal to ask for approval. Re-run in a terminal, or pass --yes to approve unattended.")
        return None
    while True:
        ans = input("\n[a] approve all   [d N N ...] drop rows by number   [c] cancel > ").strip().lower()
        if ans in ("a", ""):
            return batch
        if ans == "c":
            return None
        if ans.startswith("d "):
            drop = {int(x) for x in ans[2:].replace(",", " ").split() if x.isdigit()}
            batch = [c for i, c in enumerate(batch, 1) if i not in drop]
            if not batch:
                return None
            show(batch, licenses)
            continue
        print("Not understood.")


class Runner:
    def __init__(self, root: Path, env: dict):
        self.root, self.env = root, env

    def py(self, script: str, *args: str) -> None:
        print(f"\n$ {script} {' '.join(args)}")
        subprocess.run([sys.executable, str(self.root / script), *args], cwd=self.root, env=self.env, check=True)

    def git(self, *args: str, check: bool = True) -> str:
        r = subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, env=self.env)
        if check and r.returncode:
            raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
        return r.stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--size", type=int, default=15)
    ap.add_argument("--cves", type=Path, help="Restrict the batch to these CVE IDs (one per line)")
    ap.add_argument("--dry-run", action="store_true", help="Resolve and propose, then stop before approval")
    ap.add_argument("--yes", action="store_true", help="Approve the whole proposal without asking")
    ap.add_argument("--skip-resolve", action="store_true")
    args = ap.parse_args()

    env = dict(os.environ)
    if not env.get("GITHUB_TOKEN"):
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if r.returncode:
            raise SystemExit("GITHUB_TOKEN is not set and `gh auth token` failed.")
        env["GITHUB_TOKEN"] = r.stdout.strip()
    run = Runner(ROOT, env)

    # 1. preflight
    if run.git("branch", "--show-current") != "main":
        raise SystemExit("Start from the main branch.")
    if run.git("status", "--porcelain"):
        raise SystemExit("Working tree is not clean; commit or stash first.")
    run.git("pull", "--ff-only")
    batch_no = next_batch_number(ROOT)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    branch = f"automation/acquisition-{date}-{batch_no}"
    run.git("checkout", "-b", branch)

    def abandon(reason: str) -> int:
        """Leave main clean; keep any refreshed data in a stash rather than deleting it."""
        if run.git("status", "--porcelain"):
            run.git("stash", "push", "-u", "-m", f"run_batch {branch}: {reason}")
            print("Refreshed data was stashed (`git stash list`).")
        run.git("checkout", "main")
        run.git("branch", "-D", branch)
        print(f"{reason}. Nothing was downloaded or committed.")
        return 1

    # 2. resolve repository leads, then refresh normalized data
    if not args.skip_resolve:
        before = set((ROOT / "discovery/raw").iterdir())
        run.py("tools/acquisition/resolve_candidates.py", *(["--cves", str(args.cves)] if args.cves else []))
        if set((ROOT / "discovery/raw").iterdir()) - before:
            run.py("tools/discovery/importer.py")
            run.py("tools/acquisition/extract_candidates.py", "--no-proposal")

    # 3. select
    cands = [c for c in json.loads((ROOT / "acquisition/candidates/candidates.json").read_text())
             if c["triage"] == "ready"]
    vulns = {v["cve"]: v for v in jl(ROOT / "discovery/normalized/vulnerabilities.jsonl")}
    done = {a["artifact_id"] for a in yaml.safe_load(
        (ROOT / "acquisition/approved/approved-artifacts.yaml").read_text()).get("approved_artifacts") or []}
    done |= {p["artifact_id"] for p in jl(ROOT / "metadata/provenance.jsonl")}
    stored_cves = {a["cve"] for a in jl(ROOT / "metadata/artifacts.jsonl")
                   if a["redistribution"].get("stored_path")}
    only = set(args.cves.read_text().split()) if args.cves else None
    licenses = repo_licenses({c["repository"] for c in cands if c["repository"]
                              and c["artifact_id"] not in done and (only is None or c["cve"] in only)
                              and c["cve"] not in stored_cves})
    batch = select_batch(cands, vulns, stored_cves, done, args.size, licenses, only)
    if not batch:
        return abandon("No ready candidates left to propose")
    show(batch, licenses)

    # 4. approval
    if args.dry_run:
        return abandon("Dry run: stopped before approval")
    approved = approve(batch, licenses, args.yes)
    if not approved:
        return abandon("Cancelled at the approval step")
    with (ROOT / "acquisition/approved/approved-artifacts.yaml").open("a") as f:
        f.write(f"# Batch {batch_no}: approved by the repository owner on {date} at the terminal prompt.\n")
        for c in approved:
            f.write(f"  - artifact_id: {c['artifact_id']}\n    approved: true\n")
    ids = [c["artifact_id"] for c in approved]

    # 5-6. acquire, metadata, docs, review sheet
    run.py("tools/acquisition/acquire_artifacts.py", "--batch", batch_no)
    run.py("tools/processing/generate_metadata.py")
    run.py("tools/processing/generate_readmes.py")
    run.py("tools/processing/review_sheet.py", "--batch", batch_no, "--ids", *ids)

    # 7. checks
    run.py("tools/validation/validate_schema.py")
    run.py("tools/validation/verify_hashes.py")
    run.py("tools/validation/check_policy.py")
    print("\n$ pytest")
    subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, env=env, check=True)

    # 8. commit, push, PR
    arts = {a["artifact_id"]: a for a in jl(ROOT / "metadata/artifacts.jsonl")}
    n_stored = sum(1 for i in ids if arts[i]["redistribution"].get("stored_path"))
    n_local = len(ids) - n_stored
    run.git("add", "-A")
    run.git("commit", "-m", f"KB-LVA acquisition batch {batch_no}: {len(ids)} approved artifacts "
                            f"({n_stored} stored, {n_local} local-only)")
    run.git("push", "-u", "origin", branch)
    body = f"""## KB-LVA acquisition batch {batch_no}

Retrieves the {len(ids)} artifacts approved at the terminal prompt, each at its pinned commit. Nothing was compiled or executed.

| Outcome | Count | Meaning |
| --- | --- | --- |
| Stored in `corpus/` | {n_stored} | Repository license is on the allow-list |
| Local-only | {n_local} | No redistributable license: hashed and recorded; the files are in the author's git-ignored `local-only/` folder, not in this PR |

Per-artifact detail: `acquisition/logs/acquisition-{date}-{batch_no}.md`. Static review aid for the stored files:
`acquisition/logs/review-sheet-{batch_no}.md` (facts and flags only; it does not review anything).

All are `RETRIEVED`: not source-reviewed, not lab-validated. Merging does not change that.

## Review checklist

- [ ] Each stored file is actually a reproduction of its CVE
- [ ] Repository-level license plausibly covers the file (recorded license is not verified per file)
- [ ] Flags in the review sheet have been looked at
- [ ] Local-only entries stay out of the repository (the policy check enforces this)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as tf:
        tf.write(body)
    pr = subprocess.run(["gh", "pr", "create", "--base", "main", "--head", branch, "--title",
                         f"KB-LVA: Acquisition Batch #{batch_no}", "--body-file", tf.name],
                        cwd=ROOT, env=env, capture_output=True, text=True)
    os.unlink(tf.name)
    print(f"\nPull request: {pr.stdout.strip() or pr.stderr.strip()}")
    run.git("checkout", "main")
    print("Back on main. Review and merge the PR when ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
