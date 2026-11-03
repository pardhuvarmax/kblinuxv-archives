"""Triage reproduction candidates from discovery/normalized/ into acquisition/candidates/.

Offline and read-only: classifies by URL, path and name only. Nothing is fetched or executed.
It never approves anything; approval is a human decision recorded in acquisition/approved/.

    python tools/acquisition/extract_candidates.py [--root .] [--batch-size 15]

Triage levels:
  ready             direct file at a pinned commit with a source-code extension
  needs-review      direct pinned file, but documentation-like or defensive-looking
  needs-resolution  repository, commit, unpinned file or other URL: must be resolved to a file first
"""
import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import requests
import yaml

SOURCE_EXT = {"C", "C++", "Python", "Shell", "Rust", "Go", "Ruby", "Perl", "JavaScript", "Assembly"}
DEFENSIVE = re.compile(r"mitigat|detect|scanner|checker|yara|sigma|snort|suricata|nuclei|ansible|"
                       r"remediat|workaround|patch|fix|rule|hardening|monitor", re.I)
SOURCE_HOSTS = ("github.com", "gitlab.com")
HELPER_NAME = re.compile(r"\.h$|^(gdb|start|run|build|setup|make|config|compile|util|helper|common)|suggest|enumerat|scanner|checker", re.I)
EXPLOIT_NAME = re.compile(r"exp|poc|cve|pwn|crash|lpe|root", re.I)
SPDX_ALLOW = {"MIT", "MIT-0", "ISC", "Unlicense", "CC0-1.0", "0BSD", "Apache-2.0", "BSD-2-Clause",
              "BSD-3-Clause", "MPL-2.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0",
              "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0"}  # keep in sync with acquire_artifacts.py


def md_url(url: str) -> str:
    """Percent-encode characters that break a markdown link target (spaces, parentheses, ...)."""
    return quote(url, safe=":/?&=#%@+~-._")


def triage(rec: dict) -> tuple[str, list[str]]:
    a, d = rec["artifact"], rec["discovery"]
    flags = []
    if d["level"] != "file" or not a["source_url"].split("/")[2].lower().endswith(SOURCE_HOSTS):
        return "needs-resolution", ["not-a-direct-file"]
    if not a["commit"]:
        return "needs-resolution", ["unpinned-ref"]
    if a["language"] not in SOURCE_EXT:
        flags.append("not-source-code")
    cve_key = rec["cve"].lower()
    if cve_key not in a["source_url"].lower() and cve_key.replace("-", "_") not in a["source_url"].lower():
        flags.append("cve-not-in-url")
    if DEFENSIVE.search(a["filename"] or "") or DEFENSIVE.search(a["source_url"].split("/blob/")[-1]):
        flags.append("defensive-name")
    return ("needs-review" if set(flags) - {"cve-not-in-url"} else "ready"), flags


def repo_licenses(repos: set[str]) -> dict[str, str | None]:
    """Repository-level SPDX id per GitHub repo (metadata only; uses GITHUB_TOKEN if set)."""
    h = {"Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    out = {}
    for repo in sorted(repos):
        r = requests.get(f"https://api.github.com/repos/{repo}", headers=h, timeout=30)
        spdx = (r.json().get("license") or {}).get("spdx_id") if r.status_code == 200 else None
        out[repo] = None if spdx == "NOASSERTION" else spdx
    return out


def propose_batch(cands: list[dict], vulns: dict, size: int,
                  licenses: dict[str, str | None] | None = None) -> list[dict]:
    """One ready candidate per CVE, round-robin across vulnerability categories.

    Ranking: real-looking exploit files first (not helpers or headers), then storable licenses (when
    known), then CVE ID in the URL, then EXPLOIT_POC in C or Python."""
    licenses = licenses or {}
    by_cat: dict[str, list[dict]] = {}
    seen = set()
    ranked = sorted((c for c in cands if c["triage"] == "ready" and not HELPER_NAME.search(c["filename"] or "")),
                    key=lambda c: (bool(HELPER_NAME.search(c["filename"] or "")), not EXPLOIT_NAME.search(c["filename"] or ""),
                                   bool(licenses) and licenses.get(c["repository"]) not in SPDX_ALLOW,
                                   "cve-not-in-url" in c["flags"], c["discovery_class"] != "EXPLOIT_POC", c["language"] not in ("C", "Python"),
                                   c["artifact_id"]))
    for c in ranked:
        if c["cve"] in seen:
            continue
        seen.add(c["cve"])
        by_cat.setdefault(vulns[c["cve"]]["category"] or "unknown", []).append(c)
    batch = []
    while len(batch) < size and any(by_cat.values()):
        for cat in sorted(by_cat):
            if by_cat[cat] and len(batch) < size:
                batch.append(by_cat[cat].pop(0))
    return batch


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--batch-size", type=int, default=15)
    ap.add_argument("--cves", type=Path, help="Text file of CVE IDs: propose only from these CVEs")
    ap.add_argument("--with-licenses", action="store_true",
                    help="Look up repository licenses (GitHub API, metadata only) and prefer storable ones")
    ap.add_argument("--no-proposal", action="store_true", help="Only refresh candidates.json and the report")
    ap.add_argument("--output", help="Proposal file name under acquisition/candidates/ "
                                     "(default: proposed-first-batch.md; other batches must name their own)")
    args = ap.parse_args()
    root = args.root
    jl = lambda p: [json.loads(x) for x in (root / p).read_text().splitlines()]  # noqa: E731
    vulns = {v["cve"]: v for v in jl("discovery/normalized/vulnerabilities.jsonl")}
    cands = []
    for rec in jl("discovery/normalized/artifacts.jsonl"):
        if not rec["discovery"]["is_reproduction_candidate"]:
            continue
        level, flags = triage(rec)
        a = rec["artifact"]
        cands.append({
            "artifact_id": rec["artifact_id"], "cve": rec["cve"], "type": a["type"],
            "source_url": a["source_url"], "repository": a["repository"], "commit": a["commit"],
            "filename": a["filename"], "language": a["language"],
            "discovery_class": rec["discovery"]["class"], "level": rec["discovery"]["level"],
            "triage": level, "flags": flags,
        })
    out = root / "acquisition/candidates"
    (out / "candidates.json").write_text(json.dumps(cands, indent=1) + "\n")

    if not args.no_proposal:
        approved_ids = {a["artifact_id"] for a in yaml.safe_load(
            (root / "acquisition/approved/approved-artifacts.yaml").read_text()).get("approved_artifacts") or []}
        pool = [c for c in cands if c["artifact_id"] not in approved_ids]
        if args.cves:
            only = set(args.cves.read_text().split())
            pool = [c for c in pool if c["cve"] in only]
        licenses = None
        if args.with_licenses:
            ready_repos = {c["repository"] for c in pool if c["triage"] == "ready" and c["repository"]}
            licenses = repo_licenses(ready_repos)
            (out / "repo-licenses.json").write_text(json.dumps(licenses, indent=1, sort_keys=True) + "\n")
        batch = propose_batch(pool, vulns, args.batch_size, licenses)
        lines = [f"| {c['artifact_id']} | {c['cve']} | {vulns[c['cve']]['category']} | {c['language']} | "
                 f"[{c['repository']}](https://{c['source_url'].split('/')[2]}/{c['repository']}) | "
                 f"[`{c['filename']}`]({md_url(c['source_url'])}) | {(licenses or {}).get(c['repository']) or ('none' if licenses else '?')} | {', '.join(c['flags']) or '-'} |" for c in batch]
        scope = sorted(only) if args.cves else sorted({c["cve"] for c in pool})
        missing = [v for v in scope if v not in {c["cve"] for c in batch}]
        name = args.output or "proposed-first-batch.md"
        (out / name).write_text(
            f"# Proposed batch ({name})\n\nSuggestion only: one ready candidate per CVE, spread across vulnerability "
            "categories, preferring candidates whose URL contains the CVE ID, then `EXPLOIT_POC` in C or Python. Nothing here is approved. To approve, copy chosen "
            "IDs into `acquisition/approved/approved-artifacts.yaml`.\n\n"
            "| Artifact ID | CVE | Category | Language | Repository | File | Repo license | Flags |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n"
            + "\n".join(lines) + "\n"
            + (f"\n## No suitable ready candidate\n\nThese CVEs have no direct, pinned, exploit-looking source file yet "
               f"(only helpers, headers, tools or unresolved leads): {', '.join(missing)}.\n" if missing else ""))
    approved = root / "acquisition/approved/approved-artifacts.yaml"
    if not approved.exists():
        approved.write_text("# Artifacts approved for retrieval. Retrieval approval is not redistribution approval.\n"
                            "approved_artifacts: []\n"
                            "# - artifact_id: LVA-0000-0000-001\n#   approved: true\n")

    t = Counter(c["triage"] for c in cands)
    fl = Counter(f for c in cands for f in c["flags"])
    langs = Counter(c["language"] for c in cands if c["triage"] == "ready")
    row = lambda c: "\n".join(f"| {k} | {n} |" for k, n in sorted(c.items(), key=lambda x: -x[1]))  # noqa: E731
    (root / "discovery/reports/candidates-report.md").write_text(f"""# Candidate triage report

Generated by `tools/acquisition/extract_candidates.py`. Heuristic, name- and URL-based: a sorting aid, not a code review.

| Triage | Count |
| --- | --- |
{row(t)}

## Flags

| Flag | Count |
| --- | --- |
{row(fl)}

## Ready candidates by language

| Language | Count |
| --- | --- |
{row(langs)}

`ready` still means only "worth a human look": none of these are reviewed, retrieved or validated.
""")
    print(dict(t), "" if args.no_proposal else f"| proposed batch: {len(batch)}")


if __name__ == "__main__":
    main()
