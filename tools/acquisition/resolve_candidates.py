"""Resolve repository-level leads into specific source files.

For every `needs-resolution` repository candidate on GitHub, list the repo's file tree at its current HEAD
(metadata only, nothing is downloaded) and keep source files whose path names the CVE. Writes a new immutable
scanner-style snapshot under discovery/raw/resolved-<date>-<n>/ that tools/discovery/importer.py merges, so
the new files get stable artifact IDs.

    python tools/acquisition/resolve_candidates.py [--root .] [--cves FILE] [--max-per-cve 10]

Needs GITHUB_TOKEN for a usable rate limit.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".py", ".sh", ".rs", ".go", ".rb", ".pl", ".js", ".s", ".asm")


def key(s: str) -> str:
    return re.sub(r"[-_]", "", s.lower())


def match_paths(paths: list[str], cve: str, limit: int) -> list[str]:
    """Source files whose path contains the CVE ID (any dash or underscore form), shortest paths first."""
    hits = [p for p in paths if p.lower().endswith(SOURCE_EXT) and key(cve) in key(p)]
    return sorted(hits, key=lambda p: (p.count("/"), p))[:limit]


def load_tree(repo: str, cache: dict, session: requests.Session) -> tuple[str, list[str]] | None:
    if repo not in cache:
        cache[repo] = None
        c = session.get(f"https://api.github.com/repos/{repo}/commits/HEAD", timeout=30)
        if c.status_code == 200:
            sha = c.json()["sha"]
            t = session.get(f"https://api.github.com/repos/{repo}/git/trees/{sha}", params={"recursive": 1}, timeout=60)
            if t.status_code == 200 and not t.json().get("truncated"):
                cache[repo] = (sha, [e["path"] for e in t.json()["tree"] if e["type"] == "blob"])
    return cache[repo]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--cves", type=Path, help="Only resolve leads for these CVE IDs (one per line)")
    ap.add_argument("--max-per-cve", type=int, default=10)
    args = ap.parse_args()
    root = args.root
    cands = json.loads((root / "acquisition/candidates/candidates.json").read_text())
    have = {c["source_url"].lower() for c in cands}
    only = set(args.cves.read_text().split()) if args.cves else None
    leads: dict[str, set[str]] = {}
    for c in cands:
        if c["triage"] == "needs-resolution" and c["level"] == "repository" and c["repository"] \
                and c["source_url"].startswith("https://github.com/") and (only is None or c["cve"] in only):
            leads.setdefault(c["repository"], set()).add(c["cve"])

    s = requests.Session()
    s.headers.update({"Accept": "application/vnd.github+json", "User-Agent": "kb-lva-resolver"})
    if os.getenv("GITHUB_TOKEN"):
        s.headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    cache: dict = {}
    by_cve: dict[str, list[dict]] = {}
    for repo, cves in sorted(leads.items()):
        loaded = load_tree(repo, cache, s)
        if not loaded:
            continue
        sha, paths = loaded
        for cve in sorted(cves):
            for path in match_paths(paths, cve, args.max_per_cve):
                url = f"https://github.com/{repo}/blob/{sha}/{quote(path)}"
                if url.lower() in have:
                    continue
                by_cve.setdefault(cve, []).append({
                    "source": "github_tree", "kind": "code", "title": f"{repo}/{path}", "url": url,
                    "snippet": f"Resolved from repository lead {repo}: {path}", "artifact_class": "EXPLOIT_POC",
                    "is_reproduction_candidate": True, "verification_state": "DISCOVERED", "poc_candidate": True})
    total = sum(len(v) for v in by_cve.values())
    print(f"{len(leads)} repository leads, {total} source files resolved across {len(by_cve)} CVEs")
    if not total:
        return 0

    now = datetime.now(timezone.utc).replace(microsecond=0)
    n = 1 + len(list((root / "discovery/raw").glob(f"resolved-{now:%Y-%m-%d}-*")))
    out = root / f"discovery/raw/resolved-{now:%Y-%m-%d}-{n:02d}"
    out.mkdir(parents=True)
    (out / "results.json").write_text(json.dumps({
        "summary": {"generated_utc": now.isoformat(), "registry": "registry.yaml",
                    "registry_entries_scanned": len(by_cve), "total_source_hits": total},
        "results": [{"cve_id": cve, "sources": hits} for cve, hits in sorted(by_cve.items())]}, indent=1) + "\n")
    (out / "README.md").write_text(f"""# {out.name}

Repository leads resolved to specific source files by `tools/acquisition/resolve_candidates.py` ({now.date()}).
Metadata only: each repository's file tree was listed at its HEAD commit and files whose path names the CVE were kept.
Nothing was downloaded or executed.

| Metric | Value |
| --- | --- |
| Repository leads examined | {len(leads)} |
| Source files resolved | {total} |
| CVEs covered | {len(by_cve)} |

These are leads, not verified PoCs. Verify files with `sha256sum -c SHA256SUMS`.
""")
    (out / "SHA256SUMS").write_text(f"{hashlib.sha256((out / 'results.json').read_bytes()).hexdigest()}  results.json\n")
    print(out.relative_to(root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
