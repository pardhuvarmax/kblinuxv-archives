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
import re
from collections import Counter
from pathlib import Path

SOURCE_EXT = {"C", "C++", "Python", "Shell", "Rust", "Go", "Ruby", "Perl", "JavaScript", "Assembly"}
DEFENSIVE = re.compile(r"mitigat|detect|scanner|checker|yara|sigma|snort|suricata|nuclei|ansible|"
                       r"remediat|workaround|patch|fix|rule|hardening|monitor", re.I)
SOURCE_HOSTS = ("github.com", "gitlab.com")


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


def propose_batch(cands: list[dict], vulns: dict, size: int) -> list[dict]:
    """One ready candidate per CVE, round-robin across vulnerability categories."""
    by_cat: dict[str, list[dict]] = {}
    seen = set()
    ranked = sorted((c for c in cands if c["triage"] == "ready"),
                    key=lambda c: ("cve-not-in-url" in c["flags"], c["discovery_class"] != "EXPLOIT_POC", c["language"] not in ("C", "Python"),
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

    batch = propose_batch(cands, vulns, args.batch_size)
    lines = [f"| {c['artifact_id']} | {c['cve']} | {vulns[c['cve']]['category']} | {c['language']} | "
             f"`{c['repository']}` | `{c['filename']}` |" for c in batch]
    (out / "proposed-first-batch.md").write_text(
        "# Proposed first batch\n\nSuggestion only: one ready candidate per CVE, spread across vulnerability "
        "categories, preferring candidates whose URL contains the CVE ID, then `EXPLOIT_POC` in C or Python. Nothing here is approved. To approve, copy chosen "
        "IDs into `acquisition/approved/approved-artifacts.yaml`.\n\n"
        "| Artifact ID | CVE | Category | Language | Repository | File |\n| --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(lines) + "\n")
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
    print(dict(t), f"| proposed batch: {len(batch)}")


if __name__ == "__main__":
    main()
