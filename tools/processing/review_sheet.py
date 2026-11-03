"""Static review aid for retrieved artifacts. Reads source as text; never compiles, imports or runs it.

    python tools/processing/review_sheet.py --batch 003 --ids ID [ID ...] [--root .]

Writes two sheets for the given artifacts:
  acquisition/logs/review-sheet-<batch>.md   stored (redistributable) files only, safe to publish
  local-only/review-sheet-<batch>.md         unlicensed files, git-ignored

The sheet is an aid, not a verdict: it never sets SOURCE_REVIEWED. Record your decision with
tools/processing/record_review.py. It reports facts (size, includes, keywords, red flags), not judgement.
"""
import argparse
import json
import re
import sys
from pathlib import Path

KEYWORDS = ["socket", "bpf", "mmap", "ioctl", "unshare", "clone", "setuid", "execve", "ptrace", "io_uring",
            "nftables", "netlink", "userfaultfd", "msgsnd", "keyctl", "pipe", "splice", "fork", "sched_setaffinity",
            "modprobe_path", "commit_creds", "prepare_kernel_cred", "cred", "namespace", "cgroup", "fsconfig"]
FLAGS = {
    "destructive-command": r"rm\s+-rf|\bmkfs\b|dd\s+if=|/dev/sd[a-z]|\b(shutdown|reboot|halt)\b",
    "downloads-code": r"\b(curl|wget)\b|requests\.get|urllib|urlopen",
    "touches-sensitive-files": r"/etc/passwd|/etc/shadow|crontab|authorized_keys|ld\.so\.preload|/etc/sudoers",
    "embedded-binary-blob": r"(\\x[0-9a-fA-F]{2}){40,}|[A-Za-z0-9+/]{200,}={0,2}",
}


def analyze(text: str, cve: str) -> dict:
    includes = sorted(set(re.findall(r"#\s*include\s*[<\"]([^>\"]+)[>\"]", text)))
    return {
        "lines": text.count("\n") + 1,
        "includes": includes[:12],
        "keywords": [k for k in KEYWORDS if re.search(rf"\b{k}", text)],
        "flags": [n for n, rx in FLAGS.items() if re.search(rx, text)] +
                 ([] if cve.lower() in text.lower() else ["no-cve-id-in-source"]),
    }


def sheet(title: str, rows: list[tuple[dict, dict, dict]], note: str) -> str:
    body = "\n".join(
        f"| `{a['artifact_id']}` | {a['cve']} | `{Path(p['path']).name}` | {p['size_bytes']} / {r['lines']} | "
        f"{', '.join(r['includes'][:6]) or '-'} | {', '.join(r['keywords'][:8]) or '-'} | "
        f"{', '.join(r['flags']) or '-'} |" for a, p, r in rows)
    return f"""# {title}

{note}

Static facts only. Nothing was compiled or run. Flags are prompts to look closer, not findings. Record your decision
with `tools/processing/record_review.py`; this sheet never changes an artifact's state.

| Artifact | CVE | File | Bytes / lines | Includes | Keywords | Flags |
| --- | --- | --- | --- | --- | --- | --- |
{body}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--batch", required=True)
    ap.add_argument("--ids", nargs="+", required=True)
    ap.add_argument("--root", type=Path, default=Path("."))
    args = ap.parse_args()
    root = args.root
    jl = lambda n: {json.loads(x)["artifact_id"]: json.loads(x)  # noqa: E731
                    for x in (root / f"metadata/{n}.jsonl").read_text().splitlines()}
    arts, prov = jl("artifacts"), jl("provenance")
    stored, local = [], []
    for aid in args.ids:
        a, p = arts[aid], prov[aid]
        sp = a["redistribution"].get("stored_path")
        f = root / sp if sp else root / "local-only" / a["cve"] / aid / Path(p["path"]).name
        if not f.is_file():
            continue
        row = (a, p, analyze(f.read_text(errors="replace"), a["cve"]))
        (stored if sp else local).append(row)
    log = root / f"acquisition/logs/review-sheet-{args.batch}.md"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(sheet(f"Review sheet, batch {args.batch}", stored,
                         "Stored (redistributable) artifacts. Unlicensed files are in a separate local-only sheet."))
    if local:
        (root / "local-only").mkdir(exist_ok=True)
        (root / f"local-only/review-sheet-{args.batch}.md").write_text(sheet(
            f"Local review sheet, batch {args.batch}", local,
            "> **LOCAL ONLY.** Unlicensed artifacts; git-ignored. Never commit or share this file."))
    print(f"review sheets: {len(stored)} stored, {len(local)} local-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
