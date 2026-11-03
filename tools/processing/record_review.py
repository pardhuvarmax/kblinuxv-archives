"""Record a human source review for an artifact: RETRIEVED -> SOURCE_REVIEWED or REJECTED.

    python tools/processing/record_review.py ARTIFACT_ID --verdict accept --reviewer NAME [--notes TEXT]
    python tools/processing/record_review.py ARTIFACT_ID --verdict reject --reviewer NAME --reason TEXT
    python tools/processing/record_review.py --status

This tool cannot set LAB_VALIDATED: that needs isolated-lab evidence and is a separate process.
Reviewing means you read the source and judged it relevant to the CVE; it never runs the artifact.
"""
import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def jl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()] if path.is_file() else []


def write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def record(root: Path, aid: str, verdict: str, reviewer: str, notes: str | None, reason: str | None) -> str:
    verif = jl(root / "metadata/verification.jsonl")
    arts = jl(root / "metadata/artifacts.jsonl")
    v = next((x for x in verif if x["artifact_id"] == aid), None)
    a = next((x for x in arts if x["artifact_id"] == aid), None)
    if v is None or a is None:
        raise SystemExit(f"{aid}: no retrieved artifact with that ID")
    if v["state"] not in ("RETRIEVED", "SOURCE_REVIEWED", "REJECTED"):
        raise SystemExit(f"{aid}: state {v['state']} cannot be changed by a source review")
    if not reviewer.strip():
        raise SystemExit("a reviewer name is required")
    if verdict == "reject" and not reason:
        raise SystemExit("--reason is required to reject")
    state = "SOURCE_REVIEWED" if verdict == "accept" else "REJECTED"
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    v.update(state=state, source_reviewed=verdict == "accept", reviewer=reviewer, reviewed_at=now,
             notes=notes, reason=reason if verdict == "reject" else None)
    a["verification"].update(state=state, source_reviewed=verdict == "accept")
    write(root / "metadata/verification.jsonl", verif)
    write(root / "metadata/artifacts.jsonl", arts)
    return state


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("artifact_id", nargs="?")
    ap.add_argument("--verdict", choices=["accept", "reject"])
    ap.add_argument("--reviewer")
    ap.add_argument("--notes")
    ap.add_argument("--reason")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--root", type=Path, default=Path("."))
    args = ap.parse_args()
    if args.status:
        for state, n in sorted(Counter(v["state"] for v in jl(args.root / "metadata/verification.jsonl")).items()):
            print(f"{state}: {n}")
        return 0
    if not (args.artifact_id and args.verdict and args.reviewer):
        ap.error("artifact_id, --verdict and --reviewer are required")
    print(f"{args.artifact_id}: {record(args.root, args.artifact_id, args.verdict, args.reviewer, args.notes, args.reason)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
