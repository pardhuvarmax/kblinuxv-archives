"""Verify stored corpus files against manifests/SHA256SUMS and the recorded provenance.

    python tools/validation/verify_hashes.py [--root .]

Exits non-zero on a missing file, a hash mismatch, or a stored artifact that is not in the manifest.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def verify(root: Path) -> list[str]:
    errors = []
    listed = {}
    manifest = root / "manifests/SHA256SUMS"
    for line in manifest.read_text().splitlines() if manifest.is_file() else []:
        sha, _, rel = line.partition("  ")
        listed[rel] = sha
        f = root / rel
        if not f.is_file():
            errors.append(f"{rel}: listed in SHA256SUMS but missing")
        elif hashlib.sha256(f.read_bytes()).hexdigest() != sha:
            errors.append(f"{rel}: hash mismatch")
    prov = {}
    for path in (root / "metadata/provenance.jsonl",):
        if path.is_file():
            prov = {r["artifact_id"]: r for r in map(json.loads, path.read_text().splitlines())}
    art_path = root / "metadata/artifacts.jsonl"
    for a in map(json.loads, art_path.read_text().splitlines()) if art_path.is_file() else []:
        rel = a.get("redistribution", {}).get("stored_path")
        if not rel:
            continue
        if listed.get(rel) is None:
            errors.append(f"{rel}: stored artifact not in SHA256SUMS")
        elif a["artifact_id"] in prov and prov[a["artifact_id"]]["sha256"] != listed[rel]:
            errors.append(f"{rel}: SHA256SUMS disagrees with provenance")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    errors = verify(ap.parse_args().root)
    for e in errors:
        print(e, file=sys.stderr)
    print("hashes ok" if not errors else f"{len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
