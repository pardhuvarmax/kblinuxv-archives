"""Validate JSONL records against schemas/.

    python tools/validation/validate_schema.py [--root .]

Exits non-zero if any record fails.
"""
import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

TARGETS = {
    "discovery/normalized/vulnerabilities.jsonl": "vulnerability",
    "discovery/normalized/artifacts.jsonl": "artifact",
    "metadata/vulnerabilities.jsonl": "vulnerability",
    "metadata/artifacts.jsonl": "artifact",
    "metadata/provenance.jsonl": "provenance",
    "metadata/verification.jsonl": "verification",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    root = ap.parse_args().root
    failures = 0
    for rel, name in TARGETS.items():
        path = root / rel
        if not path.is_file():
            continue
        validator = Draft202012Validator(json.loads((root / f"schemas/{name}.schema.json").read_text()))
        n = 0
        for i, line in enumerate(path.read_text().splitlines(), 1):
            n += 1
            for err in validator.iter_errors(json.loads(line)):
                failures += 1
                print(f"{rel}:{i}: {err.message}", file=sys.stderr)
        print(f"{rel}: {n} records")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
