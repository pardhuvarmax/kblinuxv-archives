"""Policy checks for dataset changes. Reads files only; never executes or compiles anything.

    python tools/validation/check_policy.py [--root .]

Enforces: verification states are consistent and evidenced, downloading never implies review or validation,
stored files are small, pinned, allow-licensed and under corpus/, and nothing under local-only/ is tracked by git.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "acquisition"))
from acquire_artifacts import MAX_BYTES, SPDX_ALLOW  # noqa: E402

STATES = {"DISCOVERED", "RETRIEVED", "SOURCE_REVIEWED", "LAB_VALIDATED", "REJECTED"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def jl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()] if path.is_file() else []


def check(root: Path, tracked: list[str] | None = None) -> list[str]:
    errs = []
    arts = {a["artifact_id"]: a for a in jl(root / "metadata/artifacts.jsonl")}
    verif = {v["artifact_id"]: v for v in jl(root / "metadata/verification.jsonl")}
    prov = {p["artifact_id"]: p for p in jl(root / "metadata/provenance.jsonl")}
    for aid, a in arts.items():
        v, p = verif.get(aid), prov.get(aid)
        if v is None:
            errs.append(f"{aid}: no verification record")
            continue
        if v["state"] not in STATES:
            errs.append(f"{aid}: unknown state {v['state']}")
        if v["state"] != a["verification"]["state"]:
            errs.append(f"{aid}: artifacts.jsonl and verification.jsonl disagree on state")
        if v["state"] == "SOURCE_REVIEWED" and not (v.get("reviewer") and v.get("reviewed_at")):
            errs.append(f"{aid}: SOURCE_REVIEWED needs reviewer and reviewed_at")
        if v["state"] == "REJECTED" and not v.get("reason"):
            errs.append(f"{aid}: REJECTED needs a reason")
        if v["state"] == "LAB_VALIDATED" and not v.get("evidence"):
            errs.append(f"{aid}: LAB_VALIDATED needs evidence")
        if v["state"] != "LAB_VALIDATED" and v.get("lab_validated"):
            errs.append(f"{aid}: lab_validated flag set without LAB_VALIDATED state")
        if p is None:
            errs.append(f"{aid}: no provenance record")
            continue
        if not SHA_RE.match(p["commit"] or ""):
            errs.append(f"{aid}: commit is not a pinned SHA")
        rd = a["redistribution"]
        stored = rd.get("stored_path")
        if rd["status"] == "approved":
            if not stored or p["license"] not in SPDX_ALLOW:
                errs.append(f"{aid}: approved needs a stored path and an allow-listed license")
        elif stored:
            errs.append(f"{aid}: stored but redistribution status is {rd['status']}")
        if stored:
            f = root / stored
            if not stored.startswith("corpus/"):
                errs.append(f"{aid}: stored path outside corpus/")
            elif f.is_file() and f.stat().st_size > MAX_BYTES:
                errs.append(f"{aid}: stored file larger than {MAX_BYTES} bytes")
    for aid in list(verif) + list(prov):
        if aid not in arts:
            errs.append(f"{aid}: record without an artifact in artifacts.jsonl")
    if tracked is None:
        try:
            tracked = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True,
                                     check=True).stdout.splitlines()
        except (OSError, subprocess.CalledProcessError):
            tracked = []
    errs += [f"{t}: tracked file under local-only/ (unlicensed artifacts must stay out of git)"
             for t in tracked if t.startswith("local-only/")]
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    errs = check(ap.parse_args().root)
    for e in errs:
        print(e, file=sys.stderr)
    print("policy ok" if not errs else f"{len(errs)} problem(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
