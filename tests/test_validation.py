import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
for sub in ("validation", "processing"):
    sys.path.insert(0, str(ROOT / "tools" / sub))
from check_policy import check  # noqa: E402
from record_review import record  # noqa: E402
from verify_hashes import verify  # noqa: E402

SHA = "a" * 40


def build(tmp_path, state="RETRIEVED", license="MIT", status="approved", stored="corpus/other/CVE-1/A/x.c"):
    (tmp_path / "metadata").mkdir()
    data = b"int main(){}"
    if stored:
        f = tmp_path / stored
        f.parent.mkdir(parents=True)
        f.write_bytes(data)
        (tmp_path / "manifests").mkdir()
        (tmp_path / "manifests/SHA256SUMS").write_text(f"{hashlib.sha256(data).hexdigest()}  {stored}\n")
    rows = {
        "artifacts": {"artifact_id": "LVA-2021-0001-001", "cve": "CVE-2021-0001",
                      "verification": {"state": state, "source_reviewed": False, "lab_validated": False},
                      "redistribution": {"status": status, "stored_path": stored}},
        "provenance": {"artifact_id": "LVA-2021-0001-001", "commit": SHA, "license": license,
                       "sha256": hashlib.sha256(data).hexdigest()},
        "verification": {"artifact_id": "LVA-2021-0001-001", "state": state, "source_reviewed": False,
                         "lab_validated": False},
    }
    for name, row in rows.items():
        (tmp_path / f"metadata/{name}.jsonl").write_text(json.dumps(row) + "\n")
    return tmp_path


def test_clean_fixture_passes(tmp_path):
    root = build(tmp_path)
    assert check(root, tracked=[]) == [] and verify(root) == []


def test_lab_validated_without_evidence_fails(tmp_path):
    root = build(tmp_path, state="LAB_VALIDATED")
    assert any("needs evidence" in e for e in check(root, tracked=[]))


def test_unlicensed_cannot_be_approved_or_stored(tmp_path):
    root = build(tmp_path, license=None)
    assert any("allow-listed" in e for e in check(root, tracked=[]))


def test_local_only_must_not_be_tracked(tmp_path):
    root = build(tmp_path)
    assert any("local-only" in e for e in check(root, tracked=["local-only/CVE-1/x.c"]))


def test_hash_mismatch_detected(tmp_path):
    root = build(tmp_path)
    (root / "corpus/other/CVE-1/A/x.c").write_bytes(b"tampered")
    assert any("mismatch" in e for e in verify(root))


def test_review_accept_reject_and_guards(tmp_path):
    root = build(tmp_path)
    assert record(root, "LVA-2021-0001-001", "accept", "me", "reads as a real PoC", None) == "SOURCE_REVIEWED"
    assert check(root, tracked=[]) == []
    with pytest.raises(SystemExit):
        record(root, "LVA-2021-0001-001", "reject", "me", None, None)  # reject needs a reason
    assert record(root, "LVA-2021-0001-001", "reject", "me", None, "unrelated") == "REJECTED"
    with pytest.raises(SystemExit):
        record(root, "LVA-9999-0001-001", "accept", "me", None, None)  # unknown artifact
