import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools/discovery"))
from normalize import artifact_id, canonical_url, normalize_cve, parse_source  # noqa: E402

SHA = "6d8c93dabf674cea102713781cc534d577412357"


def hit(url, cls="EXPLOIT_POC", cand=True, source="github_code"):
    return {"source": source, "kind": "code", "title": "t", "url": url, "snippet": "",
            "artifact_class": cls, "is_reproduction_candidate": cand}


def test_github_file_is_pinned():
    s = parse_source(f"https://github.com/o/r/blob/{SHA}/a/b.c")
    assert (s["level"], s["repository"], s["commit"], s["path"]) == ("file", "o/r", SHA, "a/b.c")


def test_github_branch_ref_is_not_a_pin():
    assert parse_source("https://github.com/o/r/blob/main/x.py")["commit"] is None


def test_repository_level():
    assert parse_source("https://github.com/o/r")["level"] == "repository"


def test_artifact_id_and_url_key():
    assert artifact_id("CVE-2021-3156", 1) == "LVA-2021-3156-001"
    assert canonical_url("HTTPS://GitHub.com/o/r/") == "https://github.com/o/r"


def test_dedup_merges_refs_and_never_validates():
    entry = {"cve_id": "CVE-2021-3156", "sources": [
        hit("https://github.com/o/r"), hit("https://github.com/o/r/", source="github_repositories"),
        hit("https://example.org/p", cls="PATCH_REFERENCE", cand=False)]}
    vuln, arts = normalize_cve(entry, "snap")
    assert len(arts) == 2 and vuln["reproduction_candidate_count"] == 1
    assert arts[0]["artifact_id"] == "LVA-2021-3156-001" and len(arts[0]["discovery"]["refs"]) == 2
    assert all(a["verification"]["state"] == "DISCOVERED" and not a["verification"]["lab_validated"]
               for a in arts)
