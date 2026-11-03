import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
for sub in ("", "acquisition", "processing"):
    sys.path.insert(0, str(ROOT / "tools" / sub))
from resolve_candidates import match_paths  # noqa: E402
from review_sheet import analyze  # noqa: E402
from run_batch import next_batch_number, select_batch  # noqa: E402


def cand(aid, cve, repo="o/r", name="exploit.c"):
    return {"artifact_id": aid, "cve": cve, "repository": repo, "filename": name, "language": "C", "flags": [],
            "triage": "ready", "discovery_class": "EXPLOIT_POC", "source_url": f"https://github.com/{repo}/blob/{'a'*40}/{name}"}


def test_select_prefers_cves_without_a_stored_artifact_and_skips_done():
    vulns = {c: {"category": "memory-corruption"} for c in ("CVE-1-1", "CVE-2-2")}
    cands = [cand("A-1", "CVE-1-1"), cand("A-2", "CVE-2-2"), cand("A-3", "CVE-2-2", name="poc.c")]
    out = select_batch(cands, vulns, stored_cves={"CVE-1-1"}, done_ids={"A-2"}, size=1)
    assert [c["artifact_id"] for c in out] == ["A-3"]  # fresh CVE first, approved A-2 skipped
    out = select_batch(cands, vulns, stored_cves={"CVE-1-1"}, done_ids={"A-2"}, size=2)
    assert {c["cve"] for c in out} == {"CVE-1-1", "CVE-2-2"}  # tops up from CVEs that already have one


def test_next_batch_number(tmp_path):
    (tmp_path / "acquisition/logs").mkdir(parents=True)
    assert next_batch_number(tmp_path) == "001"
    (tmp_path / "acquisition/logs/acquisition-2026-11-03-001.md").write_text("")
    (tmp_path / "acquisition/logs/acquisition-2026-11-04-002.md").write_text("")
    assert next_batch_number(tmp_path) == "003"


def test_match_paths_finds_cve_in_directory_names_only_for_source_files():
    paths = ["CVE-2022-0847/exp.c", "cve_2022_0847/run.sh", "CVE-2022-0847/bzImage", "other/x.c", "a/b/c/CVE-2022-0847/d.py"]
    assert match_paths(paths, "CVE-2022-0847", 10) == ["CVE-2022-0847/exp.c", "cve_2022_0847/run.sh", "a/b/c/CVE-2022-0847/d.py"]


def test_review_sheet_flags():
    r = analyze('#include <sys/socket.h>\nsystem("rm -rf /tmp/x"); // CVE-2021-1\nint fd = open("/etc/passwd");', "CVE-2021-1")
    assert "destructive-command" in r["flags"] and "touches-sensitive-files" in r["flags"]
    assert "no-cve-id-in-source" not in r["flags"] and "sys/socket.h" in r["includes"] and "socket" in r["keywords"]
    assert "no-cve-id-in-source" in analyze("int main(){}", "CVE-2021-2")["flags"]
