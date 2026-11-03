import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools/acquisition"))
from extract_candidates import triage  # noqa: E402

SHA = "a" * 40


def rec(url, level="file", lang="C", commit=SHA, name="x.c", cve="CVE-2021-3156"):
    return {"cve": cve, "artifact": {"source_url": url, "commit": commit, "language": lang, "filename": name},
            "discovery": {"level": level}}


def test_pinned_source_file_is_ready():
    assert triage(rec(f"https://github.com/o/r/blob/{SHA}/cve-2021-3156.c"))[0] == "ready"


def test_repository_needs_resolution():
    assert triage(rec("https://github.com/o/r", level="repository"))[0] == "needs-resolution"


def test_unpinned_file_needs_resolution():
    assert triage(rec("https://github.com/o/r/blob/main/x.c", commit=None))[0] == "needs-resolution"


def test_markdown_and_defensive_need_review():
    assert triage(rec(f"https://github.com/o/r/blob/{SHA}/a.md", lang="Markdown", name="a.md"))[0] == "needs-review"
    assert triage(rec(f"https://github.com/o/r/blob/{SHA}/mitigate.sh", lang="Shell", name="mitigate.sh"))[0] == "needs-review"


def test_cve_not_in_url_is_flagged_but_stays_ready():
    level, flags = triage(rec(f"https://github.com/o/r/blob/{SHA}/poc.c", name="poc.c"))
    assert level == "ready" and "cve-not-in-url" in flags
