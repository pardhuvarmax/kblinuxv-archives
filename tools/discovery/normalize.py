"""Normalize scanner hits into KB-LVA vulnerability and artifact records.

Pure functions only: no network access, and downloaded artifacts are never touched.
"""
import re
from urllib.parse import urlparse

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

TYPE_BY_CLASS = {
    "EXPLOIT_POC": "exploit_poc",
    "CRASH_REPRODUCER": "crash_reproducer",
    "SYZ_REPRODUCER": "kernel_reproducer",
    "PATCH_REFERENCE": "patch_reference",
    "TECHNICAL_ANALYSIS": "technical_analysis",
    "VENDOR_ADVISORY": "vendor_advisory",
}
CLASS_ORDER = list(TYPE_BY_CLASS) + ["CVE_METADATA", "UNRELATED_MATCH"]

LANG_BY_EXT = {
    ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".py": "Python",
    ".sh": "Shell", ".bash": "Shell", ".rs": "Rust", ".go": "Go", ".rb": "Ruby",
    ".pl": "Perl", ".js": "JavaScript", ".md": "Markdown", ".txt": "Text", ".json": "JSON",
    ".yaml": "YAML", ".yml": "YAML", ".asm": "Assembly", ".s": "Assembly",
}


def canonical_url(url: str) -> str:
    """Identity key for deduplication: lowercase host, no fragment, no trailing slash."""
    p = urlparse(url.strip())
    path = p.path.rstrip("/") or "/"
    return f"{p.scheme.lower()}://{p.netloc.lower()}{path}" + (f"?{p.query}" if p.query else "")


def parse_source(url: str) -> dict:
    """Split a source URL into level (file/repository/other), repository, commit and path."""
    p = urlparse(url)
    host = p.netloc.lower()
    parts = [x for x in p.path.split("/") if x]
    out = {"level": "other", "repository": None, "commit": None, "path": None}
    if host in ("github.com", "www.github.com") and len(parts) >= 2:
        out["repository"] = f"{parts[0]}/{parts[1]}"
        if len(parts) >= 5 and parts[2] == "blob":
            out.update(level="file", commit=parts[3] if SHA_RE.match(parts[3]) else None,
                       path="/".join(parts[4:]))
        elif len(parts) >= 4 and parts[2] == "commit":
            out.update(level="commit", commit=parts[3] if SHA_RE.match(parts[3]) else None)
        elif len(parts) == 2:
            out["level"] = "repository"
    elif host == "gitlab.com" and len(parts) >= 2:
        if "-" in parts and "blob" in parts:
            i = parts.index("blob")
            out.update(level="file", repository="/".join(parts[:parts.index("-")]),
                       commit=parts[i + 1] if i + 1 < len(parts) and SHA_RE.match(parts[i + 1]) else None,
                       path="/".join(parts[i + 2:]))
        elif "-" not in parts:
            out.update(level="repository", repository="/".join(parts))
    return out


def language_of(path: str | None) -> str | None:
    if not path or "." not in path.rsplit("/", 1)[-1]:
        return None
    return LANG_BY_EXT.get("." + path.rsplit(".", 1)[-1].lower())


def artifact_id(cve: str, seq: int) -> str:
    m = CVE_RE.match(cve)
    return f"LVA-{m.group(1)}-{m.group(2)}-{seq:03d}"


def best_class(classes: set[str]) -> str:
    return min(classes, key=CLASS_ORDER.index)


def normalize_cve(entry: dict, known_ids: dict[str, str] | None = None) -> tuple[dict, list[dict]]:
    """Return (vulnerability record, artifact records) for one scanner CVE entry.

    Every hit in `entry["sources"]` carries a `_snapshot` tag. `known_ids` maps canonical URL to an
    artifact ID issued by an earlier import: those IDs are kept, and new URLs get the next free
    sequence number, so an ID never changes once issued.
    """
    cve = entry["cve_id"].upper()
    known_ids = known_ids or {}
    groups: dict[str, list[dict]] = {}
    for hit in entry.get("sources", []):
        groups.setdefault(canonical_url(hit["url"]), []).append(hit)

    drafts = []
    for key, hits in groups.items():
        cls = best_class({h["artifact_class"] for h in hits})
        drafts.append((CLASS_ORDER.index(cls), key, cls, hits))
    drafts.sort(key=lambda d: (d[0], d[1]))

    next_seq = 1 + max((int(i.rsplit("-", 1)[1]) for i in known_ids.values()), default=0)
    ids = {}
    for _, key, _, _ in drafts:
        if key in known_ids:
            ids[key] = known_ids[key]
        else:
            ids[key] = artifact_id(cve, next_seq)
            next_seq += 1
    drafts.sort(key=lambda d: ids[d[1]])

    artifacts = []
    for _, key, cls, hits in drafts:
        src = parse_source(hits[0]["url"])
        snaps = sorted({h["_snapshot"] for h in hits})
        artifacts.append({
            "artifact_id": ids[key],
            "cve": cve,
            "artifact": {
                "type": TYPE_BY_CLASS.get(cls, "other"),
                "filename": src["path"].rsplit("/", 1)[-1] if src["path"] else None,
                "language": language_of(src["path"]),
                "source_url": hits[0]["url"],
                "repository": src["repository"],
                "commit": src["commit"],
            },
            "discovery": {
                "class": cls,
                "level": src["level"],
                "is_reproduction_candidate": any(h["is_reproduction_candidate"] for h in hits),
                "snapshots": snaps,
                "refs": [{"source": h["source"], "kind": h["kind"], "title": h["title"],
                          "snippet": h.get("snippet", ""), "snapshot": h["_snapshot"]} for h in hits],
            },
            "verification": {"state": "DISCOVERED", "source_reviewed": False, "lab_validated": False},
            "redistribution": {"status": "pending"},
        })

    vuln = {
        "cve": cve,
        "component": entry.get("component") or None,
        "subsystem": entry.get("subsystem") or None,
        "category": entry.get("class") or None,
        "severity": entry.get("severity") or None,
        "snapshots": sorted({h["_snapshot"] for h in entry.get("sources", [])} or {entry["_snapshot"]}),
        "artifact_count": len(artifacts),
        "reproduction_candidate_count": sum(a["discovery"]["is_reproduction_candidate"] for a in artifacts),
    }
    return vuln, artifacts
