"""Retrieve approved artifacts at their pinned commits and record provenance.

Fetches file bytes only. Nothing retrieved is ever compiled, executed or imported: files are hashed and written
to disk as opaque bytes. Only artifacts listed in acquisition/approved/approved-artifacts.yaml are touched.

    python tools/acquisition/acquire_artifacts.py [--root .] [--batch 001]

Redistribution: a file is stored under corpus/ only when its repository carries an allow-listed open-source
license. Otherwise it is hashed, recorded as reference-only, and written to the git-ignored local-only/ folder
for local research. It never enters git. Repository-level licenses are not proof of the file author's license;
reviewers must confirm.

    python tools/acquisition/acquire_artifacts.py --sync-local

fetches any reference-only artifact missing from local-only/ at its pinned commit and checks its recorded SHA-256.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

import requests
import yaml

MAX_BYTES = 1_000_000
TIMEOUT = 30
ALLOWED_HOSTS = {"github.com": "raw.githubusercontent.com", "gitlab.com": "gitlab.com"}
SPDX_ALLOW = {"MIT", "MIT-0", "ISC", "Unlicense", "CC0-1.0", "0BSD", "Apache-2.0", "BSD-2-Clause",
              "BSD-3-Clause", "MPL-2.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0",
              "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

KERNEL_DIR = {
    "privilege-escalation": "privilege-escalation", "credential-permission-manipulation": "privilege-escalation",
    "memory-corruption": "memory-corruption", "use-after-free": "memory-corruption",
    "race-conditions": "memory-corruption", "filesystem": "filesystem",
    "network-stack-netfilter": "networking", "container-isolation-escape": "linux-kernel",
    "syscall-ioctl-kernel-interface": "linux-kernel", "information-disclosure": "other",
}


class Refused(Exception):
    """A candidate failed a safety check and was not retrieved."""


def corpus_dir(vuln: dict) -> str:
    if (vuln.get("component") or "linux-kernel") != "linux-kernel":
        return "linux-userspace"
    return KERNEL_DIR.get(vuln.get("category") or "", "other")


def parse_pinned(url: str) -> tuple[str, str, str, str]:
    """Return (host, repository, commit, path) for a pinned blob URL, or raise Refused."""
    parts = [p for p in url.split("/") if p]  # scheme:, host, ...
    host = parts[1].lower() if len(parts) > 1 else ""
    if host not in ALLOWED_HOSTS:
        raise Refused(f"host not allowed: {host}")
    rest = parts[2:]
    if host == "github.com":
        if len(rest) < 5 or rest[2] != "blob":
            raise Refused("not a blob URL")
        repo, commit, path = "/".join(rest[:2]), rest[3], "/".join(rest[4:])
    else:
        if "-" not in rest or "blob" not in rest:
            raise Refused("not a blob URL")
        i = rest.index("blob")
        repo, commit, path = "/".join(rest[:rest.index("-")]), rest[i + 1], "/".join(rest[i + 2:])
    if not SHA_RE.match(commit):
        raise Refused("commit is not a pinned 40-hex SHA")
    path = unquote(path)
    if path.startswith("/") or ".." in path.split("/") or "\\" in path or "\x00" in path:
        raise Refused("invalid path")
    return host, repo, commit, path


def raw_url(host: str, repo: str, commit: str, path: str) -> str:
    if host == "github.com":
        return f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(path)}"
    return f"https://gitlab.com/{repo}/-/raw/{commit}/{quote(path)}"


def fetch(url: str) -> bytes:
    """GET without following redirects, with a size cap. Raises Refused on anything unexpected."""
    with requests.get(url, stream=True, allow_redirects=False, timeout=TIMEOUT,
                      headers={"User-Agent": "kb-lva-acquisition"}) as r:
        if r.status_code != 200:
            raise Refused(f"HTTP {r.status_code}")
        buf = bytearray()
        for chunk in r.iter_content(65536):
            buf += chunk
            if len(buf) > MAX_BYTES:
                raise Refused(f"larger than {MAX_BYTES} bytes")
        return bytes(buf)


def repo_license(host: str, repo: str) -> tuple[str | None, str | None]:
    """Repository-level SPDX id and owner login (GitHub only)."""
    if host != "github.com":
        return None, repo.split("/")[0]
    h = {"Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = requests.get(f"https://api.github.com/repos/{repo}", headers=h, timeout=TIMEOUT)
    if r.status_code != 200:
        return None, repo.split("/")[0]
    d = r.json()
    spdx = (d.get("license") or {}).get("spdx_id")
    return (None if spdx in (None, "NOASSERTION") else spdx), d["owner"]["login"]


def local_path(root: Path, cve: str, aid: str, name: str) -> Path:
    return root / "local-only" / cve / aid / name


def sync_local(root: Path) -> int:
    """Fetch recorded reference-only artifacts into local-only/, verifying the recorded hash."""
    prov = [json.loads(x) for x in (root / "metadata/provenance.jsonl").read_text().splitlines()]
    arts = {json.loads(x)["artifact_id"]: json.loads(x)
            for x in (root / "metadata/artifacts.jsonl").read_text().splitlines()}
    bad = 0
    for p in prov:
        a = arts[p["artifact_id"]]
        if a["redistribution"].get("stored_path"):
            continue
        out = local_path(root, a["cve"], p["artifact_id"], Path(p["path"]).name)
        if out.is_file() and hashlib.sha256(out.read_bytes()).hexdigest() == p["sha256"]:
            continue
        try:
            host, repo, commit, path = parse_pinned(p["source_url"])
            data = fetch(raw_url(host, repo, commit, path))
        except (Refused, requests.RequestException) as e:
            print(f"{p['artifact_id']}: REFUSED ({e})")
            bad += 1
            continue
        if hashlib.sha256(data).hexdigest() != p["sha256"]:
            print(f"{p['artifact_id']}: HASH MISMATCH, not saved")
            bad += 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        print(f"{p['artifact_id']}: saved to {out.relative_to(root)}")
    return 1 if bad else 0


def upsert(path: Path, rows: list[dict]) -> None:
    """Replace-by-artifact_id into a JSONL file, keeping it sorted."""
    cur = {}
    if path.is_file():
        cur = {json.loads(x)["artifact_id"]: json.loads(x) for x in path.read_text().splitlines()}
    cur.update({r["artifact_id"]: r for r in rows})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(cur[k]) + "\n" for k in sorted(cur)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--batch", default="001")
    ap.add_argument("--sync-local", action="store_true",
                    help="Only fill local-only/ for recorded reference-only artifacts that are missing locally")
    ap.add_argument("--force", action="store_true", help="Re-retrieve artifacts that are already recorded")
    args = ap.parse_args()
    root = args.root

    if args.sync_local:
        return sync_local(root)
    approved = [a["artifact_id"] for a in yaml.safe_load(
        (root / "acquisition/approved/approved-artifacts.yaml").read_text())["approved_artifacts"] if a.get("approved")]
    arts = {json.loads(x)["artifact_id"]: json.loads(x)
            for x in (root / "discovery/normalized/artifacts.jsonl").read_text().splitlines()}
    vulns = {json.loads(x)["cve"]: json.loads(x)
             for x in (root / "discovery/normalized/vulnerabilities.jsonl").read_text().splitlines()}

    done = set()
    prov_path = root / "metadata/provenance.jsonl"
    if prov_path.is_file() and not args.force:
        done = {json.loads(x)["artifact_id"] for x in prov_path.read_text().splitlines()}
    approved = [a for a in approved if a not in done]

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    meta, prov, verif, lic, sums, log = [], [], [], [], [], []
    for aid in approved:
        rec = arts.get(aid)
        if rec is None:
            log.append((aid, "REFUSED", "unknown artifact ID"))
            continue
        try:
            host, repo, commit, path = parse_pinned(rec["artifact"]["source_url"])
            data = fetch(raw_url(host, repo, commit, path))
            spdx, owner = repo_license(host, repo)
        except (Refused, requests.RequestException) as e:
            log.append((aid, "REFUSED", str(e)))
            continue
        sha = hashlib.sha256(data).hexdigest()
        allowed = spdx in SPDX_ALLOW
        stored = None
        if not allowed:  # no redistributable license: keep a local copy only, git-ignored
            out = local_path(root, rec["cve"], aid, Path(path).name)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        if allowed:
            stored = f"corpus/{corpus_dir(vulns[rec['cve']])}/{rec['cve']}/{aid}/{Path(path).name}"
            out = root / stored
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            sums.append(f"{sha}  {stored}")
        meta.append({**rec, "verification": {"state": "RETRIEVED", "source_reviewed": False,
                                              "lab_validated": False},
                     "redistribution": {"status": "approved" if allowed else "unknown",
                                        "stored_path": stored}})
        prov.append({"artifact_id": aid, "original_author": None, "repository_owner": owner,
                     "license": spdx, "license_scope": "repository-level, not verified for this file",
                     "repository": repo, "commit": commit, "path": path,
                     "source_url": rec["artifact"]["source_url"], "retrieved_at": now,
                     "sha256": sha, "size_bytes": len(data)})
        verif.append({"artifact_id": aid, "state": "RETRIEVED", "source_reviewed": False,
                      "lab_validated": False, "reason": None})
        lic.append({"artifact_id": aid, "license": spdx, "status": "approved" if allowed else "unknown",
                    "stored": bool(stored)})
        log.append((aid, "STORED" if stored else "LOCAL-ONLY",
                    f"{spdx or 'no license'}, {len(data)} bytes, sha256 {sha[:12]}"))

    upsert(root / "metadata/artifacts.jsonl", meta)
    upsert(root / "metadata/provenance.jsonl", prov)
    upsert(root / "metadata/verification.jsonl", verif)
    upsert(root / "metadata/licenses.jsonl", lic)
    sums_path = root / "manifests/SHA256SUMS"
    old = sums_path.read_text().splitlines() if sums_path.is_file() else []
    keep = [x for x in old if x.split("  ", 1)[-1] not in {s.split("  ", 1)[-1] for s in sums}]
    sums_path.parent.mkdir(parents=True, exist_ok=True)
    sums_path.write_text("".join(x + "\n" for x in sorted(keep + sums, key=lambda x: x.split("  ", 1)[-1])))

    lines = "\n".join(f"| {a} | {s} | {d} |" for a, s, d in log)
    report = root / f"acquisition/logs/acquisition-{now[:10]}-{args.batch}.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(f"""# Acquisition batch {args.batch}

Run {now}. Approved: {len(approved)}. Nothing was executed or compiled. All retrieved artifacts are `RETRIEVED`,
not reviewed or validated.

| Artifact | Outcome | Detail |
| --- | --- | --- |
{lines}

`STORED` means the repository's license is on the allow-list and the file is in `corpus/`. `LOCAL-ONLY` means
the license is missing or not allow-listed: the file was hashed and recorded and kept in the git-ignored local-only/ folder.
Licenses are repository-level and must be confirmed per file during review.
""")
    for a, s, d in log:
        print(f"{a}: {s} ({d})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
