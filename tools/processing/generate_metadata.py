"""Build metadata/vulnerabilities.jsonl for every CVE that has a retrieved artifact.

Sources: the NVD CVE API (network, rate-limited) and the KB-LVA registry. Metadata only: it never downloads
or runs any artifact.

    python tools/processing/generate_metadata.py [--root .]

Set NVD_API_KEY for a higher rate limit. Existing records are replaced by CVE ID.
"""
import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(cve: str) -> dict | None:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    r = requests.get(NVD, params={"cveId": cve}, headers=headers, timeout=30)
    if r.status_code != 200:
        return None
    vulns = r.json().get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None


def summarize_nvd(c: dict) -> dict:
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = c.get("metrics", {}).get(key)
        if metrics:
            m = sorted(metrics, key=lambda x: x.get("type") != "Primary")[0]
            d = m["cvssData"]
            cvss = {"version": d["version"], "score": d["baseScore"], "vector": d["vectorString"],
                    "severity": d.get("baseSeverity") or m.get("baseSeverity"), "source": m.get("source")}
            break
    cwe = sorted({w["value"] for ws in c.get("weaknesses", []) for w in ws.get("description", [])
                  if w["value"].startswith("CWE-")})
    return {"published": c.get("published"), "last_modified": c.get("lastModified"),
            "status": c.get("vulnStatus"), "description": desc, "cvss": cvss, "cwe": cwe,
            "references": [{"url": r["url"], "tags": r.get("tags", [])} for r in c.get("references", [])]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path("."))
    root = ap.parse_args().root
    cves = sorted({json.loads(x)["cve"] for x in (root / "metadata/artifacts.jsonl").read_text().splitlines()})
    registry = {str(e["cve_id"]).upper(): e for e in yaml.safe_load(
        (root / "discovery/registry/registry.yaml").read_text())["entries"]}
    path = root / "metadata/vulnerabilities.jsonl"
    cur = {json.loads(x)["cve"]: json.loads(x) for x in path.read_text().splitlines()} if path.is_file() else {}
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    for i, cve in enumerate(cves):
        if i:
            time.sleep(0.7 if os.getenv("NVD_API_KEY") else 6.5)
        nvd = fetch_nvd(cve)
        reg = registry.get(cve, {})
        cur[cve] = {
            "cve": cve, "component": reg.get("component"), "subsystem": reg.get("subsystem"),
            "category": reg.get("class"), "severity": reg.get("severity"),
            "registry": {"summary": " ".join(str(reg.get("summary", "")).split()) or None,
                         "affected": reg.get("affected"), "fixed_in": reg.get("fixed_in"),
                         "references": reg.get("references") or []},
            "nvd": summarize_nvd(nvd) if nvd else None,
            "sources": ["kb-lva-registry"] + (["nvd"] if nvd else []), "retrieved_at": now,
        }
        print(cve, "NVD ok" if nvd else "NVD record not found")
    path.write_text("".join(json.dumps(cur[k]) + "\n" for k in sorted(cur)))


if __name__ == "__main__":
    main()
