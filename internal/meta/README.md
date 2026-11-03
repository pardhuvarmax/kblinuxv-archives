# internal/meta

Builds `metadata/vulnerabilities.jsonl` from the NVD CVE API and the registry for every CVE with a retrieved artifact. Rate-limited by NVD; set `NVD_API_KEY` for a higher limit.
