# discovery/raw/scan-24-new-cves

Full scan (2026-11-03) of 24 CVEs added to the registry after `bsauce/kernel-exploit-factory` turned out to cover
CVEs the first registry lacked. Sources: nvd, github (repositories and code), github_commits, github_tree, gitlab,
lore, kernel_cgit, ubuntu_cve. Metadata only; nothing was downloaded or executed.

CVEs: CVE-2015-8550, CVE-2016-9793, CVE-2017-11176, CVE-2017-16995, CVE-2017-5123, CVE-2017-6074, CVE-2017-8890,
CVE-2018-5333, CVE-2019-15666, CVE-2019-9213, CVE-2020-27194, CVE-2020-8835, CVE-2021-31440, CVE-2021-3490,
CVE-2021-41073, CVE-2021-4154, CVE-2021-42008, CVE-2021-43267, CVE-2022-1015, CVE-2022-2639, CVE-2022-27666,
CVE-2022-32250, CVE-2025-21702, CVE-2026-23271.

| Metric | Value |
| --- | --- |
| CVEs scanned | 24 |
| Raw source hits | 1,302 |
| Unique discovered artifacts | 1,207 |
| Unique reproduction candidates (as reported by the scanner at the time) | 298 |
| Lab-validated reproductions | 0 |

The scanner's 298 counts every file found by the `github_tree` source separately, because its dedup function did not
yet treat that source as repository-level (since fixed). At repository level, as for the initial scan, it is 207.

Candidates are leads, not verified PoCs. Verify files with `sha256sum -c SHA256SUMS`.
