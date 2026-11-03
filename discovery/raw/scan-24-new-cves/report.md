# KB-AL-150 PoC/source discovery report

- Generated (UTC): 2026-11-03T17:57:18.871805+00:00
- Registry: `registry.yaml (subset of entries)`
- CVEs scanned: **24**
- CVEs with any search hit: **24**
- CVEs with no search hits: **0**
- CVEs with a reproduction-candidate lead: **24**
- CVEs without a reproduction-candidate lead: **0**

## The three numbers that matter (read this before the tables below)

Raw hit counts and a single `poc_candidate` flag are not reported as the headline numbers anymore, because they conflate three different research outcomes. This report tracks them separately:

1. **Unique artifacts discovered** (deduplicated repos/commits/files/references): **1207**
2. **Unique reproduction candidates** (artifact_class is EXPLOIT_POC, CRASH_REPRODUCER, or SYZ_REPRODUCER — still unverified leads, not confirmed working code): **298**
3. **Lab-validated reproductions** (independently reviewed and successfully run in an isolated Attack-Lab category-A guest): **0** — always 0 from this script; it never executes anything.

(For reference, raw totals before dedup/classification: 1302 total source hits, 315 reproduction-candidate hits.)

## Hits by source

| Source | Hits |
|---|---:|
| github_code | 499 |
| github_commits | 360 |
| github_repositories | 91 |
| github_tree | 108 |
| gitlab_projects | 2 |
| nvd | 242 |

## Hits by artifact classification

| Classification | Hits | Counts as reproduction candidate? |
|---|---:|---|
| EXPLOIT_POC | 276 | yes |
| CRASH_REPRODUCER | 39 | yes |
| SYZ_REPRODUCER | 0 | yes |
| PATCH_REFERENCE | 398 | no |
| TECHNICAL_ANALYSIS | 92 | no |
| VENDOR_ADVISORY | 49 | no |
| CVE_METADATA | 420 | no |
| UNRELATED_MATCH | 28 | no |

## Per-CVE results

| CVE | Subsystem | Any hits | Unique artifacts | Reproduction candidates (unique) | Sources |
|---|---|---:|---:|---:|---|
| CVE-2015-8550 |  | 48 | 47 | 17 | github_code, github_tree, nvd |
| CVE-2016-9793 |  | 54 | 51 | 23 | github_code, github_tree, gitlab_projects, nvd |
| CVE-2017-11176 |  | 58 | 57 | 14 | github_code, github_repositories, github_tree |
| CVE-2017-16995 |  | 70 | 63 | 15 | github_code, github_repositories, github_tree |
| CVE-2017-5123 |  | 55 | 54 | 16 | github_code, github_repositories, github_tree |
| CVE-2017-6074 |  | 68 | 61 | 11 | github_code, github_repositories, github_tree |
| CVE-2017-8890 |  | 56 | 51 | 9 | github_code, github_repositories, github_tree |
| CVE-2018-5333 |  | 56 | 54 | 28 | github_code, github_commits, github_tree, gitlab_projects, nvd |
| CVE-2019-15666 |  | 46 | 43 | 5 | github_code, github_tree |
| CVE-2019-9213 |  | 67 | 65 | 9 | github_code, github_tree |
| CVE-2020-27194 |  | 44 | 42 | 10 | github_code, github_tree |
| CVE-2020-8835 |  | 58 | 56 | 10 | github_code, github_repositories, github_tree |
| CVE-2021-31440 |  | 43 | 39 | 10 | github_code, github_tree |
| CVE-2021-3490 |  | 62 | 50 | 17 | github_code, github_repositories, github_tree |
| CVE-2021-41073 |  | 57 | 56 | 19 | github_code, github_tree |
| CVE-2021-4154 |  | 51 | 41 | 9 | github_code, github_repositories, github_tree |
| CVE-2021-42008 |  | 44 | 43 | 7 | github_code, github_tree |
| CVE-2021-43267 |  | 42 | 39 | 9 | github_code, github_repositories, github_tree |
| CVE-2022-1015 |  | 61 | 57 | 12 | github_code, github_repositories, github_tree |
| CVE-2022-2639 |  | 43 | 37 | 7 | github_code, github_tree |
| CVE-2022-27666 |  | 57 | 55 | 20 | github_code, github_repositories, github_tree |
| CVE-2022-32250 |  | 63 | 56 | 11 | github_code, github_repositories, github_tree |
| CVE-2025-21702 |  | 54 | 47 | 5 | github_code, github_tree |
| CVE-2026-23271 |  | 45 | 43 | 5 | github_code, github_tree |

## Interpretation

Search results are leads only. `artifact_class` is a heuristic classification over source/URL/title/snippet text — it sorts hits into buckets a human can triage quickly, but it is not a code read. A hit classified EXPLOIT_POC, CRASH_REPRODUCER, or SYZ_REPRODUCER is still just a *candidate*: manually inspect provenance, source code, affected versions, licence, and reproduction prerequisites before moving its `verification_state` past DISCOVERED. PATCH_REFERENCE, TECHNICAL_ANALYSIS, VENDOR_ADVISORY, and CVE_METADATA hits are valuable research context but are not reproduction leads and are excluded from the candidate counts above. This scanner never downloads or executes candidate code, and never sets anything to LAB_VALIDATED.

## Verification state (manual workflow outside this script)

Every hit this script produces starts at `DISCOVERED`. Promoting a specific hit through the remaining states is deliberately a human (or lab) action, not something a discovery scan can claim for itself:

| State | Meaning | Who/what sets it |
|---|---|---|
| DISCOVERED | A search query returned this reference. | This script, always. |
| RETRIEVED | The artifact's actual content was fetched and read. | A reviewer, out of band. |
| SOURCE_REVIEWED | A reviewer read the code/write-up and judged whether it plausibly reproduces the CVE. | A reviewer. |
| LAB_VALIDATED | Independently reproduced in an isolated Attack-Lab category-A guest. | Attack-Lab run, per `docs/development/Attack-LabTest-Suite.md` §5/§6, with written per-CVE authorisation. |
| REJECTED | Reviewed and found to be unrelated, non-functional, or not a reproduction of this CVE. | A reviewer. |

## Recommended discovery strategies added in this revision

- **Filename-based GitHub code search** (`filename:cve-yyyy-nnnnn`): catches exploit scripts named after the CVE that don't repeat the full CVE string inside the file body — a real recall gap in a plain string-match code search.
- **Repository tree scan** (`github_tree`, `--tree-repos`): lists the file tree of known exploit-collection repos and matches the CVE ID in any path segment, catching repos that file CVEs under directories (`CVE-2022-0847/exp.c`) which filename and content search miss.
- **GitHub commit search** (`github_commits`, needs `GITHUB_TOKEN`): finds fixing/referencing commits anywhere on GitHub, not just in repos that also show up in repository/code search.
- **Exploit-DB via its GitHub mirror** (`offensive-security/exploitdb`, scoped code search) instead of scraping exploit-db.com's JS-rendered search page — same source, far more reliable to query.
- **git.kernel.org cgit grep search** (`kernel_cgit`): greps commit messages in `torvalds/linux` and `stable/linux` for the literal CVE ID. High precision — a hit is a real commit, not a keyword proximity guess — and it is the most authoritative patch-reference source available without a kernel.org account.
- **Ubuntu CVE tracker JSON API** (`ubuntu_cve`): adds a maintained distro-level view (patch/release status per package) alongside NVD, per the source list `Attack-LabTest-Suite.md` §4 already recommends (kernel.org, NVD, CISA KEV, Ubuntu/Debian trackers).

### Not added, and why

- **Scraping syzkaller/syzbot's dashboard directly** was considered and deliberately left out: syzbot's bug-list pages don't carry CVE IDs in a stable, scrapeable way, and a brittle scraper would silently rot. Instead, `SYZ_REPRODUCER` classification is applied to hits already returned by GitHub/GitLab/lore search whose title/snippet/path mentions `syzkaller`/`syzbot`/`repro.{c,prog,syz}`. Manually cross-referencing a CVE's fixing commit hash against syzbot's "fixed" bug list remains a recommended manual step for kernel CVEs with no candidate found any other way.
- **Scraping exploit-db.com's own search UI** was replaced by scoping GitHub code search to its GitHub mirror (see above) rather than parsing a JS-rendered page whose markup isn't stable across requests.

## Limitations

- GitHub code search, commit search, and the Exploit-DB-mirror search are only queried when `GITHUB_TOKEN` is set.
- NVD and public search APIs can rate-limit requests; rerun with a larger `--delay` or an `NVD_API_KEY` if errors are reported.
- Search coverage depends on each source's indexing and query behaviour; a zero-hit result means not found by these queries, not that no PoC exists.
- `artifact_class` is a regex/keyword heuristic over title, URL, and snippet text. It will misclassify some hits in both directions (an exploit repo with an unusual description; a mitigation tool that happens to use exploit-sounding language). Treat it as a triage aid, not a verdict.
- This script still never downloads, executes, builds, or modifies anything it finds.
