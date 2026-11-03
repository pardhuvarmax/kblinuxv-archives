# KB-AL-150 PoC/source discovery report

- Generated (UTC): 2026-11-03T14:42:34.009234+00:00
- Registry: `registry.yaml`
- CVEs scanned: **148**
- CVEs with any search hit: **148**
- CVEs with no search hits: **0**
- CVEs with a reproduction-candidate lead: **139**
- CVEs without a reproduction-candidate lead: **9**

## The three numbers that matter (read this before the tables below)

Raw hit counts and a single `poc_candidate` flag are not reported as the headline numbers anymore, because they conflate three different research outcomes. This report tracks them separately:

1. **Unique artifacts discovered** (deduplicated repos/commits/files/references): **4447**
2. **Unique reproduction candidates** (artifact_class is EXPLOIT_POC, CRASH_REPRODUCER, or SYZ_REPRODUCER — still unverified leads, not confirmed working code): **617**
3. **Lab-validated reproductions** (independently reviewed and successfully run in an isolated Attack-Lab category-A guest): **0** — always 0 from this script; it never executes anything.

(For reference, raw totals before dedup/classification: 5102 total source hits, 704 reproduction-candidate hits.)

## Hits by source

| Source | Hits |
|---|---:|
| github_code | 3002 |
| github_repositories | 378 |
| gitlab_projects | 35 |
| nvd | 1670 |
| registry_reference | 17 |

## Hits by artifact classification

| Classification | Hits | Counts as reproduction candidate? |
|---|---:|---|
| EXPLOIT_POC | 640 | yes |
| CRASH_REPRODUCER | 21 | yes |
| SYZ_REPRODUCER | 43 | yes |
| PATCH_REFERENCE | 419 | no |
| TECHNICAL_ANALYSIS | 475 | no |
| VENDOR_ADVISORY | 408 | no |
| CVE_METADATA | 3036 | no |
| UNRELATED_MATCH | 60 | no |

## Per-CVE results

| CVE | Subsystem | Any hits | Unique artifacts | Reproduction candidates (unique) | Sources |
|---|---|---:|---:|---:|---|
| CVE-2021-3156 | userspace-setuid-utility | 83 | 73 | 12 | github_code, github_repositories, gitlab_projects |
| CVE-2021-4034 | userspace-setuid-utility | 59 | 45 | 15 | github_code, github_repositories, gitlab_projects |
| CVE-2021-3493 | filesystem | 53 | 37 | 6 | github_code, github_repositories |
| CVE-2024-53104 | usb-video-class-driver | 33 | 29 | 4 | github_code |
| CVE-2025-38352 | posix-cpu-timers | 42 | 29 | 8 | github_code, github_repositories |
| CVE-2022-0185 | filesystem-context | 44 | 40 | 15 | github_code, github_repositories, gitlab_projects |
| CVE-2022-0995 | watch_queue | 31 | 26 | 6 | github_code, github_repositories |
| CVE-2021-22555 | netfilter-x_tables | 52 | 49 | 15 | github_code, github_repositories, gitlab_projects |
| CVE-2023-2124 | xfs | 31 | 19 | 1 | github_code |
| CVE-2024-0582 | io_uring | 32 | 24 | 7 | github_code, github_repositories |
| CVE-2024-53186 | ksmbd | 21 | 20 | 6 | github_code, nvd |
| CVE-2024-50286 | ksmbd | 23 | 22 | 1 | github_code |
| CVE-2025-21967 | ksmbd | 22 | 21 | 2 | github_code |
| CVE-2022-2602 | io_uring | 37 | 27 | 4 | github_code, github_repositories |
| CVE-2016-5195 | memory-management-cow | 172 | 161 | 11 | github_code, github_repositories |
| CVE-2024-35880 | io_uring-kbuf | 22 | 21 | 3 | github_code |
| CVE-2023-1872 | io_uring | 27 | 19 | 1 | github_code |
| CVE-2024-39508 | io-wq | 23 | 18 | 2 | github_code |
| CVE-2022-0847 | pipe-page-cache | 54 | 48 | 7 | github_code, github_repositories |
| CVE-2023-0386 | overlayfs | 49 | 39 | 4 | github_code, github_repositories |
| CVE-2026-80530 | xfs | 23 | 17 | 1 | github_code |
| CVE-2021-47335 | f2fs | 25 | 20 | 5 | github_code, nvd |
| CVE-2024-1086 | netfilter-nf_tables | 57 | 39 | 5 | github_code, github_repositories, gitlab_projects |
| CVE-2023-4244 | netfilter-nf_tables | 30 | 19 | 4 | github_code |
| CVE-2023-5197 | netfilter-nf_tables | 28 | 12 | 3 | github_code |
| CVE-2023-32233 | netfilter-nf_tables | 44 | 32 | 4 | github_code, github_repositories |
| CVE-2026-23111 | netfilter-nf_tables | 52 | 49 | 9 | github_code, github_repositories |
| CVE-2024-21626 | container-runtime | 82 | 74 | 6 | github_code, github_repositories |
| CVE-2019-5736 | container-runtime | 107 | 104 | 13 | github_code, github_repositories |
| CVE-2024-23651 | container-build-tool | 23 | 19 | 3 | github_code |
| CVE-2024-23652 | container-build-tool | 24 | 20 | 4 | github_code |
| CVE-2024-23653 | container-build-tool | 22 | 19 | 4 | github_code |
| CVE-2026-53210 | tee-subsystem | 22 | 21 | 1 | github_code |
| CVE-2023-53059 | cros_ec_chardev | 24 | 23 | 1 | github_code |
| CVE-2018-1000204 | scsi-generic-sg_io | 32 | 29 | 2 | github_code |
| CVE-2013-4515 | beceem-bcm_char_ioctl | 35 | 33 | 0 | none |
| CVE-2010-4077 | tty-serial | 29 | 28 | 5 | github_code |
| CVE-2020-14386 | af_packet | 34 | 34 | 5 | github_code |
| CVE-2022-30594 | ptrace-seccomp | 32 | 29 | 4 | github_code |
| CVE-2023-2163 | ebpf-verifier | 30 | 20 | 3 | github_code |
| CVE-2019-13272 | ptrace | 72 | 63 | 11 | github_code, github_repositories, gitlab_projects |
| CVE-2016-0728 | keyring | 82 | 74 | 15 | github_code, github_repositories |
| CVE-2026-46243 | cifs-client | 73 | 71 | 6 | github_code |
| CVE-2013-1959 | user-namespace | 27 | 24 | 5 | github_code |
| CVE-2021-33909 | seq_file | 47 | 41 | 8 | github_code, github_repositories |
| CVE-2022-0492 | cgroups-v1 | 47 | 40 | 8 | github_code, github_repositories |
| CVE-2024-26890 | bluetooth-btrtl | 23 | 22 | 1 | github_code |
| CVE-2024-46869 | bluetooth | 20 | 18 | 2 | github_code |
| CVE-2020-12352 | bluetooth-hci | 25 | 20 | 4 | github_code |
| CVE-2024-26914 | drm-amd-display | 19 | 19 | 1 | github_code |
| CVE-2017-7308 | af_packet | 40 | 36 | 11 | github_code, github_repositories, gitlab_projects |
| CVE-2025-21756 | vsock | 34 | 27 | 5 | github_code, github_repositories |
| CVE-2025-40248 | vsock | 27 | 25 | 1 | github_code |
| CVE-2017-1000112 | af_packet-udp-fragmentation | 43 | 40 | 14 | github_code, github_repositories, gitlab_projects |
| CVE-2022-2588 | net-sched-route4 | 52 | 40 | 6 | github_code, github_repositories, gitlab_projects |
| CVE-2014-9529 | keyring | 46 | 46 | 0 | none |
| CVE-2021-26708 | vsock | 31 | 29 | 8 | github_code, github_repositories |
| CVE-2021-3609 | can-bcm | 26 | 13 | 2 | github_code |
| CVE-2022-48654 | netfilter-nfnetlink_osf | 22 | 21 | 2 | github_code |
| CVE-2022-25636 | netfilter-nft_fwd_neigh | 33 | 31 | 7 | github_code, github_repositories |
| CVE-2023-54137 | vfio-type1 | 24 | 23 | 1 | github_code |
| CVE-2010-4072 | sysv-shm | 58 | 57 | 1 | github_code |
| CVE-2026-43366 | io_uring | 25 | 24 | 1 | github_code |
| CVE-2023-3389 | io_uring | 29 | 15 | 1 | github_code |
| CVE-2023-2598 | io_uring | 31 | 13 | 2 | github_code, github_repositories |
| CVE-2022-1786 | io_uring | 23 | 22 | 4 | github_code |
| CVE-2023-2236 | io_uring | 29 | 15 | 2 | github_code |
| CVE-2021-3612 | joystick-driver | 31 | 20 | 4 | github_code |
| CVE-2021-31916 | device-mapper-dm-ioctl | 24 | 21 | 3 | github_code |
| CVE-2017-7187 | scsi-generic-sg_ioctl | 28 | 27 | 1 | github_code |
| CVE-2026-72183 | landlock-lsm | 21 | 20 | 0 | none |
| CVE-2021-47128 | bpf-lockdown | 20 | 19 | 2 | github_code |
| CVE-2024-42318 | landlock-lsm | 28 | 23 | 3 | github_code |
| CVE-2025-21830 | landlock-bcachefs | 24 | 23 | 2 | github_code |
| CVE-2026-96812 | container-sandbox-gofer | 16 | 15 | 0 | none |
| CVE-2025-2713 | container-sandbox-runsc | 27 | 15 | 4 | github_code, github_repositories |
| CVE-2016-10124 | container-runtime | 22 | 20 | 1 | github_code |
| CVE-2016-8649 | container-runtime | 23 | 22 | 0 | none |
| CVE-2025-23266 | container-runtime | 26 | 21 | 5 | github_code, github_repositories |
| CVE-2023-4394 | btrfs | 26 | 20 | 2 | github_code |
| CVE-2025-21879 | btrfs | 20 | 19 | 1 | github_code |
| CVE-2019-19377 | btrfs | 25 | 23 | 2 | github_code |
| CVE-2025-38714 | hfsplus | 30 | 27 | 2 | github_code |
| CVE-2023-6932 | ipv4-igmp | 31 | 26 | 2 | github_code |
| CVE-2017-10661 | timerfd | 34 | 34 | 7 | github_code, github_repositories |
| CVE-2026-46300 | xfrm-esp-in-tcp | 91 | 84 | 8 | github_code, github_repositories |
| CVE-2026-31635 | rxgk | 29 | 24 | 6 | github_code |
| CVE-2023-53521 | scsi-ses | 26 | 25 | 1 | github_code |
| CVE-2025-37774 | mm-slab | 20 | 20 | 4 | github_code, nvd |
| CVE-2025-37908 | mm-slab | 21 | 20 | 1 | github_code |
| CVE-2024-1085 | netfilter-nf_tables | 28 | 12 | 3 | github_code |
| CVE-2023-3777 | netfilter-nf_tables | 33 | 20 | 2 | github_code |
| CVE-2026-43198 | tcp-ipv6 | 43 | 41 | 26 | github_code, nvd |
| CVE-2025-38499 | vfs-mount-namespace | 25 | 24 | 2 | github_code |
| CVE-2025-37988 | vfs-mount-namespace | 22 | 21 | 1 | github_code |
| CVE-2022-3567 | ipv6-inet6_dgram_ops | 29 | 16 | 3 | github_code |
| CVE-2025-37947 | ksmbd | 24 | 23 | 4 | github_code |
| CVE-2025-24325 | intel-800-series-ethernet-driver | 17 | 15 | 1 | github_code |
| CVE-2025-40354 | amd-display-driver | 18 | 17 | 1 | github_code |
| CVE-2021-20292 | nouveau-drm | 23 | 19 | 1 | github_code |
| CVE-2023-28410 | i915-drm | 22 | 21 | 1 | github_code |
| CVE-2025-40271 | procfs | 29 | 28 | 5 | github_code |
| CVE-2022-20369 | v4l2-mem2mem | 21 | 17 | 3 | github_code |
| CVE-2025-38226 | v4l2-vivid-test-driver | 28 | 25 | 12 | github_code, nvd |
| CVE-2023-52440 | ksmbd | 23 | 22 | 2 | github_code |
| CVE-2026-31705 | ksmbd | 26 | 25 | 1 | github_code |
| CVE-2026-43185 | ksmbd-smb-direct | 24 | 24 | 1 | github_code |
| CVE-2020-27815 | jfs | 32 | 30 | 2 | github_code |
| CVE-2018-10881 | jfs | 33 | 32 | 16 | github_code, nvd |
| CVE-2015-8961 | ext4-journal | 26 | 24 | 2 | github_code |
| CVE-2024-26594 | unknown-verify-against-nvd | 22 | 21 | 2 | github_code |
| CVE-2025-0927 | hfsplus | 18 | 16 | 2 | github_code |
| CVE-2025-21692 | net-sched-ets | 30 | 27 | 6 | github_code, github_repositories |
| CVE-2025-24486 | intel-700-series-ethernet-driver | 17 | 15 | 1 | github_code |
| CVE-2017-8824 | dccp | 44 | 43 | 4 | github_code |
| CVE-2020-16119 | dccp | 31 | 30 | 5 | github_code |
| CVE-2026-23231 | netfilter-nf_tables | 33 | 27 | 3 | github_code |
| CVE-2026-53218 | netfilter-nft_exthdr | 28 | 28 | 1 | github_code |
| CVE-2024-1753 | container-runtime | 41 | 39 | 2 | github_code |
| CVE-2022-1227 | container-runtime | 23 | 20 | 3 | github_code |
| CVE-2021-3347 | futex | 45 | 27 | 5 | github_code |
| CVE-2014-0205 | futex | 27 | 23 | 4 | nvd |
| CVE-2020-14381 | futex | 22 | 20 | 4 | github_code |
| CVE-2026-23415 | futex-mempolicy | 20 | 18 | 5 | github_code, github_repositories |
| CVE-2026-52973 | futex-vfork | 27 | 27 | 1 | github_code |
| CVE-2026-43499 | rtmutex-futex-requeue | 55 | 43 | 10 | github_code, github_repositories |
| CVE-2021-3847 | overlayfs | 31 | 20 | 3 | github_code |
| CVE-2026-45250 | setcred2-syscall | 23 | 17 | 2 | github_code |
| CVE-2012-2123 | commoncap-cap_bprm_set_creds | 29 | 28 | 0 | none |
| CVE-2026-52995 | rds-sockets | 26 | 25 | 1 | github_code |
| CVE-2026-64553 | psample-netlink | 25 | 25 | 0 | none |
| CVE-2026-43026 | netfilter-ctnetlink | 29 | 28 | 1 | github_code |
| CVE-2023-1073 | hid | 25 | 23 | 2 | github_code |
| CVE-2026-43009 | ebpf-verifier | 24 | 22 | 1 | github_code |
| CVE-2026-31431 | af_alg-crypto-api | 179 | 174 | 16 | github_code, github_repositories, gitlab_projects |
| CVE-2026-43494 | rds-networking | 42 | 38 | 8 | github_code, github_repositories |
| CVE-2024-0193 | netfilter-nft_trans_gc | 27 | 23 | 4 | github_code |
| CVE-2022-34918 | netfilter-nft_set_elem_init | 38 | 37 | 8 | github_code, github_repositories |
| CVE-2026-90203 | squashfs | 25 | 24 | 0 | none |
| CVE-2019-19319 | ext4 | 27 | 26 | 2 | github_code |
| CVE-2025-31133 | container-runtime | 27 | 23 | 6 | github_code, github_repositories |
| CVE-2025-52565 | container-runtime | 30 | 28 | 3 | github_code |
| CVE-2025-52881 | container-runtime | 43 | 42 | 3 | github_code |
| CVE-2026-46319 | net-sched-act_ct | 26 | 25 | 1 | github_code |
| CVE-2024-36971 | net-dst-cache | 31 | 26 | 4 | github_code, github_repositories |
| CVE-2026-46081 | crypto-acomp | 21 | 20 | 1 | github_code |
| CVE-2026-74404 | crypto-ccp | 21 | 20 | 0 | none |
| CVE-2026-43502 | rds-zerocopy | 28 | 28 | 2 | github_code |

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
