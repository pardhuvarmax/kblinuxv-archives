# Review sheet, batch 003

Stored (redistributable) artifacts. Unlicensed files are in a separate local-only sheet.

Static facts only. Nothing was compiled or run. Flags are prompts to look closer, not findings. Record your decision
with `kblva review record`; this sheet never changes an artifact's state.

| Artifact | CVE | File | Bytes / lines | Includes | Keywords | Flags |
| --- | --- | --- | --- | --- | --- | --- |
| `LVA-2024-23652-006` | CVE-2024-23652 | `poc.py` | 3984 / 119 | - | - | downloads-code |
| `LVA-2019-13272-001` | CVE-2019-13272 | `CVE-2019-13272.c` | 13520 / 443 | fcntl.h, linux/elf.h, pwd.h, sched.h, signal.h, stdarg.h | clone, execve, ptrace, pipe, fork, cred | destructive-command |
| `LVA-2017-7308-003` | CVE-2017-7308 | `poc.c` | 12905 / 498 | arpa/inet.h, errno.h, fcntl.h, linux/if_packet.h, linux/ip.h, linux/udp.h | socket, mmap, ioctl, unshare, execve, fork, sched_setaffinity, commit_creds | touches-sensitive-files |
| `LVA-2024-0193-004` | CVE-2024-0193 | `poc.py` | 3962 / 119 | - | - | downloads-code |
| `LVA-2021-4034-002` | CVE-2021-4034 | `cve-2021-4034.c` | 292 / 18 | unistd.h | execve | no-cve-id-in-source |
| `LVA-2017-10661-003` | CVE-2017-10661 | `poc.c` | 3009 / 116 | errno.h, fcntl.h, pthread.h, stdint.h, stdio.h, stdlib.h | - | - |
| `LVA-2017-8890-057` | CVE-2017-8890 | `rootz.c` | 65726 / 1986 | arpa/inet.h, dict.h, dirent.h, errno.h, fcntl.h, fn.h | socket, mmap, ioctl, pipe, fork, commit_creds, cred | destructive-command |
| `LVA-2024-23653-004` | CVE-2024-23653 | `poc.py` | 3989 / 119 | - | - | downloads-code |
| `LVA-2022-0185-002` | CVE-2022-0185 | `poc.c` | 846 / 34 | stdio.h, stdlib.h, sys/syscall.h, unistd.h | fsconfig | - |
| `LVA-2022-25636-004` | CVE-2022-25636 | `cve-2022-25636.sh` | 3017 / 89 | - | - | - |
| `LVA-2024-53104-006` | CVE-2024-53104 | `poc.py` | 4057 / 119 | - | - | downloads-code |
