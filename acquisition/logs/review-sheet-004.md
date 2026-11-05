# Review sheet, batch 004

Stored (redistributable) artifacts. Unlicensed files are in a separate local-only sheet.

Static facts only. Nothing was compiled or run. Flags are prompts to look closer, not findings. Record your decision
with `kblva review record`; this sheet never changes an artifact's state.

| Artifact | CVE | File | Bytes / lines | Includes | Keywords | Flags |
| --- | --- | --- | --- | --- | --- | --- |
| `LVA-2019-5736-009` | CVE-2019-5736 | `cve-2019-5736.sh` | 3862 / 105 | - | - | - |
| `LVA-2026-31431-180` | CVE-2026-31431 | `CVE-2026-31431.py` | 3597 / 160 | - | socket, pipe, splice | touches-sensitive-files |
| `LVA-2021-26708-003` | CVE-2021-26708 | `cve-2021-26708.c` | 15620 / 547 | fcntl.h, linux/userfaultfd.h, linux/vm_sockets.h, pthread.h, semaphore.h, signal.h | socket, mmap, ioctl, userfaultfd, msgsnd, cred | destructive-command |
| `LVA-2020-16119-003` | CVE-2020-16119 | `poc.c` | 2274 / 90 | fcntl.h, netinet/in.h, pthread.h, stdio.h, stdlib.h, string.h | socket | - |
| `LVA-2022-0492-001` | CVE-2022-0492 | `can-ctr-escape-cve-2022-0492.sh` | 1261 / 35 | - | unshare, namespace, cgroup | destructive-command |
| `LVA-2024-42318-004` | CVE-2024-42318 | `landlock07.c` | 2071 / 99 | landlock_common.h, lapi/keyctl.h, lapi/prctl.h, tst_test.h | keyctl, fork, cred | - |
| `LVA-2026-31635-006` | CVE-2026-31635 | `v12_poc.c` | 1420 / 35 | stdio.h, stdlib.h | - | - |
| `LVA-2024-36971-006` | CVE-2024-36971 | `poc.py` | 3963 / 117 | - | - | downloads-code |
| `LVA-2025-21756-004` | CVE-2025-21756 | `cve-2025-21756.c` | 2328 / 96 | lapi/vm_sockets.h, tst_test.h | socket | - |
| `LVA-2021-3156-006` | CVE-2021-3156 | `cve-2021-3156.sh` | 5261 / 159 | - | - | - |
| `LVA-2026-23415-005` | CVE-2026-23415 | `poc-cve-2026-23415.sh` | 3797 / 181 | - | pipe | touches-sensitive-files |
| `LVA-2026-43499-056` | CVE-2026-43499 | `cve_2026_43499_backend.cpp` | 30830 / 652 | array, attack/ops.hpp, common.h, cstdint, kernel/target.h, kernelsnitch/utils.h | clone, pipe, fork, cred, namespace | no-cve-id-in-source |
| `LVA-2026-46300-004` | CVE-2026-46300 | `check-cve-2026-46300.sh` | 50270 / 1198 | - | socket, pipe, fork, cgroup | destructive-command |
| `LVA-2026-98432-005` | CVE-2026-98432 | `mptcp.go` | 921 / 33 | - | socket | - |
| `LVA-2016-0728-002` | CVE-2016-0728 | `cve-2016-0728.c` | 4331 / 170 | keyutils.h, stdio.h, stdlib.h, string.h, sys/ipc.h, sys/msg.h | msgsnd, keyctl, fork, commit_creds, prepare_kernel_cred, cred | - |
| `LVA-2022-0847-005` | CVE-2022-0847 | `cve-2022-0847.sh` | 3623 / 103 | - | - | - |
| `LVA-2021-4034-005` | CVE-2021-4034 | `cve-2021-4034.sh` | 5917 / 177 | - | fork | - |
| `LVA-2017-10661-007` | CVE-2017-10661 | `main.c` | 1506 / 43 | heapspray_addkey_1.c, poc_10661.h, rop_payload.c, the_use.h, userspace_base_mmap_1.c | - | - |
| `LVA-2017-1000112-004` | CVE-2017-1000112 | `CVE-2017-1000112_container_escape.c` | 26515 / 1016 | assert.h, errno.h, fcntl.h, linux/socket.h, netinet/ip.h, sched.h | socket, mmap, unshare, execve, sched_setaffinity, commit_creds, prepare_kernel_cred, cred | touches-sensitive-files |
