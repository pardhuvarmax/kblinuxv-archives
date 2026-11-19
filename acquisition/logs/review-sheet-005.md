# Review sheet, batch 005

Stored (redistributable) artifacts. Unlicensed files are in a separate local-only sheet.

Static facts only. Nothing was compiled or run. Flags are prompts to look closer, not findings. Record your decision
with `kblva review record`; this sheet never changes an artifact's state.

| Artifact | CVE | File | Bytes / lines | Includes | Keywords | Flags |
| --- | --- | --- | --- | --- | --- | --- |
| `LVA-2022-0492-006` | CVE-2022-0492 | `can-ctr-escape-cve-2022-0492.sh` | 1261 / 35 | - | unshare, namespace, cgroup | destructive-command |
| `LVA-2016-0728-003` | CVE-2016-0728 | `cve-2016-0728.c` | 4500 / 170 | keyutils.h, stdio.h, stdlib.h, string.h, sys/ipc.h, sys/msg.h | msgsnd, keyctl, fork, commit_creds, prepare_kernel_cred, cred | - |
| `LVA-2022-25636-005` | CVE-2022-25636 | `cve-2022-25636.sh` | 3017 / 89 | - | - | - |
| `LVA-2021-26708-005` | CVE-2021-26708 | `lib_cve-2021-26708.c` | 1678 / 90 | linux/vm_sockets.h, stdio.h, stdlib.h, sys/socket.h, unistd.h | socket | - |
| `LVA-2017-1000112-007` | CVE-2017-1000112 | `poc.c` | 22886 / 669 | assert.h, errno.h, fcntl.h, linux/socket.h, netinet/ip.h, sched.h | socket, mmap, unshare, execve, sched_setaffinity, commit_creds, prepare_kernel_cred, cred | touches-sensitive-files |
| `LVA-2017-16995-013` | CVE-2017-16995 | `cve-2017-16995.c` | 13236 / 497 | errno.h, fcntl.h, linux/bpf.h, linux/unistd.h, stdarg.h, stdio.h | socket, bpf, cred | - |
| `LVA-2021-4034-006` | CVE-2021-4034 | `cve-2021-4034.c` | 292 / 18 | unistd.h | execve | no-cve-id-in-source |
| `LVA-2021-41073-005` | CVE-2021-41073 | `hello.c` | 2628 / 108 | assert.h, err.h, errno.h, fcntl.h, fuse.h, stdio.h | bpf, io_uring | - |
| `LVA-2021-3156-001` | CVE-2021-3156 | `hax.c` | 4420 / 159 | ctype.h, stdint.h, stdio.h, stdlib.h, string.h, unistd.h | execve | - |
