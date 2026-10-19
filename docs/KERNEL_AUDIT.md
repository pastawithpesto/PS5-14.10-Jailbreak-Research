# Kernel Audit

PS5 14.10 runs a FreeBSD 11 fork (r230171). All kernel candidates require WebKit code execution and sandbox escape first.

## Tier 1 -- High Priority

### CVE-2026-7270: execve memmove Out-of-Bounds Write

Present since FreeBSD 11 (2013). The `execve` system call computes a `memmove` length from user-controlled argv/envp data without proper bounds checking, producing an out-of-bounds write. A full exploit has been publicly released. It requires an adapted exec target on PS5 because sshd is not available. Local access only.

### CVE-2026-45251: poll/select Use-After-Free

Affects all supported FreeBSD versions. A race condition between `close()` on a file descriptor and a concurrent `poll` or `select` wakeup on the same descriptor allows the wakeup path to access the freed file structure. A full exploit has been publicly released. Exploitation on PS5 depends on whether `pdfork()` is available inside the WebContent sandbox.

### CVE-2024-43102: UMTX Use-After-Free (CVSS 10)

This bug was already exploited on older PS5 firmware (1.00 through 7.61) by prior jailbreak efforts. A full chain exists.

**Patch status on 14.10 is open, not "likely patched".** The umtx evidence correction in [ZigZagBoi1/PS5-14.10-Research PR #41](https://github.com/ZigZagBoi1/PS5-14.10-Research/pull/41) ([evidence note](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/UMTX_454_EVIDENCE.md)) shows that every earlier "umtx" test on 14.10 was issued against syscall **557** (`namedobj_create` in the 13.60 sysent capture) — not `_umtx_op` (454). The only saved executions of 454 on 14.10 are two calls in probe 56i2 (ops 5 and 21, both `ret=0`, op 5 writing a TID-shaped owner word), so the syscall is alive and behaves like `_umtx_op`. `UMTX_OP_SHM` (op 25) and `UMTX_OP_ROBUST_LISTS` (op 26) have never been exercised on 454, and FreeBSD reads their key/params pointer from `uaddr1` — a layout no earlier probe used. Reachability probe 110a (correct-layout SHM create/lookup/alive/destroy cycle) is prepared and awaiting a device run in that repo.

## Tier 2 -- Medium Priority

### CVE-2025-15547 / CVE-2025-15576: FreeBSD Jail Escapes

PS5 uses FreeBSD jails for process sandboxing. These CVEs allow escaping jail confinement. Exploitation depends on whether nullfs is available on PS5.

### CVE-2020-7460: sendmsg 32-bit TOCTOU

Affects FreeBSD 11, but it is old and Sony may have backported the fix. A race condition in `sendmsg` with the 32-bit compatibility layer allows a time-of-check-time-of-use attack.

## Sony-Specific Syscall Bugs

Found during binary analysis of PS5 firmware 13.60. All need validation on firmware 14.10.

| Syscall | Bug | Status |
|---------|-----|--------|
| sys_532 | Out-of-bounds read | Verified on 13.60, needs 14.10 check |
| sys_558 | Unchecked index | Not yet validated |
| sys_536 | Negative count accepted | Not yet validated |

14.10 syscall availability from a compromised userland process is being mapped live in [ZigZagBoi1/PS5-14.10-Research](https://github.com/ZigZagBoi1/PS5-14.10-Research): its [ATTACK_SURFACE.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/ATTACK_SURFACE.md) records which syscalls work, return -1, or kill the process on 14.10 (233+ probes), and a prepared reachability probe exists for sys 532 (`shm_open2`). Use it as the validation map for this table before writing new probes.

## Not Applicable to PS5

| CVE | Reason |
|-----|--------|
| CVE-2026-45250 (setcred) | Syscall does not exist in FreeBSD 11. |
| CVE-2026-45253 (ptrace PT_SC_REMOTE) | Feature added in 2022, not present in FreeBSD 11. |
| CTL HA RCEs (3 bugs) | Requires a network listener that PS5 does not expose. |
| CVE-2026-4747 (RPCSEC_GSS) | Requires an NFS server. |
| CVE-2026-49413 (Linuxulator) | PS5 has no Linux compatibility layer. |
| CVE-2026-49427 (largepage SHM) | Not present in FreeBSD 11. |
| bhyve escape bugs | PS5 uses Aeolia/Belize hardware, not bhyve. |

## Recommended Chain

```
WebKit code execution
    -> userland arbitrary R/W
    -> CVE-2026-7270 or CVE-2026-45251
    -> kernel R/W
    -> GPU DMA for SMAP bypass
```
