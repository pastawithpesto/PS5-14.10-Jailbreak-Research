# WebKit Crash-Oracle Probe Strategy

Analysis of the optimal search strategy for finding mapped memory in the PS5 FW 14.10 WebKit (WebContent) renderer process, given the crash oracle primitive and 10 observed misses.

**Context:** A crash oracle forges a pointer, reads it as float64 — HIT if mapped (8 bytes of data), MISS if unmapped (SIGSEGV, ~25s restart + spray time). Before each probe, 640MB of ArrayBuffers are sprayed (40×16MB, touching every 16KB page). Total mapped memory ~1040MB with spray.

**Repo constraints used:** No SharedArrayBuffer, No WebAssembly, No WebGL, JIT disabled (LLInt only), 16KB pages, Gigacage disabled, WebKit fork predates Safari 17.0 (Sep 2023 branch).

## ASLR on PS5 FW 14.10

~~Previous version of this document claimed "0 bits mmap ASLR" based on stock FreeBSD 11 not having upstream mmap randomization (kib's r343964 landed in FreeBSD 13, not 11). This was incorrect for the PS5.~~

**Corrected:** Sony added custom ASLR to their FreeBSD 11 fork. Per device measurements from this repo's README:

| Component | Entropy |
|-----------|---------|
| User ASLR | **24 bits** |
| Kernel ASLR | **16 bits** |

Additional findings from ZigZagBoi1's Lua-based research (syscall 674 VM map, syscall 593 dynlib_get_info):
- Code base shifts between runs (observed 0x2393xxxx → 0x2558xxxx), but the **delta is consistent** across all code pointers within a single process — one leaked pointer reveals all module bases.
- Function addresses share a constant upper prefix (0x9FE5) across ASLR'd processes — reduced entropy in the upper bits.
- Per-connection ASLR: the PS5 browser spawns a fresh WebContent process per TCP connection, so each crash re-randomizes the layout.
- Userland ASLR can be fully bypassed from the Lua loader via dynlib_get_info (syscall 593/608/660).

**Implication for blind probing:** With 24-bit user ASLR over 16KB pages, the randomization window is 16KB × 2^24 = **256 GB**. With ~1040MB mapped, P(HIT) ≈ 0.004 per probe. Expected probes to first hit: ~252 (wall time ~1.75 hours). This is marginal but technically feasible for a patient attacker.

Sources: ZigZagBoi1/PS5-14.10-Research FINDINGS.md, CHANGELOG.md; pastawithpesto README.md environment table.

## PS5 WebContent Memory Map — Known Layout from Online Sources

No vendor documentation exists for the PS5 WebContent process memory map. What follows is assembled from community research: ZigZagBoi1's Lua-based VM map dumps (syscall 674), the Lapse/Relapse kernel exploit writeups, Cryptogenic's IPV6 kernel exploit, and WebKit upstream documentation for libpas/bmalloc.

### What syscall 674 reveals (~317 named regions)

ZigZagBoi1 documented syscall 674 returning the full userland VM map with named regions. Key region types observed on FW 14.10:

| Region type | Purpose | Typical size |
|-------------|---------|-------------|
| `SceLibcHeap` | Main libc heap (jemalloc-based) | 64-256 MB |
| `SceLibcMallocManagedMemory` | Secondary managed heap regions | variable |
| `SceKernelFlexibleMemory` | Flexible memory pool (GPU-shared) | variable |
| Code segments | WebKit, libSceCef, libc, libkernel | ~200 MB total |
| Stack | Per-thread stacks | 8 MB each |
| `anon` / unnamed | mmap'd anonymous pages (ArrayBuffer backing stores, libpas pages) | spray-dependent |

The 317 regions span the full userland VA. The WebContent process has a complex layout: WebKit's libpas allocator sits on top of the OS's mmap, and JSC objects, ArrayBuffer backing stores, DOM nodes, and rendering buffers all share the same FastMalloc heap because **Gigacage is disabled** and **IsoHeap compiles to FastMalloc** on PlayStation.

### libpas / bmalloc allocator layout (from WebKit upstream docs)

Per WebKit's libpas documentation and bmalloc source:

| Tier | Object size | Allocator | Page size |
|------|------------|-----------|-----------|
| Segregated | 0-400 bytes | Per-size-class free lists | 16 KB granules |
| Marge bitfit | 400 bytes - 4 MB | Bitmap-based within large pages | 4 MB pages |
| Large / direct | >4 MB | Direct mmap via `tryLargeMemalignVirtual` | OS page (16 KB) |

Upstream WebKit's libpas uses a **128 MB "compact reservation"** for 24-bit compressed pointers to heap metadata objects. Whether Sony's fork preserves this is unconfirmed, but it would appear as a single large anonymous mapping near the heap base.

**ArrayBuffer backing stores >4 MB** (like the 16 MB chunks in the spray) go through `tryLargeMemalignVirtual` → `mmap(MAP_ANON)` with no address hint. The kernel places them via first-fit in the process's free VA space. Sequential 16 MB allocations are typically **contiguous** unless fragmentation intervenes.

### ASLR delta structure (from ZigZagBoi1's measurements)

Cross-run measurements of code base addresses:

```
Run 1: WebKit code base at 0x2393xxxx
Run 2: WebKit code base at 0x2558xxxx
Delta: ~0x1C5xxxx (~29 MB shift)
```

Within a single run, the ASLR delta is **consistent**: all code pointers share the same slide. A function at known offset within libSceWebKit2.sprx retains the upper prefix `0x9FE5` across runs — only the lower bits shift. This means:

1. One leaked code pointer defeats ASLR for all code regions
2. The heap regions may use a different or independent randomization base
3. The relationship between code ASLR slide and heap placement is unknown

### Unconditional userland ASLR bypass (Lua context only)

From the Lua loader (not available from WebKit JS), three syscalls return module base addresses directly:

| Syscall | Name | What it leaks |
|---------|------|---------------|
| 593 | `sys_dynlib_get_info` | Module base, TLS, init/fini |
| 608 | `sys_dynlib_get_info2` | Extended module info |
| 660 | `sys_dynlib_get_info_for_libdbg` | Debug info for all modules |

These are not callable from the WebKit sandbox. If a Lua→WebKit bridge exists (shared file, loopback socket, shared mapping), Lua could supply the full address map. No such bridge has been confirmed on 14.10.

### Known exploit memory layout patterns (from Relapse / Lapse)

The Relapse exploit (FW ≤13.60) and the Lapse kernel exploit (AIO race, documented by MUSIC-ENSEIRB GISTRE) establish the general PS5 exploitation memory model:

- **Relapse Stage 1 (JSC info leak):** Uses a ProxyObject/JSScope mismatch to leak a JSScope pointer → computes WebKit .data base → derives vtable addresses. **Patched on 14.10** (binary fix confirmed by v588).
- **Relapse Stage 2 (arbitrary R/W):** Corrupts ArrayBuffer length via `structuredClone` object pool mismatch → OOB read/write. **Patched on 14.10**.
- **Lapse (kernel):** AF_ROUTE socket KASLR leak → AIO race condition → kernel R/W. Targets the kernel's `sysentvec` to disable sandbox. FW ≤7.61 only.

The methodology is consistent: **info leak → arbitrary R/W → vtable/function pointer hijack → ROP chain → kernel exploit**. The blocker on 14.10 is Step 1 — no working info leak from the WebKit JS context.

### What the 10 missed probes tell us about layout

All 10 probes fell in [0x100000000, 0x2F8000000] (4-12 GB). With 24-bit user ASLR over 16 KB pages, the randomization window is 256 GB. The probes covered only ~5% of the window. The misses are statistically expected (P(all 10 miss) ≈ 0.96).

The spray (40×16 MB = 640 MB via `tryLargeMemalignVirtual`) maps as ~40 contiguous anonymous regions in the process VA, likely above existing heap regions. With the main heap, code, stacks, and libraries, total mapped memory is ~1040 MB — a ~0.4% fill ratio in a 256 GB window.

## The 10 Misses

| Probe | Address | Spray | Result |
|-------|---------|-------|--------|
| 1 | 0x100000000 | No | MISS |
| 2 | 0x180000000 | No | MISS |
| 3 | 0x200000000 | No | MISS |
| 4 | 0x280000000 | No | MISS |
| 5 | 0x2F8000000 | No | MISS |
| 6 | 0x100000000 | 640MB | MISS |
| 7 | 0x200000000 | 640MB | MISS |
| 8 | 0x2F8000000 | 640MB | MISS |
| 9-10 | (assumed in same range) | - | MISS |

All probes fell within 0x100000000 to 0x2F8000000 (~5.2GB window). The spray (640MB) adds ~640MB of contiguous mapped pages. With ~1040MB total mapped footprint, each miss at address X rules out that ANY of the ~1040MB of mapped memory overlaps X. This eliminates the range approximately [0x100000000 - 1GB, 0x2F8000000 + 1GB] ≈ [0x060000000, 0x338000000].

## Question 1: Optimal Single-Probe Strategy (Re-randomizing ASLR)

If ASLR re-randomizes on each WebProcess crash, each probe is independent. The probability of a HIT depends on the ratio of mapped memory to the ASLR window:

```
P(HIT) = mapped_size / aslr_window_size
```

| ASLR entropy (bits over 16KB pages) | Window size | P(HIT) per probe | Expected probes to first HIT | Wall time |
|------|-------------|---------|------|-----------|
| 0 (deterministic) | Fixed | 1.0 (if correct address) | 1 | 25s |
| 16 | 1 GB | 1040MB/1GB ≈ 1.0 | 1 | 25s |
| 20 | 16 GB | 1040/16384 ≈ 0.063 | 16 | 7 min |
| 24 | 256 GB | 1040/262144 ≈ 0.004 | 252 | 1.7 hr |
| 28 | 4 TB | ~0.00025 | 4032 | 28 hr |
| 32 | 64 TB | ~1.5×10⁻⁵ | 64512 | 19 days |
| 36 | full 48-bit | ~7.7×10⁻⁶ | 129024 | 37 days |

**The 10 misses constrain the entropy.** If the spray always lands within a fixed base region and the probes were inside that region, 10 consecutive misses at P=1.0 is impossible. The misses mean either:
- The base moved out of the probed range (deterministic but different base), or
- ASLR entropy is high enough that 10 misses is expected

For re-randomizing ASLR with entropy N bits: P(all 10 miss) = (1 - P(HIT))^10.

| N bits | P(all 10 miss) | Consistent with data? |
|--------|----------------|----------------------|
| 20 | 0.52 | Possible but unlikely |
| 24 | 0.96 | Consistent |
| 28+ | >0.99 | Very consistent |

**If re-randomizing with ≤20 bits:** Probing is feasible. The optimal single-probe address is the CENTER of the ASLR window. Without knowing the window, probe at the most likely base address. On FreeBSD amd64, try the upper VA range where mmap is typically placed on newer kernels.

**If re-randomizing with ≥24 bits:** Blind probing is infeasible (hundreds to thousands of 25-second probes). Switch to non-crashing detection (Question 4) or spray optimization (Question 3).

**Optimal single-probe address (re-randomizing, unknown window):** Maximize coverage by probing the address with the highest prior probability of being mapped. Since all probes in [0x100000000, 0x2F8000000] missed, and FreeBSD mmap uses first-fit upward from a base, the best single guess is in the upper VA range. Recommended:

```
0x7F0000000000
```

Rationale: This is near the top of the 47-bit user VA space, where Linux-style mmap placement lands and where Sony may have moved the mmap region for FW 14.10. The stack is near 0x7FFFFFFFFFFF — shared libraries and mmap regions often cluster below it.

## Question 2: Deterministic Layout — What the 10 Misses Rule Out

If ASLR is deterministic (same layout every restart), the 10 misses are definitive evidence. The spray's ~1040MB footprint is NOT anywhere in [0x060000000, 0x338000000].

**The search space is the full 47-bit user VA minus the ruled-out range:**

```
Total:      0x7FFFFFFFFFFF = 128 TB
Ruled out:  ~7.2 GB (0x060000000 to 0x338000000)
Remaining:  ~128 TB - 7.2 GB ≈ 128 TB
```

This is still enormous. Optimal strategy: **logarithmic coverage** — space probes exponentially across the remaining VA space.

**Optimal next-10 probe sequence (deterministic case):**

The idea: place each probe to bisect the largest uncovered interval, weighted by prior probability. Since FreeBSD amd64 typically uses lower VA regions for mmap, weight slightly toward the lower-middle range, but cover the full space.

| # | Address | Region | Rationale |
|---|---------|--------|-----------|
| 1 | 0x800000000 | 32 GB | Just above the ruled-out zone; FreeBSD first-fit typically places mmap here if base moved to 0x400000000+ |
| 2 | 0x7F0000000000 | ~127 TB | Near top of VA; Linux-style mmap region; shared lib area |
| 3 | 0x2000000000 | 128 GB | Log midpoint between 32GB and 1TB |
| 4 | 0x10000000000 | 1 TB | Log midpoint between 128GB and 127TB |
| 5 | 0x100000000000 | 16 TB | Log midpoint between 1TB and 127TB |
| 6 | 0x400000000000 | 64 TB | Upper half of VA space |
| 7 | 0x1000000000 | 64 GB | Fill gap between 32GB and 128GB |
| 8 | 0x8000000000 | 512 GB | Fill gap between 128GB and 1TB |
| 9 | 0x40000000000 | 4 TB | Fill gap between 1TB and 16TB |
| 10 | 0x600000000000 | 96 TB | Fill gap between 64TB and 127TB |

After each HIT: switch to **binary search** within the surrounding ±1GB to map the spray boundaries, then chain the 500 free reads to locate ArrayBuffer headers and JSCell structures.

After each MISS: each miss rules out ~1GB of the remaining search space. Update the search and bisect the largest remaining interval.

## Question 3: Forcing Predictable Spray Placement from JavaScript

### 3a. OOM pressure approach

With OOM at ~1200MB and spray at 640MB, the process uses ~1040MB. The kernel has very little VA space flexibility when the process is near OOM. Strategy:

1. Allocate to near-OOM (~1150MB) with diverse object types (ArrayBuffers, strings, ImageData, typed arrays)
2. Free specific allocations to create controlled holes
3. Re-allocate the spray into those holes
4. The spray lands where the freed memory was — which you controlled

**Problem:** Requires knowing where the first allocations landed, which is the original problem. But if the kernel's first-fit algorithm is deterministic, the FIRST allocation always starts at the same base. The trick is to allocate ONE small ArrayBuffer first, corrupt its backing store pointer via the crash oracle, and read it — the data you read back IS the address.

### 3b. Relative spray (best approach for crash oracle)

Instead of finding the spray's absolute address, use the oracle to find ANY mapped page, then use relative offsets:

1. Spray 640MB of ArrayBuffers, each initialized with a unique 8-byte magic pattern
2. On HIT, the float64 read back IS the magic pattern
3. The magic pattern encodes which ArrayBuffer and which offset within it
4. Now you know the absolute address of that specific offset in that specific ArrayBuffer
5. From there, compute the addresses of all other sprayed ArrayBuffers

**This turns one HIT into a complete address map.**

### 3c. Allocation pattern inference

If bmalloc's large allocation path passes no hint to mmap (confirmed in WebKit source — tryLargeMemalignVirtual uses MAP_ANON without MAP_FIXED), the kernel's first-fit algorithm determines placement. On stock FreeBSD 11:

1. The kernel maintains a free-space tree for the process VA
2. First-fit searches upward from the last allocation
3. Sequential large allocations are **contiguous**
4. The base address is deterministic IF there's no mmap ASLR

So: allocate one small ArrayBuffer, corrupt its backing store pointer via the vulnerability (not the crash oracle), read back the pointer value → you have the base address. No crashing needed.

### 3d. Worker heap isolation

Create a Web Worker. If the Worker's heap is in a different VA region than the main thread's, and you can observe which region by testing addresses, you've narrowed the search. Workers share the same process on WebKit, so their allocations go through the same bmalloc. This likely doesn't help.

## Question 4: Non-Crashing Detection Methods

**Constraints that kill most techniques:**
- No SharedArrayBuffer → no high-resolution timer from SAB counter thread
- No WebAssembly → no Wasm trap handler, no Wasm memory probing
- No WebGL → no GPU-based timing
- JIT disabled (LLInt only) → no JIT spray, no JIT-based Spectre gadgets
- performance.now() likely reduced to 1ms resolution (Spectre mitigations)

### 4a. DEAD techniques
| Technique | Why dead |
|-----------|----------|
| SAB counter timer | No SharedArrayBuffer |
| Wasm trap handling | No WebAssembly |
| GPU cache timing | No WebGL |
| JIT spray / Spectre v1 gadget in JIT | JIT disabled |
| Worker crash isolation | Workers share WebProcess; SIGSEGV kills all |

### 4b. POTENTIALLY ALIVE techniques

**Allocation timing inference:**
- Allocate ArrayBuffers of increasing size
- Time each allocation using `Date.now()` (1ms resolution) or `performance.now()`
- If the kernel's first-fit search traverses more free-space tree nodes, allocation takes longer
- Detectable difference: unlikely at 1ms resolution, but possible with statistical averaging over many allocations
- **Verdict: weak but non-crashing. Test with 1000+ allocations and look for bimodal timing.**

**SPOILER (CVE-2019-0162):**
- Leaks physical address bits via memory subsystem contention on Intel
- Works from JavaScript (demonstrated by Gruss et al.)
- PS5 uses AMD Zen 2, NOT Intel — SPOILER is Intel-specific
- **Verdict: DEAD on PS5 (AMD CPU).**

**Transparent Huge Page (THP) first-access timing:**
- First access to a THP takes measurably longer than subsequent accesses
- Could detect whether a page was previously touched
- FreeBSD 11 may not have THP; Sony's fork is unknown
- **Verdict: unlikely but worth one test.**

**Rowhammer / memory subsystem:**
- Zen 2 is resistant to classic Rowhammer
- Not useful for address detection
- **Verdict: DEAD.**

**CSS/DOM timing oracle:**
- Create DOM elements that reference attacker-controlled CSS with `url()` pointing to different addresses
- Monitor rendering timing differences
- Very noisy, probably not measurable at 1ms resolution
- **Verdict: extremely weak, not recommended.**

### 4c. BEST AVAILABLE NON-CRASHING APPROACH

**Use the vulnerability itself, not the crash oracle.**

The MetadataTable overflow (CVE-2026-64784) is confirmed on two 14.10 consoles. This vulnerability corrupts memory ADJACENT to the MetadataTable in the JSC heap. By controlling what objects are adjacent (heap feng shui), you can:

1. Corrupt a JSObject's butterfly pointer or structure ID
2. Create a type confusion that lets you read object internal fields
3. Object internal fields contain POINTERS — this leaks addresses without crashing
4. From one leaked pointer, derive the entire heap layout

**This is how the Relapse exploit works on 13.60 — it doesn't brute-force addresses.** It uses JSC memory corruption to leak pointers, then builds arbitrary R/W from there.

The crash oracle is a fallback primitive. The primary exploit path should use CVE-2026-64784 directly with heap feng shui.

## Question 5: 20 Probe Addresses (Ordered by P(HIT))

Assumptions: deterministic layout (stock FreeBSD 11 behavior), the 10 misses rule out [0x060000000, 0x338000000], spray is 640MB contiguous. All addresses are 16KB-aligned (0x4000 boundary).

### Strategy

Logarithmic coverage of the 47-bit VA space. Probes are spaced at roughly exponential intervals, weighted toward regions where FreeBSD/Orbis is most likely to place mmap:

- **Tier 1 (probes 1-5):** Just above the ruled-out zone and in the upper VA range — highest prior probability
- **Tier 2 (probes 6-10):** Logarithmic fill between Tier 1 probes
- **Tier 3 (probes 11-15):** Secondary fill — covers the middle of the VA space
- **Tier 4 (probes 16-20):** Tertiary fill — completes coverage

| # | Address | ~VA offset | Justification |
|---|---------|-----------|---------------|
| 1 | `0x000800000000` | 32 GB | First unchecked region above ruled-out zone. If Sony moved base to ~0x400000000+, spray lands here. |
| 2 | `0x7F0000000000` | 127.5 TB | Linux-style mmap top. Sony may mirror this for defense-in-depth. Near shared libs and stack. |
| 3 | `0x002000000000` | 128 GB | Log midpoint lower range. FreeBSD first-fit from a ~64GB base reaches here with 640MB spray. |
| 4 | `0x010000000000` | 1 TB | Power-of-2 landmark. Common page table boundary. |
| 5 | `0x000400000000` | 16 GB | Just above the ruled-out zone. If base moved to ~0x340000000, spray reaches here. |
| 6 | `0x100000000000` | 16 TB | Mid VA space. Splits the gap between 1TB and 127TB. |
| 7 | `0x001000000000` | 64 GB | Fills gap between 32GB and 128GB. |
| 8 | `0x008000000000` | 512 GB | Fills gap between 128GB and 1TB. |
| 9 | `0x400000000000` | 64 TB | Upper quarter of VA space. |
| 10 | `0x040000000000` | 4 TB | Fills gap between 1TB and 16TB. |
| 11 | `0x200000000000` | 32 TB | Splits gap between 16TB and 64TB. |
| 12 | `0x600000000000` | 96 TB | Splits gap between 64TB and 127TB. |
| 13 | `0x004000000000` | 256 GB | Fills gap between 128GB and 512GB. |
| 14 | `0x080000000000` | 8 TB | Fills gap between 4TB and 16TB. |
| 15 | `0x000600000000` | 24 GB | Fills gap between 16GB and 32GB. |
| 16 | `0x020000000000` | 2 TB | Fills gap between 1TB and 4TB. |
| 17 | `0x700000000000` | 112 TB | Fills gap between 96TB and 127TB. |
| 18 | `0x500000000000` | 80 TB | Fills gap between 64TB and 96TB. |
| 19 | `0x300000000000` | 48 TB | Fills gap between 32TB and 64TB. |
| 20 | `0x00C000000000` | 768 GB | Fills gap between 512GB and 1TB. |

### After a HIT

Once any probe returns data instead of crashing:

1. **Identify what you hit:** The float64 value tells you — if it matches a spray magic pattern, you hit the spray. Otherwise you hit code, stack, or a library.
2. **Binary search:** Probe ±1GB from the hit in halving steps to find the spray boundaries.
3. **Chain the 500 reads:** Map the heap structure. Look for:
   - ArrayBuffer headers (bmalloc metadata at chunk start)
   - JSCell headers (structure ID + flags in first 8 bytes)
   - vtable pointers (these leak the executable/library base addresses)
4. **Derive ASLR slide:** Compare leaked vtable pointers against known offsets from the eboot or WebKit library.

## Recommended Approach: Heap Feng Shui > Blind Probing

The crash oracle treats address discovery as a search problem over 128TB. Even with the spray, this is an O(log(128TB/1GB)) = ~17 bisection steps if deterministic, or potentially infeasible if re-randomizing with high entropy.

**The MetadataTable overflow (CVE-2026-64784) offers a fundamentally better path:**

1. **Heap feng shui:** Allocate JSC objects in a controlled pattern so that the MetadataTable overflow corrupts a KNOWN object type at a KNOWN relative offset.
2. **Type confusion:** The corrupted object is read as a different type, exposing internal pointer fields as readable JavaScript values.
3. **Pointer leak:** One leaked pointer breaks ASLR without any crashing.
4. **Arbitrary R/W:** Build fakeobj/addrof primitives from the type confusion → full arbitrary read/write in userland.

This is the established WebKit exploitation methodology (used by Relapse on 13.60, by Safari exploits since iOS 10). It does not require knowing absolute addresses in advance.

**The crash oracle's best use is as a FALLBACK** — if heap feng shui for CVE-2026-64784 proves unreliable, the oracle can verify whether a specific heap layout was achieved before triggering the overflow.

## Cross-Vector Note

The Lua loader (Entry Vector 1) has `sys 674` which returns the full process VM map (317 regions with protections). If there is any way to pass information between the Lua process and the WebKit process — shared files, network loopback, shared memory segments, /dev nodes — the Lua loader could provide the WebKit process's VA layout directly.

Worth investigating: does the PS5 browser share any memory mappings with game processes? Do they share /dev/dmem0? Can a Lua probe write to a file that a WebKit page reads via `file://` or `fetch()`?

## Info Leak Analysis for CVE-2026-43720 — Fresh Routes

The Canvas UAF (CVE-2026-43720) has confirmed same-type reclaim and full bidirectional R/W through 12 Canvas2D APIs. The blocker is an info leak: reading a raw heap pointer as a JavaScript number. **10 dedicated info leak paths have been exhausted** (see DEAD_ENDS.md). Below are routes that remain open or underexplored.

### Route 1: OOB State Stack Read via Save-Count Mismatch (v600 — deployed, awaiting results)

**Status:** Strongest candidate. Deployed as v600, not yet confirmed on device.

The attack: the inner context (freed by the BMR trigger) had N saves, so its `m_stateStack` had `m_size = N+1` with an out-of-line buffer. After same-type reclaim, the new context has `m_size = 1` (just the initial state) with a NEWLY allocated 1-State buffer (400 bytes).

The key question is whether the stale JS wrapper's access to Canvas2D APIs (lineWidth, getLineDash, getTransform) goes through the NEW object's `m_stateStack` or accesses stale offsets.

**Why it might work:** The stale wrapper calls the same C++ methods on the reclaimed slot. If the reclaimed object's State struct occupies memory that PREVIOUSLY held a different object's data (because the 400-byte State buffer was allocated into a freed slot containing pointer data), then `lineWidth` (a double at State offset +48) reads 8 bytes that were part of a freed object — potentially a heap pointer.

**The setup to maximize this:**
1. Before triggering the UAF, allocate many 400-byte objects containing pointers (e.g., JSC objects whose butterfly or structure fields fall at the right offset)
2. Free those objects (GC or explicit)
3. Trigger the UAF + same-type reclaim
4. The new context's State buffer reclaims one of those freed 400-byte slots
5. Read `lineWidth` through the alias — it reads bytes 48-55 of the State, which may contain a stale pointer from the freed object

**libpas behavior:** Freed blocks retain their data (no zeroing, MADV_FREE decommit only reclaims physical pages but leaves VA mapped with stale contents). A 400-byte allocation falls in the **segregated** tier (per-size-class free list). The freed 400-byte objects' slots are reused LIFO. If the State buffer's 400-byte allocation lands in a slot that previously held a JSObject with a pointer at the corresponding offset, `lineWidth` reads that pointer as a float64.

**48-bit AMD64 pointers are exactly representable as float64** (53-bit mantissa covers 48 bits). The read value can be converted back to an integer with no loss.

### Route 2: FreeType measureText() as Info Oracle (p252 — pending device test)

**Status:** Awaiting device confirmation. Strongest non-Canvas-API info leak path.

The FontFace API loads fonts from ArrayBuffer (confirmed working: p161a T13). FreeType parses the font in the same process, in the same FastMalloc heap. If we can craft a font whose `hmtx` (horizontal metrics) table has an out-of-bounds offset, FreeType reads advance widths from adjacent heap memory. `measureText('A')` then returns a width derived from that OOB data.

**The chain:**
1. Craft a TrueType font in JS (ArrayBuffer) with a corrupted `hmtx` table offset (loca entry points past the actual hmtx data)
2. Load via `new FontFace('leak', arrayBuffer)` + `document.fonts.add()`
3. Set the aliased Canvas2D context's font to `'48px leak'`
4. Call `ctx.measureText('A')` — returns TextMetrics with `width` derived from FreeType's computation
5. FreeType's `FT_Get_Advance` reads the glyph's advance width from the offset in `hmtx` — if that offset is OOB, it reads heap data as a uint16 advance width
6. The returned width encodes 16 bits of heap data

**Limitations:**
- Only 16 bits per glyph (advance widths are uint16 in TrueType)
- Need multiple glyphs with different OOB offsets to assemble a full pointer
- p161a T11 confirmed `unitsPerEm=0` is accepted, and T12 confirmed canvas drawing works (311 pixels)
- Font loca OOB was confirmed DEAD by p260 (validated on PS5) — BUT that was for rendering; measureText may take a different code path through FreeType

**Workaround for loca validation:** Instead of corrupting `loca`, corrupt the `hmtx` table length field in the font's table directory so FreeType believes `hmtx` extends past its actual allocation. FreeType's length check may differ from the rendering validation that blocked p260.

### Route 3: SVG-to-OTF Placeholder Truncation → FreeType Heap Read (p250S — pending)

**Status:** Confirmed alive in STATUS-REPORT-v80.md. Pending device probe.

The SVG font parsing pipeline converts SVG `<font>` definitions to OTF. The Placeholder truncation bug produces a corrupted OTF binary where table offsets point to wrong locations. When FreeType parses this corrupted OTF, it may read from heap memory adjacent to the font buffer.

Combined with the Canvas measureText path:
1. Construct an SVG document containing a `<font>` with crafted glyph definitions designed to trigger the truncation
2. Load via `<style>@font-face { src: url('data:image/svg+xml,...') }</style>` or FontFace API
3. The truncated OTF's `hmtx`/`glyf` table offsets point past the font data into adjacent heap
4. `measureText` or canvas rendering reads from those offsets

This combines two confirmed-alive bugs (SVG font parsing + Placeholder truncation) into an info leak chain.

### Route 4: MetadataTable Golden Primitive (CVE-2026-64784 — alternative vector)

**Status:** Not dead. Detailed in EXPLOIT-PLAN-METADATA-OOB.md. Requires ~38M function compilation.

This is not a Canvas UAF route — it's an independent info leak path that could solve the Canvas UAF's blocker:

**Phase 0 (the golden primitive):**
1. Compile a ~38M function → `finishCreation` OOB writes forward past MetadataTable
2. Groom: spray 300×100096-byte ArrayBuffers, free even-indexed ones, GC, spray Uint8Arrays into holes
3. OOB write corrupts a Uint8Array's `m_length` field to a value that is actually a thunk address (~0x2XXXXXXX, ~700 MB)
4. `ta.length` reads the corrupted length → this IS the ASLR leak (a code pointer readable as a JS number)
5. `ta[16+]` reads past the Uint8Array's backing store into adjacent memory → OOB R/W

**Why this works:** The MetadataTable overflow writes 112-byte `UnlinkedMetadataTable::LinkValueProfile` structs forward from the table. At 38M entries, the overflow reaches ~700 MB past the table base. With heap grooming, this lands on a sprayed Uint8Array. The `m_length` field at the target offset gets overwritten with the address of an internal thunk function.

**OOM concern:** 38M entries × 104 bytes/node = 3.7 GB AST. PS5 OOM at ~1.5 GB. BUT: the MetadataTable itself is much smaller (38M entries × 8 bytes = 304 MB). The 3.7 GB figure is for the AST, not the MetadataTable. If the function can be structured to minimize AST overhead while maximizing MetadataTable entries, it may fit.

**Mitigation note:** This was listed as "DEAD: OOM" in DEAD_ENDS.md for the integer overflow angle. But the golden primitive uses a different mechanism — controlled forward write at compile time, not an integer overflow. The OOM constraint is real but the approach may be viable with careful memory management (allocate, compile, free AST, then groom).

### Route 5: CSSFontFaceSet reference_wrapper Race (p251 — pending device test)

**Status:** Confirmed alive in STATUS-REPORT-v80.md.

`CSSFontFaceSet` uses `std::reference_wrapper<CSSFontFace>` in its face list. If a font face is freed during iteration (via the eager promise path in CVE-2026-43715), the reference wrapper holds a dangling reference. Unlike the CSSFontFace UAF itself (which is blocked by Timer RELEASE_ASSERT), the `CSSFontFaceSet` iteration may access the freed face's fields in a way that doesn't hit the Timer path — potentially reading stale pointer data from a reclaimed slot.

### Route 6: lineDash Vector Buffer as Heap Spray Target

**Status:** Untested. New angle.

`setLineDash()` with a 500-element array allocates a `Vector<double>` buffer of 4000 bytes (500 × 8). This buffer goes through FastMalloc (segregated tier for 4000 bytes). After `restore()`, the Vector shrinks (m_size decrements) but **the buffer is not freed** (confirmed in DEAD_ENDS.md: "removeLast() decrements m_size but never frees buffer").

**The setup:**
1. Through the alias: `save()`, then `setLineDash(Array(500).fill(0))` — allocates 4000-byte Vector buffer A
2. `restore()` — m_size back to 0, but buffer A stays allocated with zeros
3. Through the alias: `save()` again, `setLineDash(Array(500).fill(0))` — may allocate buffer B (new) or reuse A
4. `restore()` — now buffer B (or A) has zeros, m_size=0
5. Repeat N times — creates N orphaned 4000-byte buffers in FastMalloc
6. Free objects of the same size class (JSC objects, strings) whose freed slots contain pointers
7. Through the alias: `save()`, `setLineDash(Array(500).fill(0))` — the Vector allocator MAY reclaim a freed slot that contains stale pointer data
8. The Vector's `memcpy` from the JS array overwrites the buffer... BUT only up to m_size elements. If Vector pre-allocates capacity > m_size, bytes past m_size retain stale data
9. `getLineDash()` reads m_size elements — all zeros. No leak.

**Verdict:** Likely DEAD — the `memcpy` in `setLineDash` writes all m_size × 8 bytes, and `getLineDash` reads only m_size elements. No window to read stale data. Documented here to prevent duplicate effort.

### Route 7: Cross-Process Info Leak via Timing Side-Channel

**Status:** Theoretical. Extremely weak.

If two browser tabs share any microarchitectural state (L3 cache on Zen 2), tab A's memory accesses create cache line evictions observable by tab B via `performance.now()` timing. On AMD Zen 2:

- L3 is shared across cores (16 MB, 16-way associative)
- Cache line = 64 bytes, ~262K lines
- `performance.now()` likely degraded to 1ms (Spectre mitigation)

At 1ms resolution, cache timing attacks require thousands of measurements to distinguish signal from noise. Combined with per-connection ASLR (each tab gets a fresh process), this is impractical.

**Verdict:** DEAD for practical purposes. Only viable if `performance.now()` has better than 100μs resolution on PS5.

### Summary: Priority Order for Info Leak Routes

| Priority | Route | Status | Effort | Expected outcome |
|----------|-------|--------|--------|-----------------|
| **1** | State stack OOB (v600) | Deployed | Low (awaiting device) | Moderate: depends on State buffer heap placement |
| **2** | FreeType measureText (p252) | Pending | Medium (craft font) | High if loca validation is rendering-only |
| **3** | SVG-to-OTF truncation (p250S) | Pending | Medium (craft SVG font) | Moderate: two-bug chain increases complexity |
| **4** | MetadataTable golden (CVE-2026-64784) | Not deployed | High (38M function + groom) | High if OOM can be managed |
| **5** | CSSFontFaceSet race (p251) | Pending | Medium | Low: narrow race window |
| **6** | lineDash Vector buffer | Untested | Low | Very low (memcpy overwrites) |
| **7** | Cross-process timing | Theoretical | High | Near zero |

**Recommendation:** Await v600 device results. In parallel, craft the FreeType measureText font (p252) — this is the most promising non-Canvas info leak because it reads heap data through a completely different code path (C font parser → float width → JS number) that was not covered by the 10 dead Canvas API paths. If both fail, the MetadataTable golden primitive (Route 4) is the strategic fallback — it provides both info leak AND OOB R/W from a single compilation, bypassing the Canvas UAF entirely.

## References

- FreeBSD D5603 (mmap ASLR, landed in FreeBSD 13): reviews.freebsd.org/D5603
- HardenedBSD ASLR: hardenedbsd.org aslr.4
- SPOILER (Intel-specific, dead on AMD): arxiv.org 1903.00446
- Relapse exploit methodology (13.60): AF_ROUTE KASLR + AIO race
- bmalloc tryLargeMemalignVirtual: WebKit source, bmalloc/bmalloc/Heap.cpp
- FreeBSD vm_map_findspace: sys/vm/vm_map.c (first-fit upward, no randomization in 11.x)
- ZigZagBoi1/PS5-14.10-Research: github.com/ZigZagBoi1/PS5-14.10-Research (FINDINGS.md, CHANGELOG.md — syscall 674 VM map, ASLR delta measurements)
- Lapse AIO kernel exploit writeup: blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/
- Cryptogenic PS5-IPV6-Kernel-Exploit: github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
- WebKit libpas documentation: docs.webkit.org/Deep%20Dive/Libpas/Libpas.html
- WebKit libpas internals: github.com/webkit/Documentation/blob/main/docs/Deep%20Dive/Libpas/Internals.md
- PS4 WebKit bugs reference: psdevwiki.com/ps4/WebKit_Bugs
- HackTricks PS5 FreeBSD: hacktricks.wiki/en/binary-exploitation/freebsd-ptrace-rfi-vm_map-prot_exec-bypass-ps5.html
- wooluo ps5-firmware-research: github.com/wooluo/ps5-firmware-research
