# Research Map -- Browser to Kernel

This document describes the full exploitation chain from the PS5 browser to the kernel, the current status of each stage, and all confirmed bugs.

## Chain Overview

```
Stage 1: WebKit memory corruption        DONE (CVE-2026-43720)
Stage 2: Arbitrary read/write primitive   IN PROGRESS (info leak needed)
Stage 3: Sandbox escape                   Not started
Stage 4: Kernel read/write                Not started
Stage 5: Post-exploitation                Not started
```

## Stage 1: WebKit Memory Corruption -- DONE

**Primary vector: CVE-2026-43720 (Canvas getContext() reentrant UAF)**

`HTMLCanvasElement::getContext()` reads dictionary options via JS property getters BEFORE setting the new context. A re-entrant getter creates a 2d context; the outer `bitmaprenderer` call then replaces it via `unique_ptr` assignment, freeing the 2d context while its JS wrapper survives.

IsoHeap is OFF on PS5 (`WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on FreeBSD/PlayStation). Gigacage also disabled. All WebCore/JSC objects share the same heap.

### Confirmed primitives

| Primitive | Probe | Status |
|-----------|-------|--------|
| UAF trigger (bitmaprenderer outer + 2d inner) | V589 | CONFIRMED |
| Same-type reclaim (500x Canvas2D spray) | V573 | CONFIRMED |
| Bidirectional R/W via alias (all 12 Canvas2D APIs) | V562, V630 | CONFIRMED |
| Crash oracle (forge m_stateStack, lineWidth reads 8B) | V650-V655 | CONFIRMED |
| OOB state stack read (save-count mismatch) | -- | Designed, needs device test |

### Secondary / Blocked leads

**CVE-2026-43715 (CSSFontFace UAF):** UAF write is real and triggers on device but Timer `RELEASE_ASSERT` crashes the process. CSSFontFace is the sole occupant of the 192-byte size class -- no type confusion target. DoS-only.

**tee() private-name inversion:** Writes ReadableStream private slots onto arbitrary objects. Contained by JS builtin wall -- all operations go through `@getByIdDirectPrivate` which returns `undefined` on fake objects. No memory corruption.

**TransformStream disconnect (CVE-2026-43705):** C++ stores attacker streams, JS internals use real ones. Same JS builtin wall. No memory corruption from the disconnect alone.

### Exhausted surfaces (49 investigated, 44 dead)

See [DEAD_ENDS.md](DEAD_ENDS.md) for the full list. Key dead ends:
- MetadataTable overflow: OOM before 38M entries (3.7GB AST needed)
- All 2023-2024 WebKit CVEs: require JIT tiers unavailable on PS5
- ClonedArguments butterfly: conservative GC pins cells
- RAB (all angles): per-element bounds, IDL gate, TOCTOU false positives
- structuredClone: pool roots objects, mismatch fix present
- All WSA-2026-0003/0004 CVEs: 39 audited, all dead

## Stage 2: Arbitrary Read/Write Primitive -- IN PROGRESS

The info leak is the current blocker. We have full R/W of typed Canvas2D state fields through the V573 alias, but no path to read a raw heap pointer -- all APIs return typed JS values.

### Info leak approaches (10+ exhausted)

1. CanvasStyle variant type confusion (chicken-and-egg)
2. WTF::Vector stale data after restore (m_size gates reads)
3. AB zero-init wall (memset(0) on every path)
4. Freed memory read (destructor nulls m_buffer)
5. Butterfly overlap (conservative GC)
6. StructureID confusion (direct pointer, no table)
7. FinReg/WeakRef timing (no pointer in callback)
8. DontInitialize AB paths (all return zeros on device)
9. libpas race CVE-2025-43531 (zero-init blocks data)
10. Canvas backing store (tryFastCalloc zeros)

### Current info leak candidate

**OOB state stack read:** Stale wrapper retains `m_stateStack.m_size = 9` (from 8 saves) while new context has `m_size = 1`. Reading `last()` indexes at `buffer[8]` = 2800 bytes past end of 1-State buffer. Reads adjacent heap as float64. 48-bit x86-64 pointer is exactly representable as IEEE 754 float64.

**APNG overread (V704/V705):** A hidden-default APNG whose first animation frame is narrower than the canvas returns adjacent process bytes through canvas readback. Exact controls and two device loads confirm the disclosure, including aligned heap-shaped values. The source address is decoder-selected; this is not `read64(address)` or an ASLR bypass by itself. See [the device report](reports/APNG_HIDDEN_DEFAULT_DISCLOSURE_1410.md).

### Planned exploitation path (once info leak solved)

1. Leak heap address via OOB state stack read or APNG overread
2. Forge lineDash `Vector<double>` in AB: `m_buffer = target`, `m_capacity = N`, `m_size = N`
3. `setLineDash([v1,...,vN])` through alias -- in-place memcpy to target = arbitrary write
4. `getLineDash()` through alias -- reads from `m_buffer` = arbitrary read
5. Read JSGlobalObject vtable for binary base, find ROP gadgets
6. Vtable hijack or `startOfStructureHeap` overwrite (JSC Config is unfrozen on PS5)
7. ROP chain (x86-64 Zen 2, no PAC, no JIT RWX pages)

### PS5 exploitation environment advantages

- **Gigacage disabled:** AB backing stores share heap with JSC/WebCore objects
- **IsoHeap OFF:** `WTF_MAKE_ISO_ALLOCATED` = standard FastMalloc on PlayStation
- **StructureID no validation:** Pure mask+offset decode, no bounds check in release
- **Config unfrozen:** `disableFreezingForTesting()` -- `startOfStructureHeap` writable
- **Security assertions compiled out:** `ASSERT_WITH_SECURITY_IMPLICATION` = no-op
- **Freed blocks stay mapped:** Virtual memory persists, no in-band freelist

## Stage 3: Sandbox Escape

Not started. Requires arbitrary R/W from Stage 2.

PS5 uses FreeBSD jails for process sandboxing. Candidates:
- **CVE-2025-15547 / CVE-2025-15576:** FreeBSD jail escape. Depends on nullfs availability.
- **Sony syscalls:** sys_532 (OOB, verified 13.60), sys_558 (unchecked index), sys_536 (negative count). Need 14.10 validation.
- **SCM_RIGHTS fd passing:** Potential sandbox boundary crossing via Unix domain sockets.

## Stage 4: Kernel Read/Write

Not started. Requires sandbox escape from Stage 3. See [KERNEL_AUDIT.md](KERNEL_AUDIT.md).

Top candidates:
- **CVE-2026-7270 (execve memmove OOB):** Full exploit published. FreeBSD 11+.
- **CVE-2026-45251 (poll/select UAF):** Full exploit published. All supported FreeBSD.
- **CVE-2024-43102 (UMTX):** Exploited on FW 1.00-7.61. SHM stubbed on 14.10 -- likely dead.

## Stage 5: Post-Exploitation

GPU DMA for SMAP bypass, kernel R/W to full system access. Post-exploit framework (flatz SDK v0.45) has 14.10 kernel offsets for SECURITY_FLAGS, ALLPROC, ROOTVNODE.

Recommended chain:
```
WebKit code execution
    -> userland arb R/W
    -> CVE-2026-7270 or CVE-2026-45251
    -> kernel R/W
    -> GPU DMA for SMAP bypass
```
