# Research Map -- Browser to Kernel

This document describes the full exploitation chain from the PS5 browser to the kernel, the current status of each stage, and all confirmed bugs.

## Chain Overview

```
Stage 1: WebKit memory corruption        <-- current position
Stage 2: Arbitrary read/write primitive
Stage 3: Sandbox escape
Stage 4: Kernel read/write
Stage 5: Post-exploitation (SMAP bypass via GPU DMA)
```

## Stage 1: WebKit Memory Corruption

The goal of this stage is to trigger a use-after-free or type confusion in WebKit that gives the attacker controlled access to freed or confused C++ object memory.

### Best Lead: CVE-2026-43715 (CSSFontFace UAF)

A use-after-free in `iterateClients()` triggered by a thenable getter on `FontFace.prototype.then`. The getter runs synchronous JavaScript during callback iteration, removes a style element, and forces a layout update. This disconnects a client mid-iteration. The next callback hits the disconnected object.

This is the strongest lead because it is a real C++ UAF with synchronous JavaScript re-entry. It is not blocked by the JS builtin wall that limits the stream-based bugs. Patched upstream, unpatched on PS5 14.10. Device test deployed, awaiting crash confirmation.

See [bugs/cssfontface-uaf.md](bugs/cssfontface-uaf.md).

### Novel Findings (no CVE assigned)

**tee() Private-Name Inversion.** Poison `Array.prototype[Symbol.iterator]` to yield the same object X twice during `rs.tee()`. The engine writes internal private slots onto X. Confirmed live on device. Blocked by the JS builtin wall -- all operations on the confused object go through `@getByIdDirectPrivate`, which returns `undefined` on fake objects.

See [bugs/private-name-inversion.md](bugs/private-name-inversion.md).

**tee() fromObject() Type Confusion.** `InternalReadableStream::fromObject()` wraps any JSObject as an InternalReadableStream with no type check. Attacker substitutes objects via iterator override during `tee()`. Confirmed live on device. Same JS builtin wall limitation.

See [bugs/tee-type-confusion.md](bugs/tee-type-confusion.md).

### Known CVE (unpatched on PS5 14.10)

**CVE-2026-43705 (TransformStream Disconnect).** Sony's custom TransformStream constructor iterates the JavaScript builtin return array twice. An attacker overrides the iterator on the second pass to substitute their own streams. The C++ side stores the attacker's streams while the JavaScript side uses the real streams. Confirmed live on device. No memory corruption from the disconnect alone.

See [bugs/transformstream-disconnect.md](bugs/transformstream-disconnect.md).

### The JS Builtin Wall

All InternalReadableStream operations go through `invokeReadableStreamFunction()` into JavaScript builtins. These builtins access object state via `@getByIdDirectPrivate`, which uses an internal SymbolImpl that is invisible to user JavaScript. On a confused object, these reads return `undefined` rather than accessing C++ memory. This wall blocks exploitation of the tee() and TransformStream bugs at the type confusion level.

### Exhausted Surfaces

Over 20 attack surfaces have been audited across 11+ sessions. All were dead-ended. The key dead ends and their root causes:

- **MetadataTable overflow (CVE-2026-64784):** 4.29GB forward sweep exits mapped virtual memory. Parser OOM at 32% of required entries.
- **All 2023-2024 WebKit CVEs:** Target JIT tiers (DFG, B3, Wasm OMG). None applicable to PS5's LLInt-only execution.
- **ClonedArguments butterfly UAF:** Conservative GC stack scanning keeps the stale butterfly pointer alive. Cannot free it while `copyToArguments` is on the call stack.
- **RAB (all angles):** Per-element `inBounds()` checks, IDL converters reject resizable views, TOCTOU variants are false positives.
- **structuredClone pool mismatch:** Patched on PS5 14.10. The gcBuffer split fix is present.
- **Font loca OOB:** PS5 renderer validates loca offsets. All OOB reads produce notdef fallback glyphs.
- **EventTarget UAF:** `isJSExecutionForbidden()` guard blocks the second handler.
- **sort() detach:** `m_vector` cleared, `m_length` zeroed, all access returns undefined.
- **Yarr lookbehind:** Fixed in WK-1400 at YarrPattern.cpp:1534-1537.
- **BYOB streams:** PS5 14.10 lacks `ReadableStream type:bytes` entirely.

See [ATTACK_SURFACE.md](ATTACK_SURFACE.md) for the full list.

## Stage 2: Arbitrary Read/Write Primitive

This stage has not been reached. It depends on confirming the CVE-2026-43715 crash on device.

The PS5 exploitation environment is highly favorable for this stage. See [EXPLOITATION_ENVIRONMENT.md](EXPLOITATION_ENVIRONMENT.md) for full details. The key properties:

- **Gigacage is disabled.** ArrayBuffer backing stores share the same FastMalloc heap as JSC objects. No address space isolation.
- **StructureID has no runtime validation.** A corrupted cell header maps to an arbitrary Structure pointer within 128MB, producing type confusion with no runtime check.
- **Security assertions are compiled out.** `ASSERT_WITH_SECURITY_IMPLICATION` is a no-op on PS5 release builds.
- **Freed blocks stay mapped.** Heap grooming can replace freed objects with attacker-controlled data.

The planned path: UAF on CSSFontSelector or CSSSegmentedFontFace, heap grooming to replace the freed object with an ArrayBuffer backing store (same heap, same size class), corrupt the StructureID in a JSCell header, trigger type confusion, and build `addrof` and `fakeobj` primitives. A fake JSArray with a controlled butterfly pointer provides arbitrary read/write.

## Stage 3: Sandbox Escape

This stage has not been started. It requires the arbitrary read/write from Stage 2.

PS5 uses FreeBSD jails for process sandboxing. Candidates:

- **CVE-2025-15547 / CVE-2025-15576:** FreeBSD jail escape vulnerabilities. Depend on whether nullfs is available on PS5.
- **Sony syscall bugs:** sys_532 (OOB, verified on 13.60), sys_558 (unchecked index), sys_536 (negative count). All need validation on firmware 14.10.

The sandbox boundaries (which syscalls are available, jail configuration) have not been mapped from the browser process yet. However, syscall availability on 14.10 from a compromised userland process is already mapped in [ZigZagBoi1/PS5-14.10-Research](https://github.com/ZigZagBoi1/PS5-14.10-Research) — its [ATTACK_SURFACE.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/ATTACK_SURFACE.md) covers working/blocked/lethal syscalls across 233+ probes from a game-process Lua loader, which is the closest available proxy for a post-WebKit userland process. Also see its umtx correction (PR #41): `_umtx_op(454)` is alive on 14.10 and `UMTX_OP_SHM` reachability is an open question, directly relevant to the kernel candidates in [KERNEL_AUDIT.md](KERNEL_AUDIT.md).

## Stage 4: Kernel Read/Write

This stage has not been started. It requires sandbox escape from Stage 3. Public exploits exist for the top candidates.

See [KERNEL_AUDIT.md](KERNEL_AUDIT.md) for the full audit.

- **CVE-2026-7270 (execve memmove OOB):** Tier 1. Full exploit published. FreeBSD 11+ confirmed.
- **CVE-2026-45251 (poll/select UAF):** Tier 1. Full exploit published. All supported FreeBSD versions.
- **CVE-2024-43102 (UMTX UAF, CVSS 10):** Tier 1. Exploited on older PS5 firmware (1.00-7.61). Patch status on 14.10 is open: `_umtx_op` (454) is alive, but `UMTX_OP_SHM` was never exercised there — the earlier "umtx" tests hit syscall 557 ([ZigZagBoi1 PR #41](https://github.com/ZigZagBoi1/PS5-14.10-Research/pull/41)).

## Stage 5: Post-Exploitation

GPU DMA for SMAP bypass, providing full system access. This stage has not been researched yet.
