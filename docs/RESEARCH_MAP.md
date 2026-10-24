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

### Best Lead: CVE-2026-43720 (Canvas getContext UAF)

Re-entrant `getContext()` invalidates the inner Canvas2D context while its JS wrapper survives. Same-type live Canvas2D allocation reliably reclaims the 768-byte slot, producing two wrappers over one native context and typed bidirectional state-field access.

This is not arbitrary read/write. All exposed Canvas APIs return typed values; ArrayBuffer storage does not reclaim the object slot, and no raw Vector-header write has been demonstrated. The next required result is either a native-byte disclosure through an integer-preserving JS buffer/String or an independent corruption that can write a pointer/Vector header.

See `CONFIRMED_VULNS.md` section 1 and `DEAD_ENDS.md` "Info Leak Paths".

### Closed lead: CVE-2026-43715 (CSSFontFace UAF)

The CSSFontFace lifetime bug is real, but current device/source evidence limits
it to a synchronous fixed enum write followed by the Timer thread
`RELEASE_ASSERT`. Same-type grooming produces no useful secondary corruption;
other allocation families do not provide a viable 192-byte target. Keep it as
a DoS finding, not the Stage-2 plan.

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

This stage has not been reached. The Canvas UAF supplies a typed state-field alias, but Stage 2 still needs a native-byte disclosure and an independent raw pointer/header write.

The PS5 exploitation environment is highly favorable for this stage. See [EXPLOITATION_ENVIRONMENT.md](EXPLOITATION_ENVIRONMENT.md) for full details. The key properties:

- **Gigacage is disabled, but allocation domains still matter.** This removes one isolation layer; it does not make ArrayBuffer storage interchangeable with every WebCore object slot. In particular, 768-byte ArrayBuffers do not reclaim the Canvas2D slot on the tested Guide build.
- **StructureID has no runtime validation.** A corrupted cell header maps to an arbitrary Structure pointer within 128MB, producing type confusion with no runtime check.
- **Security assertions are compiled out.** `ASSERT_WITH_SECURITY_IMPLICATION` is a no-op on PS5 release builds.
- **Freed-block persistence is size/build dependent.** On the tested 14.10 Guide, a bare stale Canvas2D read dies and ArrayBuffer storage does not reclaim its 768-byte slot. Only same-type live Canvas2D reclaim is confirmed.

The earlier ArrayBuffer-replacement plan is not supported by current device evidence. Stage 2 still requires an independent native-byte disclosure and an independent raw pointer/Vector-header write; the Canvas alias currently exposes typed state fields only.

## Stage 3: Sandbox Escape

This stage has not been started. It requires the arbitrary read/write from Stage 2.

PS5 uses FreeBSD jails for process sandboxing. Candidates:

- **CVE-2025-15547 / CVE-2025-15576:** FreeBSD jail escape vulnerabilities. Depend on whether nullfs is available on PS5.
- **Sony syscall bugs:** sys_532 (OOB, verified on 13.60), sys_558 (unchecked index), sys_536 (negative count). All need validation on firmware 14.10.

The sandbox boundaries (which syscalls are available, jail configuration) have not been mapped yet.

## Stage 4: Kernel Read/Write

This stage has not been started. It requires sandbox escape from Stage 3. Public exploits exist for the top candidates.

See [KERNEL_AUDIT.md](KERNEL_AUDIT.md) for the full audit.

- **CVE-2026-7270 (execve memmove OOB):** Tier 1. Full exploit published. FreeBSD 11+ confirmed.
- **CVE-2026-45251 (poll/select UAF):** Tier 1. Full exploit published. All supported FreeBSD versions.
- **CVE-2024-43102 (UMTX UAF, CVSS 10):** Tier 1. Exploited on older PS5 firmware (1.00-7.61). Likely patched on 14.10.

## Stage 5: Post-Exploitation

GPU DMA for SMAP bypass, providing full system access. This stage has not been researched yet.
