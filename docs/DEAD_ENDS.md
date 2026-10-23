# Dead-End Investigations

Comprehensive list of all investigated attack vectors confirmed dead on PS5 firmware 14.10. Documented to prevent duplicate effort.

All investigations were performed against retail PS5 hardware running firmware 14.10, targeting the built-in browser (Safari 17.0 / WebKit-1400, LLInt-only, no JIT).

---

## JSC / JavaScript Engine

### MetadataTable Integer Overflow (Bug 317632) — DEAD: OOM

38M entries x 104 bytes/node = 3.7 GB AST needed. PS5 WebContent OOM-kills at ~1.5 GB.

Mathematically impossible within PS5 memory limits. ThrowableExpressionData adds 36 bytes per call node, and no opcode can overflow within available memory. The `.length=81400` and `.length=79600` results were false positives (correct literal lengths: 817-char or 796-char chunks x 100). Inner function CodeBlocks are created lazily at first call, so the sweep never ran without an IIFE wrapper.

### ClonedArguments Butterfly UAF — DEAD: Conservative GC

All 9 bypass angles exhausted. Conservative GC scanning pins butterfly memory.

Conservative GC rooting blocks all butterfly reclaim strategies. The GC scans the stack conservatively and will pin any cell that looks like a heap pointer, preventing reuse of freed butterfly storage. Confirmed with V240/V241 (CORRUPT-0 result).

### DirectArguments OOB Write — DEAD: Bounds Check

`isMappedArgument(i)` checks `i < m_length` before `setIndexQuickly`.

Both the interpreter path and DFG path (irrelevant on PS5 anyway) perform bounds checking. No path from JavaScript to write past the mapped arguments boundary.

### sort() Detach UAF — DEAD: Cleared

On detach: `m_vector` cleared, `m_length` zeroed. All access returns `undefined`.

Device-confirmed with V422. TypedArray sort with concurrent detach is fully handled.

### Yarr C3 Position Corruption — DEAD: Match Failure

1-unit displacement always causes match failure, not exploitable state.

The corruption affects the pattern matcher's position tracking, but the resulting mismatch causes the regex engine to report "no match" rather than producing corrupted output that could be leveraged.

### Yarr Lookbehind Forward Reference — DEAD: Fixed in WK-1400

`{0}` quantification cleanup fixed at YarrPattern.cpp:1534-1537.

The bug allowed a forward reference inside a lookbehind to skip quantification cleanup, but WK-1400 contains the fix.

### structuredClone Re-entry — DEAD: Pool Roots Objects

`m_objectPool` roots all objects during serialization. No re-entry possible.

The serialization pool maintains strong references to all objects being cloned, preventing GC collection during the operation.

### structuredClone Pool Mismatch — DEAD: Fix Present

V287 confirmed gcBuffer split fix present on PS5 14.10 binary.

The pool mismatch vulnerability (where serialization and deserialization could reference different buffer pools) has been patched.

### structuredCloneForStream OOB — DEAD: Zero-Fill

V330 stale metadata confirmed on device but mmap zero-fill blocks info leak.

The stale metadata is real but newly mapped pages are zero-filled by the kernel, preventing information disclosure. V345 confirmed proper bounds checking on the JS `.length` property.

### ProxyObject JSScope Leak — DEAD: Binary Fix

14.10 has binary-level fix. Receiver is constructor, not JSScope.

The Relapse Stage-1 primitive. 54/54 attempts fail deterministically on 14.10. The binary contains a fix that ensures the receiver object is the constructor rather than leaking the JSScope chain.

### jsCast Unchecked Paths — SAFE: All Type-Guarded

Complete audit of all unchecked `jsCast<>` in JSC runtime.

Every unchecked jsCast is preceded by a C++ type check (@isRegExpObject, @isMap, etc.). No exploitable type confusion reachable from JavaScript.

---

## Streams API

### tee() Type Confusion — DEAD: JS Builtin Wall

Private-name inversion confirmed. BUT all operations go through JS builtins.

Can write ReadableStream private slots onto arbitrary objects via yielding the same object twice to tee(). However, ALL InternalReadableStream operations dispatch through `invokeReadableStreamFunction` to JS builtins, which call proper methods on the target. No direct C++ field access bypasses this wall.

### tee() OOB Read — DEAD: CrashOnOverflow

`Vector::at()` has CrashOnOverflow bounds check that kills the process before stale pointer access.

Device-confirmed with V438b: crashes were CrashOnOverflow trap (process termination), not exploitable stale pointer dereferences. AB cross-pollution approach also dead because it was premised on the OOB read.

### Stream Tee OOB via RAB Resize — DEAD: Bounds Checks

Per-element `inBounds()` checks `bufferByteLength`. IDL converters reject RAB views.

All WebCore APIs reject resizable views at `toWrapped()`, and the stream internals perform per-element bounds checking.

### BYOB Stream Prototype Poison — DEAD: No BYOB

PS5 14.10 lacks `ReadableStream` type:bytes entirely.

The `ReadableByteStreamController` and BYOB reader are not available. Device fingerprint confirms this.

---

## RAB (ResizableArrayBuffer)

### RAB TOCTOU (set/clone/copyWithin) — DEAD: Per-Element Bounds

`set()` has per-element `inBounds`. `copyWithin` bounded by `maxByteLength`. `structuredClone` within bounds.

V416 was a false positive (signed/unsigned comparison bug in analysis, not in WebKit). V418 showed zero corruption. V419 detach is caught.

### RAB byteLength Inversion — DEAD: Sinks Guarded

Inverted OOB check in byteLength getter is real but all downstream sinks have correct guards.

The inversion allows a view to report an incorrect byte length, but every consumer that uses this value performs its own bounds checking.

### RAB IDL Gate — SAFE

ALL WebCore APIs reject resizable views at `toWrapped()`. Only `structuredCloneForStream` bypasses this gate, and that path is separately bounded.

---

## DOM / Rendering

### CSSFontFace UAF (CVE-2026-43715) — DEAD: DoS-Only

UAF exists but free and use are synchronous. All grooming fails.

Eager promise + setProperty adopt path writes `m_status 0x03` to freed FastMalloc memory. However, no JS re-entry window exists between free and use. The 192-byte size class contains only CSSFontFace — no type confusion target. All spray strategies (AB, string, Blob) fail. Confirmed DoS-only with p504.

### Canvas getContext() UAF (CVE-2026-43720) — ~~DEAD~~ ALIVE: IsoHeap is OFF on PS5

**RETRACTED.** IsoHeap (`WTF_MAKE_ISO_ALLOCATED`) compiles to standard FastMalloc on FreeBSD/PlayStation. Confirmed by `BPLATFORM(PLAYSTATION)` in BPlatform.h:341 and Synacktiv writeup. Same-type reclaim, AB reclaim, and bidirectional R/W all CONFIRMED WORKING on device. See CONFIRMED_VULNS.md #1.

### OffscreenCanvas getContext() — DEAD: API Missing

Identical reentrant pattern at OffscreenCanvas.cpp:243-263. IsoHeap is actually OFF (see Canvas UAF retraction), but `OffscreenCanvas` constructor is `undefined` on PS5 14.10 — API completely absent.

### EventTarget UAF — DEAD: isJSExecutionForbidden

Guard blocks second handler execution. Document never freed during dispatch.

`isJSExecutionForbidden()` prevents handler re-entry in the critical window. V405 confirmed on device.

### XMLParser Custom Element UAF — DEAD: Fragment Guard

Line 810: `!m_parsingFragment` skips CE check. `innerHTML` cannot trigger.

The XMLParser custom element instantiation path is guarded by a fragment-parsing check. Since innerHTML uses fragment parsing, it cannot reach the vulnerable code. XHTML iframes are dead on PS5. Main-frame XHTML requires specific content-type serving.

### Font loca OOB — DEAD: Validated on PS5

PS5 renderer validates loca table offsets. All OOB produce notdef fallback glyph.

Device-confirmed with V260. The PS5 font renderer (possibly Sony-specific) performs offset validation that upstream WebKit may not.

### BMP OOB Read — DEAD: Fixed

V400 and V402 returned fill values instead of leaked memory.

PS5 binary has the fix or uses a different BMP decoding codepath.

### Popover API Re-entrancy — MOOT: Not Available

Popover API not available on PS5 14.10.

No `popoverAttribute`, `showPopover`, or `ToggleEvent`. Analysis showed the pattern is safe anyway (EventDispatcher Ref + validity rechecks).

### Clipboard Iterator UAF — DEAD: No Clipboard

Clipboard API not available on PS5 despite `isSecure:true`.

CVE-2026-43727 clearItemTypeLoaders invalidation requires SecureContext + user gesture, but the API itself is absent.

### NodeIterator Adoption — SAFE: RefPtr

All 5 tests passed. `RefPtr` keeps nodes alive through adoption, GC, removal.

---

## CVE Audit

### CVE-2023-42917 — DEAD: Patched

Fix present in WK-1400 Structure.cpp:917-933.

### All 2023-2024 WebKit CVEs — DEAD: JIT-Dependent

Every CVE from this period targets DFG, FTL, or B3 JIT tiers.

These tiers are completely unavailable on PS5 (LLInt-only execution).

### All WSA-2026-0003/0004 CVEs — DEAD

39 CVEs audited individually. All require WASM, JIT, WebGL, or user-interaction APIs not available on PS5.

### MSE SourceBuffer Re-entrancy — SAFE

All events use `queueTaskToDispatchEvent` (async delivery).

Device-confirmed: re-entrant append, SourceBuffer removal during callback, ArrayBuffer detach after append — all handled correctly.

---

## Kernel / Syscall (from browser context)

### UMTX CVE-2024-43102 — DEAD: SHM Stubbed

Sony removed shared memory subsystem on firmware 14.10.

The `USHMF_LINKED` single flag check is impossible because the SHM syscalls are stubbed. PS5Dev/PS5-UMTX-Jailbreak covers FW up to 13.60 only. Our probe 10 used the wrong syscall number, confirming the stub.

### AutoFillButtonElement Raw m_owner& — DEAD: InjectedBundle Only

Same unfixed raw `AutoFillButtonOwner& m_owner` pattern as CVE-64783 DataListButtonElement. But `setShowAutoFillButton()` is only callable from `InjectedBundleNodeHandle.cpp:319` — a native C++ API requiring browser chrome code execution. No JS/HTML/CSS path creates an AutoFillButton. SpinButton has the same pattern but is protected by `removeSpinButtonOwner()` in `destroyShadowSubtree()`.

### Relapse Scope Leak — DEAD: Binary Fix on 14.10

ALL Relapse Stage-1 scope leak variants tested (V588): direct `leakScopeObject()`, eval variant, 5 `super` sub-tests. All return `undefined` on PS5 14.10. Binary-level fix present.

### RAB Bugs 312513 + 285876 — DEAD: Mitigated

V563 confirmed both mitigated on PS5 14.10. `grow()` zeros new bytes. No info leak.

### WebGL readPixels Uninit Leak — DEAD: No WebGL

`readPixelsForPaintResults` has no error check → `toDataURL` could leak heap on GL failure. But `WebGLRenderingContext` constructor is absent on PS5 14.10 (V566: `WebGL=NO`). Unreachable.

### SVG Filter Integer Overflow — DEAD: All Paths Checked

`CheckedUint32` overflow detection, `RELEASE_ASSERT`, 4096 dimension clamp, and NaN→empty result. All four SVG filter overflow angles are mitigated.

### CVE-2026-64783 — DataListButtonElement UAF — DEAD: No Datalist on PS5

**Bug 313521.** `DataListButtonElement::defaultEventHandler()` holds raw `DataListButtonOwner& m_owner`. Changing `<input>` type inside click handler frees `TextFieldInputType` while event dispatch is in progress. Fixed in commit `be08720593` (WeakPtr + removeOwner).

**Why dead:** Requires `<input type="text" list="...">` with a visible datalist dropdown button, plus user click interaction on that button. PS5 Guide browser has no datalist UI. Even if it did, exploitation requires TextFieldInputType-sized heap spray and user interaction timing — not viable from automated JS.

**WSA-2026-0005 advisory, CVSS 8.8.** Fixed in Safari 26.6 / WebKitGTK 2.52.6.

### Kernel Probes (CVE-2026-49418, CVE-2026-7270, poll/select UAF) — BLOCKED

All require code execution outside browser sandbox. Unreachable from JavaScript.

CVE-2026-49418 (msync device-pager UAF), CVE-2026-7270 (execve memmove OOB), and the poll/select race condition all need native syscall access that the browser sandbox restricts.

### Sony Crash Tests — DEAD: Harness-Only

54 `[Crash]` tests in PS5 TestExpectations all require `testRunner` or `UIHelper` APIs.

None are triggerable from the browser. Mostly UI/viewport tests. The postMessage OOM test was the only interesting candidate but requires the test harness.

---

## Info Leak Paths (Canvas UAF Context)

All paths investigated with 13+ independent agent audits. None produce a raw heap pointer.

### Canvas2D API Surface — DEAD: All Typed Values

V630 confirms ALL 12 Canvas2D APIs work through the V573 alias (lineWidth, miterLimit, globalAlpha, fillStyle, strokeStyle, font, getLineDash, setLineDash, getTransform, createPattern, measureText, save/restore). Every API returns a typed JS value (number, string, or object). No API exposes raw memory.

### CanvasStyle Variant Type Confusion — DEAD: Chicken-and-Egg

std::variant with index byte at State+24. Flipping index 2→1 would reinterpret gradient RefPtr as Color uint64. But changing the index byte requires raw byte access to the State, which requires the info leak this would produce.

### WTF::Vector Stale Data (restore) — DEAD: API-Unreachable

removeLast() decrements m_size but never frees buffer. Stale pointer data SURVIVES in buffer past m_size after restore(). But Vector::size() gates ALL Canvas2D API reads — no API reads past m_size. State copy constructor fully overwrites stale slots on re-save.

### AB Zero-Init Wall — DEAD: All Paths

ArrayBuffer allocation: tryMalloc + memset(0) on every path. Confirmed on device (V566, V641). DontInitialize paths (Blob/Fetch/XHR/Worker segment gaps) also return zeros on PS5 (V641).

### Freed Memory Read — DEAD: Destructor Invalidates

V627 confirms reading through freed Canvas2D context crashes regardless of grooming. The ~CanvasRenderingContext2D destructor runs ~Vector on m_stateStack which calls resetBufferAndCapacity() setting m_buffer=nullptr. state() then dereferences nullptr+offset → SIGSEGV.

### JSC-Level Paths — DEAD: 10 Paths Checked

Butterfly overlap, StructureID confusion, JSFunction pointer leak, structured clone pointer exfiltration, FinalizationRegistry/WeakRef callback timing, stateStack realloc overlap, CanvasStyle forge, AB overlay scan — all confirmed dead. Structure validation present, GC conservative scan blocks all butterfly reclaim.

### DontInitialize AB Paths — DEAD: Zero on Device

Blob segment gap, Worker Float64Array, Fetch response body, XHR response ArrayBuffer — all tested on device (V641). Every path returns zeros. The DontInitialize codepath may not be reachable or the kernel zero-fills the backing pages.

### Legacy ImageData Transfer + History Leak — DEAD: Zero on Device

V661 reproduced the historical `ImageData → postMessage(..., [data.buffer]) → history.state.data.buffer` disclosure shape. The transfer detached the original buffer, and both `replaceState` and `pushState` recreated a 65,536-byte `Uint8ClampedArray`, but every byte was zero (`nz=0`) and no canonical pointer candidates existed.

### libpas CVE-2025-43531 Race — DEAD: Zero-Init Blocks Leak

libpas confirmed on PS5 (BPLATFORM(PLAYSTATION) at BPlatform.h:341). The bmalloc/libpas race condition is theoretically present but zero-init on allocation destroys any stale data that survives the race window.

### MSE buffered() — DEAD: DoS Only

MediaSource.buffered returns a TimeRanges object. Heap layout manipulation via append/remove cycles confirmed but no info leak primitive — only DoS via OOM.

### Canvas Backing Store Uninit — DEAD: tryFastCalloc

Canvas backing store uses tryFastCalloc (calloc = zero-init). Even if freed backing store memory contains pointers, reclaiming it with a new canvas zeros it. getImageData always returns zero-initialized pixel data.

### Truncated PNG Pixel Disclosure — DEAD: Decoder Draws Nothing

V662 tested three malformed/truncated IDAT shapes at 64x64 and 128x64 through both `HTMLImageElement` and `createImageBitmap`, after same-sized heap poisoning. The images report load success, but `drawImage` leaves every prefilled destination pixel untouched: 4,096/4,096 or 8,192/8,192 unchanged, with zero unknown pixels across three device runs. The earlier `PNG-TRUNC-OK` result is permissive load completion, not an uninitialized-pixel disclosure.

### CurlTMServiceRequest URL Over-read — UNREACHABLE in Guide

V663 exercised 42 iframe navigations covering URL canonicalization differences and payload lengths around allocator boundaries from 31 through 1,025 bytes. Every intended request reached the host once with the expected normalized path; there was no internal 302, garbage suffix, crash, or extra request. Although the 14.00 source passes the length-delimited `evalURL` to C-string consumers, the required `WebSecurity` traffic-manager evaluation path is not active/reachable in this Guide session. Do not revisit without first proving `WebSecurity::activatedStatus()` and a non-null `convertUrl()` result.

### V650/V655 Constant-address DASHFORGE — INVALID PREMISE on This Console

Those pages write a forged `m_stateStack.m_buffer` through sprayed 768-byte ArrayBuffers. Device results later proved that ArrayBuffer storage does not reclaim the Canvas2D object slot on this build; only same-type live Canvas2D objects do. V573 exposes typed Canvas properties, not raw header bytes.

`0x1800000..0x18002d0` as "readable/stable zero" is **not** a local result. It came from cobrajet302gt in GitHub issue #11 comment 6356111570 (2026-10-23 02:42Z), describing their separate AB-backed vehicle. On this console that AB(768) path hard-died; the comment is not transferable proof. Immediate blockers are **both** native address disclosure **and** a raw Canvas Vector-header write. A pointer alone does not activate DASHFORGE here. No V674, no scan.

### FastMalloc occupancy via StringImpl 744 / lineDash 96 — DEAD: write oracle cannot tell occupant from unmapped

libpas 16-byte classes: Canvas2D object is 768 B (index 48). Source fit: Latin-1 `StringImpl` length 744 (24+744) and `Vector<double>` of 96 (`setLineDash`). Device: V678 control with **no** extra allocs still ALIAS idx=10. Any intervening index-48 (or even index-46 `repeat(700)`) alloc then canvas spray then stale `lineWidth` store dies with Sony "not enough free system memory" and no POSTWRITE. Same dialog as dangling write. Crash ≠ occupancy. Do not Circle occupancy probes on this oracle.

### TimeRanges / 24 B MediaTime tag-flip — DEAD: wrong size class, no UAF

`TimeRanges` is RefCounted + `PlatformTimeRanges` (a `Vector`) ≈ 32 B, not 24 B. `MediaTime` (16 B union) is embedded in Vector elements. `start()`/`end()` go through `toDouble()`. `buffered`/`seekable`/`played` `create` or `copy` via `RefPtr`. No raw `TimeRanges*` UAF in WK-1400. See `docs/TIMERANGES_24B_AUDIT_2026-10-23.md`.

### IDL pointer-width getters as standalone leak — DEAD: need a tag flip we cannot write

`DeprecatedCSSOMPrimitiveValue.cssText` / `getStringValue` and `TimeRanges.start` only leak if the union/flag is already wrong. Occupancy write that would flip CSS is the oracle that crashes. BigInt / TypedArray `.length` are JSC MarkedSpace/Gigacage, not the Canvas2D FastMalloc span. See `docs/IDL_POINTER_WIDTH_GETTERS_2026-10-23.md`.

### Canvas getImageData / CSS-SVG filter paint — DEAD: zeroFill, no IDL

`createImageData` / empty `getImageData` call `initializeEmptyImageData` → `zeroFill()`. `FilterImage` is not ScriptWrappable; `copyPixelBuffer` zero-fills. See `docs/C2D_FILTER_READBACK_2026-10-23.md`.

---

## Summary

| Category | Investigated | Dead | Alive/Safe |
|----------|-------------|------|------------|
| JSC Engine | 10 | 10 | 0 |
| Streams API | 4 | 4 | 0 |
| RAB | 4 | 3 | 1 |
| DOM / Rendering | 13 | 9 | 4 (1 ALIVE: Canvas UAF) |
| CVE Audit | 5 | 5 | 0 |
| Kernel / Syscall | 3 | 3 | 0 |
| Info Leak (Canvas UAF) | 10 | 10 | 0 |
| **Total** | **49** | **44** | **5** |

Note: Canvas getContext() UAF (CVE-2026-43720) was previously listed as dead due to IsoHeap but has been **retracted** — IsoHeap is OFF on PS5. It is now the primary exploitation vector with confirmed R/W. See CONFIRMED_VULNS.md.
