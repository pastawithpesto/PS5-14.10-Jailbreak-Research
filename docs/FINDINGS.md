# Findings

All findings are validated on device (PS5 14.10) or verified against WebKit-1200 source.

## 2026-10-23 Canvas getImageData + CSS/SVG filters CLOSED

Empty `getImageData`/`createImageData` `zeroFill()`. `FilterImage` has no IDL; copy path zero-fills. Not a pointer leak. `docs/C2D_FILTER_READBACK_2026-10-23.md`.

## 2026-10-23 TimeRanges / 24 B path CLOSED

Header layout: `TimeRanges` ≈ 32 B (RefCounted + Vector), not 24 B. `MediaTime` 16 B embedded; `toDouble()` converts, does not bitcast a pointer. `buffered`/`seekable` create or copy via `Ref`. No raw `TimeRanges*` UAF in WK-1400. Details: `docs/TIMERANGES_24B_AUDIT_2026-10-23.md`.

## 2026-10-23 V679 lineDash 96 after free — same PREWRITE crash

Device: DONORS=80, DASH 96, CANVSPRAY=300, PREWRITE, no POSTWRITE (Sony memory dialog). Same signature as V676-B / V677. V578/V678 with no intervening candidate allocations still ALIAS idx=10. Stale `lineWidth` store cannot tell Vector/StringImpl occupancy from page-return-to-OS. Occupancy vehicle stays source-only. Do not Circle more occupancy probes on this oracle.

## 2026-10-23 V676/V677 string interpose CLOSED as occupancy oracle

V678 control (no strings) ALIAS idx=10, POSTWRITE ok, END healthy. Guide not toasted.
V676 arm A same. V676 B (`repeat(744)` then 300 canvas) and V677 (`repeat(700)` then 300 canvas) both die at PREWRITE with Sony "not enough free system memory". The original index-46/index-48 interpretation assumed libpas size directories, but the PlayStation configuration disables libpas. The only defensible result is that StringImpl occupancy is not distinguishable with this oracle. V679 then tested a 96-double FastMalloc buffer after free and produced the same pre-write death.

## 2026-10-23 DASHFORGE 0x1800000 retracted

No local getLineDash at 0x1800000. Source: cobrajet302gt issue #11 comment 6356111570, third-party harness. V573 = typed alias only. Blockers: native address disclosure AND raw Vector-header write. No V674.

## 2026-10-23 V673 navigator.language CLOSED

Guide dumps (multiple loads 19:17–19:18): `navigator.language` = `en-US`, JS length 5, UTF-16 `0065 006e 002d 0055 0053`, BCP47 ASCII, over15=false. `navigator.languages` n=1 same string. `navigator.userAgent` length 116 well-formed `Mozilla/5.0 (PlayStation; PlayStation 5/14.10) AppleWebKit/605.1.15 ...`. No cross-load variation. SYSTEM_LANGUAGE is a short OS locale; truncation/fromLatin1-off-stack does not fire. Path CLOSED.

## 2026-10-23 V672 password-input-changed-type CLOSED

Sony clone on the main document (no iframe). Two+ fresh loads with PRE-P2T/POST-P2T (type=text, focus held), PRE-T2P/POST-T2P (type=password), SURVIVE 50/250/1000/3000, DONE. First complete spec runs 19:12:25 and 19:12:34. Close entire secure-input family from Guide JS. Do not combine type-flip with teardown.

## 2026-10-23 V671 removed-password-input CLOSED

Phase 1 REACH: password in iframe, focus held two rAF, selectionStart/End=0.
Phase 2 remove focused input: PRE/POST-REMOVE, SURVIVE 50/250/1000/3000.
Phase 3 iframe about:blank then remove: PRE-NAV, NAV-LOAD, PRE/POST-REMOVE, full SURVIVE, DONE 19:09:44. Green box was debug iframe border. Close secure-input remove-password lifetime path from Guide JS. Type-change variant not run (Daybreak: later).

## 2026-10-23 V670 validation detached iframe CLOSED

Phase 1 REACH: reportValidity=false, invalid event, focus=required_text_input, tree alive 500ms. SSL was form GET to self-signed host (preventDefault after).
Phase 2 remove-outer: PRE/POST-DETACH + SURVIVE 50/250/1000/3000.
Phase 3 about:blank (cb=670004): two+ fresh loads 19:02:30, 19:03:33, 19:03:41 with REACH, PRE-NAV, NAV-LOAD, PRE-REMOVE, POST-REMOVE, full SURVIVE, DONE. No missing post-phase. Close validation detached-frame lifetime path from Guide JS. No more timing variants.

## 2026-10-23 V668 Sony remove-reinsert (AcceleratedSurface-from-Guide closed)

V573 kept off this page. Sony DOM + composited-subframe.html. Phases CREATE/FIRST-FRAME/COMPOSITE/REMOVE/REINSERT/BLANK/TEARDOWN/SURVIVE-250/1000/3000 all present, DONE v668-survive, no crash. JS cannot call `uiController.removeViewFromWindow`. Daybreak: close AcceleratedSurface-from-Guide. Next pick is `MediaPlayerPrivatePlayStation::performTaskAtMediaTime` (V669).

## 2026-10-23 V667 main-document compositing toggle

Negative. V573 control idx=10. Full-viewport `translate3d` overlay on the Guide document, 6 rAF, remove overlay. PRE-KILL/POST-KILL/SURVIVE. JS teardown of composited layers does not destroy `AcceleratedSurfacePlayStation` before `finish()` returns. Subframe and main-overlay paths are closed for this lifetime bug.

## 2026-10-23 V666 nested blob WebPage

Negative. V573 control idx=5. Blob iframe with child rAF+canvas, kill at tick 8. 77+ DONE survive. Subframe teardown does not race `AcceleratedSurfacePlayStation`.

## 2026-10-23 V665 kill-on-frame-2

Negative. Same V573 control (idx=6). Twelve iframes, `about:blank` + remove at tick 2. PRE-KILL then POST-KILL then SURVIVE (21+ DONE). CSS 3d iframes are not racing the detached `didRenderFrame` thread.

## 2026-10-23 V664 AcceleratedSurfacePlayStation iframe kill

Negative crash. V573 control on the same page: ALIAS idx=10 write=true, 15+ clean runs. Eight CSS translate3d iframes, 16 rAF ticks, remove(): PRE-KILL then POST-KILL then SURVIVE. The detached `didRenderFrame` thread did not die on this teardown. Either Guide never created the PS surface for those iframes, or `finish()` completed first.

## Confirmed Bugs

### 1. MetadataTable Integer Overflow (Bug 317632 / CVE-2026-64784)

`UnlinkedMetadataTable::finalize()` uses an `unsigned` accumulator with no overflow check. With 38,348,816 op_call sites at stride 112, the accumulator wraps from 4,295,067,392 to 100,096. The allocator reserves 100KB. The interpreter writes 4.29GB forward into heap memory.

**Status: BLOCKED.** The overflow triggers and corrupts heap objects, but the 4.29GB forward sweep crashes the process when it exits mapped virtual memory. Maximum working spray is ~240MB (2400 buffers), covering less than 6% of sweep distance. No early exit exists in finishCreation(). See `docs/bugs/metadatatable-overflow.md` for the full writeup.

### 2. JSString Header Corruption (via MetadataTable)

The sweep corrupts JSString.m_fiber in MarkedSpace cells. All 14 target strings report `.length = 81400` after the overflow. StringImpl backing data stays intact (charCodeAt returns original 0x41). The corruption is in the JSString header, not the character data.

Validated: p146, p147, p148 on device.

### 3. Forward Write Directionality (Proven)

finishCreation() sweeps FORWARD only (higher addresses). Targets placed before the metadata buffer are never reached. Bait and switch heap groom (allocate baits, then targets, free baits, trigger overflow) controls where the sweep lands.

Validated: p143 (no corruption when targets below), p144 (corruption when targets above).

### 4. CSSFontFace UAF (Source Verified)

`CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts` (line 381) returns `std::reference_wrapper<CSSFontFace>` (non-owning). The fix changed this to `Ref<CSSFontFace>`. Also `fontLoadEventOccurred()` calls `pump()` and client callbacks without `Ref<CSSFontFace> protectedThis`. Only `timeoutFired()` and `fontLoaded()` have that protection.

**Status: TESTING.** Probe p170 used WOFF2 (rejected on PS5). Probe p175 uses TTF from ArrayBuffer. Awaiting device results.

### 5. Font Parser OOB Read via loca Table (Device Confirmed)

PS5 FreeType accepts fonts with loca table offsets pointing past the glyf table boundary. V180A-T5 confirmed: font with loca[0]=0x7FFFFFFF loaded, rendered, and passed canvas read. V180A-T7 confirmed: directory entry offset past EOF also loads and renders.

FreeType on PS5 does NOT fully validate font internal offsets before use. With Gigacage disabled, the font buffer (from ArrayBuffer via FontFace API) shares bmalloc heap with JSC objects. A font with controlled OOB loca offsets can read adjacent heap memory through glyph rendering, then extract the data via Canvas getImageData.

**Status: TESTING.** Probe p182 deployed, testing multiple OOB offsets past glyf table.

### 6. ClonedArguments Butterfly UAF (DEAD: Conservative Scan)

ClonedArguments.cpp:289 butterfly pointer stale after Proxy trap reentrancy. V221/V243/V246 confirmed: Proxy trap fires, hole position returns Proxy value, but old butterfly is NEVER freed.

Root cause (source verified + device confirmed): conservative stack scanning keeps the stale `data` pointer alive. The C++ stack frame for `copyToArguments` is still on the stack when the Proxy trap fires. JSC's `ConservativeRoots.cpp:66-82` scans the stack for pointer-aligned values and adds any MarkedBlock cell pointer as a GC root. Even with JSArray spray (correct allocator space), `marksConveyLivenessDuringMarking` keeps the butterfly alive across GC cycles.

V246 device results: all 8 rounds show original sequential values at non-hole positions, `0xBEEF` at hole position 5, no CAFE spray markers anywhere. ArrayBuffer spray (V221/V243) and JSArray spray (V246) both fail.

**Status: DEAD.** Cannot free butterfly while `copyToArguments` is on the call stack.

## Confirmed Dead Ends

### Yarr Regex C3 Position Corruption
1-unit displacement in C3 character class handling always causes match failure. Cannot produce controlled out-of-bounds reads. Verified in source.

### RAB byteLength Inversion
ResizableArrayBuffer has an inverted bounds check that allows conceptual OOB access, but all sink paths (SubtleCrypto, TextDecoder, DataView) throw TypeError before reaching the underlying buffer. Every read/write path correctly re-validates length.

Validated: p160a (TypeErrors on all stale-read paths).

### ClonedArguments propertyCapacity
PreciseAllocation for ClonedArguments has outOfLineCapacity=4 and canRealloc always returns false. Cannot trigger reallocation to create a type confusion.

### Relapse WebKit CVE Set
All known Relapse bugs (prior firmware exploit chain) are patched on 14.10.

Validated: p160 on device.

### Streams API BYOB Reader
BYOB reader ctor/elementSize mismatch is real (acknowledged by FIXME comments in source) but TypedArray constructor bounds checking prevents all OOB paths. Every combination results in RangeError or truncated but in-bounds views.

### ReadableByteStreamController
Not implemented on PS5. V190A-P4-ERR: "TypeError: ReadableByteStreamController is not implemented". BYOB exploitation paths blocked.

### SVG Font GSUB Placeholder Truncation
SVGToOTFFontConversion.cpp line 119 truncates delta to uint16_t via implicit conversion. Triggers when GSUB ligature subtable exceeds 64KB (~10923 ligature pairs). However, the truncation corrupts offsets INSIDE the OTF buffer, not heap metadata. overwrite16 writes a wrong VALUE at a correct LOCATION. This is font data corruption, not a WebKit memory safety issue. Would only be exploitable if FreeType itself misparses the resulting malformed GSUB table.

## Audited Surfaces (No Bugs Found)

| Surface | Agent | Result |
|---------|-------|--------|
| Integer overflows (full JSC) | overflow-hunt | MetadataTable is unique. All other subsystems use Checked<>/RELEASE_ASSERT |
| ASLR leak primitives | aslr-binary-audit | Error.stack has no addresses, ArrayBuffer always zeroed, performance.now() is 1ms resolution |
| MetadataTable alternative strategies | metatbl-alt-strategy | No shortcut for sweep. No early exit, link() safe, destructor safe |
| SerializedScriptValue (structuredClone) | clone-deserialize-audit | Well hardened. No type confusion, no UAF, no uninit memory |
| Streams API + SubtleCrypto | streams-api-audit | BYOB mismatch is real but TypedArray bounds checking blocks all OOB |

## Device Recon Results (Session 10)

### FontFace API (p161a)
FontFace and document.fonts.add work on PS5. Parser rejects most malformed fonts (NetworkError). Two edge cases accepted:
- numGlyphs=0xFFFF (65535) loads without error
- unitsPerEm=0 loads AND renders on canvas (potential div-by-zero in layout math)
- WOFF2 is rejected
- ArrayBuffer source loading works (no data URL needed)

### Font Parser Fuzz (p180a, V180A)
12 corruption variants tested against FreeType via FontFace API from ArrayBuffer.

| Test | Corruption | Result |
|------|-----------|--------|
| T0 | Valid baseline | LOADED + RENDER + CANVAS-OK |
| T1 | numGlyphs=0xFFFF | LOADED |
| T2 | numHMetrics=0xFFFF | LOADED |
| T3 | Bad loca format | LOADED |
| T4 | Huge cmap segCount | LOADED |
| T5 | LOCA OOB OFFSET | LOADED (OOB read potential) |
| T6 | Dir size overflow | REJECTED |
| T7 | Dir offset past EOF | LOADED (OOB read potential) |
| T8 | maxp zero glyphs | LOADED |
| T9 | Bad magic number | LOADED |
| T10 | Huge numTables | LOADED |
| T11 | unitsPerEm=0 | REJECTED |

T5 and T7 are the critical findings. FreeType accepts fonts with offsets pointing outside the valid table data.

### Image Decoders (p161b)
All 7 formats supported: PNG, JPEG, GIF, WebP, BMP, SVG, ICO. createImageBitmap available. Edge cases:
- Truncated PNG IDAT loads successfully (potential uninit memory read)
- 0x0, 65535x65535, 32768x32768, INT_MAX width all rejected
- CIB huge crop clamped to 1x1

---

## Canvas UAF Exploitation Chain (CVE-2026-43720)

### IsoHeap OFF on PS5

`WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on FreeBSD/PlayStation. `BPLATFORM(PLAYSTATION)` at BPlatform.h:341 disables IsoHeap. Gigacage also disabled — AB backing stores share the same heap as JSC/WebCore objects. Confirmed by Synacktiv writeup and CSSFontFace exploitation research.

### Same-Type Reclaim + Bidirectional R/W (V573)

BMR trigger (bitmaprenderer outer + 2d inner via defineProperty getter) confirmed working on device. 500x Canvas2D spray reclaims freed 768B context slot. Stale wrapper aliases spray context at index 9. All 12 Canvas2D APIs work through alias: lineWidth, miterLimit, globalAlpha, fillStyle, strokeStyle, getTransform, setTransform, getLineDash, setLineDash, measureText, save, restore.

### State Buffer Reclaim (V587/V589)

8x `save()` inside getter grows `Vector<State>` out-of-line to ~6400 bytes (bmalloc class 6656). BMR trigger frees inner context + state buffer. AB spray can reclaim the freed state buffer. V589 confirmed BMR trigger works (`uaf-ok: inner=OK`) but crashes during spray phase — likely GC pressure from 500+ AB allocations.

### OOB State Stack Read — Info Leak Candidate

**Key insight:** After BMR free + same-type reclaim, the stale wrapper retains `m_stateStack.m_size = 9` (from 8 saves) while the new context has `m_size = 1`. Reading `m_stateStack.last()` through the stale wrapper indexes at `buffer[8]` = offset 3200 = **2800 bytes past the end** of the new context's 1-State buffer.

This reads from adjacent heap allocations. A 48-bit x86-64 pointer is exactly representable as IEEE 754 float64, so `lineWidth` returns the raw pointer value as a JavaScript number.

**libpas allocator behavior:** Out-of-band bitmap tracking — freed chunks retain all stale data. No in-band freelist pointers. Freed memory is NOT zeroed.

**Status:** Probe needed to confirm non-zero pointer-like values from OOB read on device.

### Exploitation Path

1. OOB state stack read → heap address leaked as float64
2. Fake lineDash `Vector<double>` in AB: set `m_buffer = TARGET`, `m_capacity = N`, `m_size = N`
3. `setLineDash([v1,...,vN])` → in-place memcpy to TARGET = arbitrary write
4. `getLineDash()` → reads from `m_buffer` = arbitrary read
5. Read JSGlobalObject vtable → binary base → ROP gadgets
6. Vtable hijack → ROP chain (x86-64, no PAC, no JIT)
7. Kernel escalation via reachable syscall surface

### Pointer-width / union-arm IDL getter map (2026-10-23)

Source-only sweep of 616.1.27 WebCore/JSC for Guide-reachable **getters** returning JS Number/String over pointer-width or union-arm backing. Full table + greps in `docs/IDL_POINTER_WIDTH_GETTERS_2026-10-23.md`. Result: only two qualify, both tag-flip sinks (not standalone leaks): `DeprecatedCSSOMPrimitiveValue.getStringValue()/cssText()` over `CSSPrimitiveValue::m_value` (StringImpl*/calc/unresolvedColor arms), and `TimeRanges.start()/end()` over `MediaTime::m_timeValue` (int64 arm). No clean IDL getter returns a native pointer without a prior type confusion.
