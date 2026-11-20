# Strategy

## Current Phase: Exploitation (Phase 4)

CVE-2026-43720 (Canvas getContext() reentrant UAF) is confirmed exploitable. Same-type reclaim gives full R/W of Canvas2D state fields. The current blocker is an info leak primitive to defeat ASLR.

## Phases

### Phase 1: Recon probes on device -- DONE

Fingerprinted the PS5 WebView. Determined API availability, format support, parser paths reachable from JavaScript.

Results:
- p163 / V399: Full API availability matrix
- p161a: FontFace API recon (15 tests)
- p161b: Image decoder recon (19 tests)
- V520: MSE SourceBuffer re-entrancy -- all safe
- V521: Structure spray, butterfly realloc, megamorphic IC -- no anomalies

### Phase 2: Source audit -- DONE

15+ WebKit subsystems audited against WK-1400 source. Zero exploitable entry bugs from source audit alone -- but confirmed IsoHeap OFF and Gigacage disabled, which reopened CVE-2026-43720.

Subsystems audited: MetadataTable, MSE/SourceBuffer, ReadableStream/tee(), Canvas2D, CSSFontFace, structuredClone, RAB, Yarr regex, NodeIterator, XMLParser/CustomElements, sort()/TypedArray, DirectArguments, ClonedArguments, font parsing, SVG filters.

See [WK1400_SOURCE_AUDIT.md](WK1400_SOURCE_AUDIT.md) for details.

### Phase 3: Targeted probes -- DONE

CVE-2026-43720 confirmed on device through a series of probes:
- V573: Same-type reclaim -- CONFIRMED (alias at idx=9)
- V562: All 12 Canvas2D APIs through alias -- clean complete run
- V630: Full 12-API alias diagnostic -- ALL PASS (alias at idx=11)
- V589: BMR trigger validation -- `uaf-ok: inner=OK`

49 total attack vectors investigated, 44 confirmed dead. 5 bugs found (1 exploitable, 4 contained/blocked). See [DEAD_ENDS.md](DEAD_ENDS.md) and [CONFIRMED_VULNS.md](CONFIRMED_VULNS.md).

### Phase 4: Exploitation -- IN PROGRESS

**Done:**
- UAF trigger (bitmaprenderer outer + defineProperty getter + 2d inner)
- Same-type reclaim (500x Canvas2D spray reclaims freed 768B slot)
- Bidirectional R/W via alias (lineWidth, miterLimit, globalAlpha, fillStyle, getLineDash, etc.)
- Crash oracle (forge m_stateStack to target address, lineWidth reads 8 bytes)
- Heap topology mapping (V650-V655 binary subdivision scanner)
- DAZ confirmed ON (all float64 channels flush denormals to 0)
- APNG overread leaks 1651 heap pointers (V674)

**Current blocker: Info leak (ASLR defeat)**

All Canvas2D APIs return typed JS values -- no raw heap pointer exposed. 10+ dedicated info leak approaches exhausted. Current candidates:
1. OOB state stack read via save-count mismatch
2. APNG overread pointer extraction

> **Issue #70 clarification:** V674 appears both in the "Done" list above (the leak event itself is reported/CONFIRMED on device per README.md) and as a "current candidate" here (not yet confirmed as the finalized, repeatable primitive that resolves this blocker). These are not contradictory if "Done" refers only to the reported observation while "current candidate" means further Stage 2 validation is needed; that interpretation and the precise remaining prerequisite require maintainer confirmation. The four documents reviewed here do not identify an original same-session raw capture/producer independently checked by our team.

**Designed but not yet reached:**
- Forge lineDash Vector in AB for arbitrary R/W
- vtable hijack or startOfStructureHeap overwrite (Config unfrozen)
- ROP chain to mprotect(74) for RWX

### Phase 5: Kernel pivot -- BLOCKED

Requires browser code execution from Phase 4. Top kernel candidates:
- CVE-2026-7270 (execve memmove OOB) -- full exploit published
- CVE-2026-45251 (poll/select UAF) -- full exploit published
- thr_create(430) confirmed working (up to 8 threads)

## Known Constraints

| Constraint | Impact |
|------------|--------|
| No JIT | No RWX pages, need ROP/JOP chains |
| No WASM | Cannot use WASM memory for layout control |
| No SharedArrayBuffer | Cannot race between threads for heap bugs |
| No WebGL | Cannot use GPU buffer tricks, readPixels leak unreachable |
| Gigacage disabled | AB shares heap with JSC internals (HELPS exploitation) |
| IsoHeap OFF | All WebCore objects in same FastMalloc (HELPS exploitation) |
| Config unfrozen | startOfStructureHeap writable post-exploitation (HELPS) |
| FreeBSD kernel | Different syscall table, different exploit surface |
| 16KB pages | Page alignment differs from x86 4KB |
| LLInt only | All bytecode through interpreter loop |
| ~1200MB ceiling | WebContent process OOM-killed beyond this |
| DAZ ON | Float64 channels flush denormals; must use BigUint64Array for raw pointers |
