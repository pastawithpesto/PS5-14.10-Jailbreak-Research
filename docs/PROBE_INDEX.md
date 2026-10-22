# Probe Index

All probes tested on PS5 14.10. Results from device beacon logs.

## MetadataTable Overflow Probes

### Early Discovery (probes/metadata-overflow/early/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p141 | First overflow test (wrong stride 96) | SIGSEGV, wraps to 715MB |
| p142 | Correct stride 112 | COMPILED-OK, then crash on call |
| p143 | Worker witness, targets below metadata | No corruption (forward only) |
| p144 | Bait-and-switch, targets above metadata | Forward write confirmed |

### Heap Groom (probes/metadata-overflow/heap-groom/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p146 | Worker .length polling | All 14 strings corrupted, .length=81400 |
| p147 | Substring views for data read | m_data8 intact, reads original 0x41 |
| p148 | Main-thread targets | 14 JSCORRUPT, 0 LEAKED, StringImpl intact |
| p148b | Sweep leak | Crash, no data |
| p149 | FinalizationRegistry + ArrayBuffer targets | OOM before completion |
| p149-diagnostic | Read after compile, before call | ZERO corruption (proves compile-time) |
| p150 | Throwing callback | OOB read crashes, garbage dereference |

### Extraction (probes/metadata-overflow/extraction/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p155 | Lean worker | Compilation testing |
| p156 | Bait-and-switch groom | Forward write layout |
| p157 | ArrayBuffer extract | Zero-init blocks stale reads |
| p158 | Throw extract | OOB crash |
| p159 | Gradient fill strings | Crash, rope cells break heap layout |
| p160 | Relapse CVE test | All patched |
| p161 | Fast gradient | Crash |
| p162 | Deep scan to 2000 bytes | Partial data |
| p164 | DataView cell corruption (view = target) | PREPARED — NOT RUN |
| p165 | Float64Array cell corruption (m_vector / m_length) | PREPARED — NOT RUN |

### p164/p165: View-Cell Extraction (issue #5 roadmap, prepared)

Both reuse the proven p156 bait-and-switch groom unchanged (20 baits, worker targets, free + 30 GC rounds, 146MB blob, 38,348,816 calls) and flip the target class from JSString to typed-array views. p157 established that backing stores are NOT overwritten (zeros came back); these probes bet on the CELL — the region p156 proves the sweep rewrites.

| Probe | Targets | Reads | Classification |
|-------|---------|-------|----------------|
| p164 | 8 canary strings + 12 small DataViews (16B AB) + 4 marge DataViews (102,400B AB) | byteLength, byteOffset, 16 raw bytes via getUint32 (try/catch each) | PRE-OK / VECTOR-HIT / LEN-HIT / DEAD |
| p165 | 8 canary strings + 16 small Float64Arrays + 4 marge Float64Arrays | length, byteLength, byteOffset, raw bits of f64[0]/f64[1] via clean bitcast buffer | PRE-OK / VECTOR-HIT / LEN-HIT / DEAD |

Interpretation guide: VECTOR-HIT with non-fill bytes = a read through a sweep-written pointer (module-relative leak candidate — the WebKit base defeat); LEN-HIT with successful high-index reads = OOB read past the backing store. Canary `.length` beacons give the p156 baseline (81400) for cross-console comparison. Both probes are memory-neutral vs p156 (+~30 small objects), so the second-console ceiling (~1.28-1.92GB, issue #6) is respected.

### Sweep Survival (probes/sweep-survival/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p150g | 400 targets + 2000 padding, call function | CALLING then silence (240MB VM not enough) |
| p150i | 3 waves of 5000 buffers, free between | OOM at BUILD (MADV_FREE pressure) |
| p150j | Single wave 8000 buffers | OOM at BUILD (764MB too much) |
| p150k | 5000 buffers + heavy GC | OOM at BUILD (477MB + blob = too much) |

## Recon Probes (probes/recon/)

### p161a: FontFace API Recon (15 tests)

| Test | What | Result |
|------|------|--------|
| T0 | API availability | FontFace YES, document.fonts YES |
| T1 | Valid font load + add | LOADED-OK, ADD-OK |
| T2 | numTables=0 | RangeError (JS build, not parser) |
| T3 | numTables=0xFFFF | NetworkError (rejected) |
| T4 | Table offset past EOF | NetworkError |
| T5 | Table length=0 | NetworkError |
| T6 | Table length=0xFFFFFFFF | NetworkError |
| T7 | CFF (OTTO) signature | NetworkError |
| T8 | WOFF totalSfntSize=0xFFFFFFFF | NetworkError |
| T9 | WOFF maxTables | NetworkError |
| T10 | maxp numGlyphs=0xFFFF | OK (accepted) |
| T11 | unitsPerEm=0 + canvas draw | OK, DRAW-OK |
| T12 | Canvas pixel count | 311 non-zero pixels |
| T13 | ArrayBuffer source | OK (direct buffer loading works) |
| T14 | WOFF2 signature | NetworkError (not supported) |

### p161b: Image Decoder Recon (19 tests)

| Test | What | Result |
|------|------|--------|
| FMT-PNG | PNG 1x1 | OK |
| FMT-JPEG | JPEG 1x1 | OK |
| FMT-GIF | GIF 1x1 | OK |
| FMT-WEBP | WebP 1x1 | OK |
| FMT-BMP | BMP 1x1 | OK |
| FMT-SVG | SVG 1x1 | OK |
| FMT-ICO | ICO 1x1 | OK |
| CIB | createImageBitmap | Available |
| PNG-0x0 | Zero dimension | FAIL (rejected) |
| PNG-HUGE | 65535x65535 | FAIL (rejected) |
| PNG-BADCLR | Invalid color type | FAIL (rejected) |
| PNG-TRUNC | Truncated IDAT | OK (loaded) |
| PNG-32K | 32768x32768 | FAIL (rejected) |
| PNG-INTMAX | INT_MAX width | FAIL (rejected) |
| CANVAS | drawImage + getImageData | OK |
| CIB-WEBP | createImageBitmap from WebP | OK |
| CIB-CROP | CIB with crop rect | OK |
| CIB-HUGECROP | CIB with oversized crop | OK (clamped to 1x1) |

## RAB Probes

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p160a | RAB byteLength inversion | TypeErrors on all stale-read paths |
| p160b | RAB full sink audit | All sinks correctly guarded |
| p160c | RAB grow + fetch | Stale view reads extra zeros, no leak |

## Font Parser Fuzz (Session 11)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p180a | 12 TrueType corruption variants via FontFace API | T5 LOCA-OOB LOADED, T7 DIR-PAST-EOF LOADED, T6/T11 REJECTED |
| p182 | Font loca OOB read at controlled offsets | Deployed, awaiting results |

## ClonedArguments UAF (Session 11)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p221 | ClonedArgs butterfly UAF via Proxy trap | Proxy fires (beef0001), butterfly not freed |
| p243 | Heap feng shui: spray + butterfly adjacency | Holes read zeros, no spray reclaim (wrong allocator) |
| p246 | Butterfly reclaim via JSArray spray (same allocator) | Deployed, awaiting results |

## CSSFontFace UAF (Session 11)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p170 | CSSFontFace UAF via WOFF2 font cycling | Network errors (PS5 rejects WOFF2) |
| p175 | CSSFontFace UAF via TTF from ArrayBuffer | Deployed, awaiting results |

## Relapse Probes (probes/relapse-test/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p160 | Full Relapse CVE test suite | All patched on 14.10 |
