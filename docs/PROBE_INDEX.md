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

## Canvas UAF Probes — CVE-2026-43720 (probes/canvas-uaf/ + probes/1410-guide/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| v527 | Historical AB reclaim discriminator (cobra PR#13) | **SUPERSEDED:** later same-type alias scans and AB class sweeps show AB storage does not reclaim the 768B Canvas2D slot on this build; the old marker was not a validated AB owner |
| v527b | Ref-pin bypass: canvas lever + AB reclaim | LEVER: reset=no-reset, type=no-type-attr, width=ok |
| v571 | lineWidth diagnostic | Offset calibration |
| v573 | Same-type reclaim diagnostic | CONFIRMED: bidirectional R/W, idx=9 |
| v578 | Light spray diagnostic | Spray count confirmed |
| v580 | Info leak capability probe | AudioContext=NO, IDB=NO, Workers=YES, WS=YES |
| v583 | JSC capability test | BigInt+DV=YES, MC+xfer=YES, class/super=YES |
| v585 | AB↔Context cross-type reclaim | Trigger/spray reached; no validated cross-type owner. Later device work closed AB(768) reclaim |
| v587 | State buffer reclaim (Proxy trigger) | CRASHED: size mismatch + GC during spray |
| v588 | Relapse scope leak test | Scope leak DEAD, structured clone+MC WORKS |
| v589 | State buffer reclaim (BMR trigger) | uaf-ok: inner=OK, CRASHED during spray |
| v592 | Butterfly harvest zero-alloc pre-read | Deployed by peer session |
| v594 | BMR trigger diagnostic | Ready, not yet tested |
| v597 | CSS filter uninit + stale heap | Ready, not yet tested |
| v600 | Save-count mismatch OOB read | **RETRACTED:** both wrappers read the reclaimed object's one shared Vector header; no stale `m_size=9` survives same-type reclaim |
| v601 | State buffer heap scan | Deployed |
| v610 | Cross-context getContext UAF (2d→WebGL→2d) | WebGL absent — DEAD |
| v611 | IntersectionObserver UAF probe | Narrow window, DEAD |
| v612 | Canvas backing store uninit | tryFastCalloc zeros — DEAD |
| v613 | Freed memory zero-alloc read | CRASHED (destructor nulls m_buffer) |
| v614 | AB spray discriminator | Deployed |
| v620 | Portablelle state buffer leak (save→free→AB) | CRASHED at lineWidth read |
| v621 | Portablelle corrected offsets | Redirects to V627 |
| v625 | Two-context alias + freed read | Deployed |
| v627 | Groomed Portablelle (768B+4608B groom + flush) | CRASHED at Phase 4 |
| v630 | **Full 12-API alias diagnostic** | **ALL 12 APIs PASS** — alias at idx=11 |
| v631 | AB zero-init + gradient + Blob/XHR uninit paths | Not deployed |
| v632 | Two-stage: alias + zero-alloc freed reads | Stage 1 pass, Stage 2 pending |
| v633 | Variant type confusion probe | Deployed |
| v640 | Info leak survey (FontFaceSet, Error.stack, etc.) | All clean/zeros |
| v641 | Blob/Worker/Fetch DontInitialize race | ALL return zeros |
| v642 | WebSocket TLS probe | Deployed |
| v643 | Heap groom timing diagnostic | Deployed |

### Later 14.10 Guide closure probes (2026-10-23/24)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| v661 | Legacy ImageData transfer/history disclosure | 65,536-byte result fully zeroed in both history variants |
| v663 | PlayStation CurlTM URL over-read reachability | 42/42 requests exact; traffic-manager path inactive/unreachable |
| v664–v668 | AcceleratedSurface teardown variants | All survived; harness-only `removeViewFromWindow` unavailable |
| v669 | Media timed-callback reachability | Direct media rejected before network; callback never armed |
| v670–v672 | Validation/password-input teardown and type changes | Full phase brackets survived; family closed |
| v673 | `navigator.language` stack-buffer read | Stable `en-US`, length 5; no truncation or over-read |
| v676–v679 | StringImpl/lineDash occupancy | Ambiguous Sony OOM/page-loss before post-write; wrong-class control also dies. Do not use as occupancy proof |
| v681/v686 | Font hmtx/metrics disclosure | Semantic/in-file widths only; `0xCC` padding does not change output |
| v683 | Stored-PNG length overshoot with valid control | Valid arm paints; overshoot arm paints no payload or heap bytes |
| v684 | Pointer-bit representation fingerprint | Integer views preserve bits; Float64/Canvas Number path DAZ-flushes to zero |
| v688–v690 | RAB detach/shrink/grow sinks | Detach clean; stale views empty/error; grow and regrow tails zeroed |
| v691–v693 | Worker/transport/stream/API battery | Transfers exact; no extra bytes; unavailable APIs recorded |
| v695–v699 | MSE and media decoder paths | Normal AB works; RAB rejected; truncation/padding does not expose leftover pixels |
| v700–v702 | SVG/ImageData/bitmaprenderer/DOM lifetime battery | Initialized/exact results only; FinalizationRegistry did not collect under safe pressure |

## Relapse Probes (probes/relapse-test/)

| Probe | Purpose | Device Result |
|-------|---------|---------------|
| p160 | Full Relapse CVE test suite | All patched on 14.10 |
