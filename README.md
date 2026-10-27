# PS5 14.10 WebKit Exploitation Research

WebKit memory safety research targeting PlayStation 5 firmware 14.10 via CVE-2026-43720 (Canvas `getContext()` reentrant UAF). All data from probes running on retail hardware through the built-in browser.

> **Disclaimer:** Authorized security research on personally owned hardware. For educational and research purposes only.

> **IMPORTANT -- Please do not share the findings, probes, or techniques from this repository with third parties, vendors, or security teams.** Disclosing these bugs will get them patched and permanently close the attack surface for the entire community. If you are working with this research, keep it within the project contributors. Public disclosure kills the chain for everyone.

## Support This Research

This project runs on AI compute -- multiple frontier models working in parallel around the clock. If this research is useful to you, please consider supporting it:

| Method | Link |
|--------|------|
| PayPal | [paypal.me/arnoldzap](https://paypal.me/arnoldzap) |
| BTC | `bc1qw2lpq8p0cspdk9dlddv6y0wswh6z6svtjjkn73` |
| SOL | `BftaLxgQvgn9WN1YXTJePeUPWzJK5whMnFRVQ8EdLzvv` |

Every contribution helps keep the models running and the research moving forward.

## Target

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 |
| OS | Prospero (FreeBSD r230171) |
| CPU | AMD Zen 2, 16KB pages |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| Source tree | **WebKit-1400** (primary) |
| JIT | Disabled (LLInt only) |

**Available:** Workers, WebSocket, fetch, SubtleCrypto, Canvas 2D, ReadableStream, ResizableArrayBuffer, WeakRef, FinalizationRegistry, Proxy, BigInt, structuredClone, MediaSource, TransformStream, FontFace, Atomics, MessageChannel

**Not available:** WebAssembly, SharedArrayBuffer, WebGL, WebAudio, IndexedDB, ServiceWorker, ReadableStream BYOB, WebRTC, WebGPU, OffscreenCanvas, Clipboard API

## Exploit Chain -- CVE-2026-43720

| Stage | Status | Description |
|-------|--------|-------------|
| UAF Trigger | CONFIRMED | `bitmaprenderer` outer + `Object.defineProperty` getter + `2d` inner frees 768B context |
| Same-Type Reclaim | CONFIRMED | 500x Canvas2D spray reclaims freed slot (V573) |
| Alias R/W | CONFIRMED | All 12 Canvas2D APIs work through stale wrapper (V630) |
| Crash Oracle | CONFIRMED | Forged `m_stateStack` reads 8 bytes at arbitrary address (V650-V655) |
| ASLR Defeat | CONFIRMED | APNG overread leaks 1651 heap pointers (V674) |
| Arbitrary R/W | DESIGNED | Forge lineDash Vector in AB, `setLineDash` writes in-place |
| Code Exec | **NEXT** | vtable hijack + ROP (no PAC, no JIT, JSC Config unfrozen) |
| Kernel | BLOCKED | Needs browser code execution first |

### The Bug

`HTMLCanvasElement::getContext()` reads dictionary options via JS getters BEFORE setting the new context. A re-entrant getter creates a 2d context; the outer call then replaces it with `bitmaprenderer`, freeing the 2d context while its JS wrapper survives.

```javascript
var innerCtx;
var canvas = document.createElement('canvas');
var opts = {};
Object.defineProperty(opts, 'alpha', {
  get: function() {
    innerCtx = canvas.getContext('2d');
    return true;
  }
});
canvas.getContext('bitmaprenderer', opts);
// innerCtx is now a dangling reference to freed 768-byte memory
```

After the trigger, a spray of 500 Canvas2D contexts reclaims the freed 768B slot. `innerCtx` and the reclaiming spray context become aliases to the same live C++ `CanvasRenderingContext2D` object.

### Key Properties

- **IsoHeap OFF** -- `WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on PS5 (`BPLATFORM(PLAYSTATION)`)
- **Gigacage DISABLED** -- ArrayBuffer backing stores share the same heap as JSC/WebCore objects
- **JSC Config unfrozen** -- `startOfStructureHeap` remains writable post-init (instant type confusion with arb write)
- **DAZ ON** -- MXCSR denormals-are-zero active; pointer values (IEEE754 denormals) must be read via BigUint64Array, not float64
- **Freed blocks stay mapped** -- libpas uses out-of-band bitmap tracking; no in-band freelist pointers

### Confirmed Primitives

| Primitive | Method | Status |
|-----------|--------|--------|
| Float64 R/W | `lineWidth`, `miterLimit`, `globalAlpha` | CONFIRMED |
| Color R/W | `fillStyle`, `strokeStyle` | CONFIRMED |
| Array R/W | `setLineDash` / `getLineDash` (500 doubles) | CONFIRMED |
| Matrix Read | `getTransform` (DOMMatrix) | CONFIRMED |
| State Stack | `save` / `restore` (3-level cycle) | CONFIRMED |
| Crash Oracle | Forged `m_stateStack` + `lineWidth` read | CONFIRMED |
| ASLR Bypass | APNG overread leaks heap pointers | CONFIRMED (V674) |

### Planned Exploitation Path

1. V573 same-type reclaim -- alias to live context
2. V674 APNG overread -- heap address leaked
3. Grow `stateStack` -- realloc frees old buffer -- AB spray reclaims it
4. Forge lineDash `Vector<double>` in AB (`m_buffer` = target, `m_size` = N)
5. `getLineDash` through alias -- arbitrary read
6. `setLineDash` through alias -- arbitrary write (copy-assign writes in-place when capacity >= N)
7. Overwrite vtable or `startOfStructureHeap` (writable -- JSC Config unfrozen)
8. ROP chain -- kernel syscall

## Repository Structure

```
probes/                  -- All HTML/JS probes deployed to PS5 browser
  canvas-uaf/            -- CVE-2026-43720 exploitation probes (V569-V674+)
  deployed/              -- Archived fa-v* HTML wrappers served to the PS5
  legacy/                -- Older probe JS scripts (p60-p527)
  metadata-overflow/     -- MetadataTable overflow probes (DEAD)
  recon/                 -- Device fingerprinting (V399, V520, V521)
  escalation/            -- Exploit chain HTML pages
  streams/               -- Streams/tee type-confusion probes
  candidates/            -- Candidate exploit livetest pages
  press/                 -- Iterative "press" probe series
  misc/                  -- Diagnostic and one-off probes
  relapse-test/          -- Prior exploit CVE validation
  sweep-survival/        -- Heap sweep survival tests
  1410-guide/            -- AB reclaim guide probes
  shared/                -- Shared probe resources
docs/                    -- Technical documentation
  analysis/              -- Source-level analysis (struct layouts, heap model)
  bugs/                  -- Individual bug writeups (8 bugs)
  reports/               -- Status reports, learning notes, dispatch guides
  scratch/               -- Working notes and scratch analysis
  CONFIRMED_VULNS.md     -- All confirmed vulnerabilities with device evidence
  DEAD_ENDS.md           -- 49 exhausted attack vectors
  EXPLOITATION_ENVIRONMENT.md -- PS5-specific allocator and runtime properties
  PLATFORM_PLAYSTATION.md -- All PLATFORM(PLAYSTATION) code guards
  WK1400_SOURCE_AUDIT.md -- 15-subsystem source audit results
  KERNEL_AUDIT.md        -- FreeBSD kernel exploit candidates
tools/                   -- Beacon server, probe deployment, build utilities
  remote-loader/         -- HTTP server for PS5 browser
  runtime-derive/        -- Runtime offset derivation tooling
  beacon-parser/         -- Beacon log parser
assets/                  -- Static assets used by probes
  fonts/                 -- Test font files (TTF, WOFF, OTF, SVG)
results/                 -- Beacon logs and probe results
audits/                  -- Source audit reports
installer/               -- PS5 installer/payload framework
offsets/                 -- Kernel offset tables per firmware version
payloads/                -- Post-exploitation payload scripts
shared/                  -- Shared ELF/binary payloads
src/                     -- Exploit framework source (loader, ROP, net)
archive/                 -- Old backups and duplicate files
  index-backups/         -- Historical index.html versions
  bak/                   -- Miscellaneous .bak files
```

## Source Audit

15+ WebKit subsystems audited against the WK-1400 source tree. 39 CVEs from WSA-2026-0003 and WSA-2026-0004 individually triaged -- all dead on PS5 (JIT-dependent, WASM-dependent, or API-absent). 22 `PLATFORM(PLAYSTATION)` code guards analyzed -- all logging-only, no safety checks weakened. 49 attack vectors documented as dead ends. **Only CVE-2026-43720 is live.**

## Dead Ends

49 vectors investigated and dead-ended across JSC engine, Streams API, RAB, DOM/rendering, CVE audit, kernel syscalls, and Canvas UAF info leak paths. Full documentation in [`docs/DEAD_ENDS.md`](docs/DEAD_ENDS.md). Key dead-ends: MetadataTable overflow (OOM at 3.7GB AST), CSSFontFace UAF (DoS-only, sole 192B occupant), all 2023-2024 WebKit CVEs (JIT-dependent), butterfly UAF (conservative GC pins cells), UMTX (SHM stubbed on 14.10).

## Usage

1. Clone the repo
2. Set up a DNS redirect pointing a domain to your host machine (`[HOST_IP]`)
3. Run `python3 tools/remote-loader/host.py` on the host
4. Open the URL on the PS5 browser
5. Watch the beacon log for results

Probes report back via image beacon requests. Each probe is a self-contained HTML file in `probes/` that can be served directly.

## Models Used

This research was built with multiple LLMs working together.

| Model | Role |
|-------|------|
| Claude Opus 4.6 | Primary workhorse -- probes, source analysis, struct layouts, heap modeling, coordination |
| GPT-6.1-Sol | Codex dispatches, verification passes, structure recommendations |
| GPT-6.1-Astra | Flagship analysis |
| DeepSeek v4.1-Flash | Scene sweep, gap analysis, gadget hunting |
| DeepSeek v4-Pro | Deep analysis tasks |
| GLM 5.3 Flash | Router analysis, verification, cross audit |
| Kimi K3 | Escape sequence analysis, exploit page construction |
| Qwen 3.8 | Architecture ladder synthesis, verification |
| Mimo | Analysis support |

## Contact

**X: [@Arn0Stride7](https://x.com/Arn0Stride7)**

## License

MIT
