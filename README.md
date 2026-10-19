# PS5 14.10 Jailbreak Research

WebKit jailbreak research for PlayStation 5 firmware 14.10. All data comes from probes that ran on the actual console.

> **Disclaimer:** Authorized security research on personally owned hardware. For educational and research purposes only.

## Target

Validated on device (p163).

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| JIT | Disabled (LLInt only) |
| Cores | 4 |
| Display | 1920x1080 |

**Available:** Workers, WebSocket, fetch, SubtleCrypto, Canvas 2D, ReadableStream, WritableStream, TransformStream, ResizableArrayBuffer, WeakRef, FinalizationRegistry, Proxy, BigInt, structuredClone, FontFace, Custom Elements, Atomics

**Not available:** WebAssembly, SharedArrayBuffer, WebGL, WebAudio, IndexedDB, ServiceWorker, BYOB streams, WebGPU

## Source Reference

The PS5 WebKit binary is not publicly available. We use two open source snapshots as reference:

- **WebKit-1200** (December 2023) -- initial reference, closest to Safari 17.0 / AppleWebKit 605.1.15.
- **WebKit-1400** (WK-1400) -- primary audit source since Session 11, used for all current source analysis.

All assumptions from source are validated on device with probes.

## Chain Overview

See [docs/RESEARCH_MAP.md](docs/RESEARCH_MAP.md) for the full browser-to-kernel map with all stages, bugs, and current position.

```
Stage 1: WebKit memory corruption        <-- current position
Stage 2: Arbitrary read/write primitive
Stage 3: Sandbox escape
Stage 4: Kernel read/write
Stage 5: Post-exploitation
```

## Confirmed Bugs

### Best Lead: CVE-2026-43715 (CSSFontFace UAF)

[Full writeup](docs/bugs/cssfontface-uaf.md)

`iterateClients()` in CSSFontFace.cpp copies a WeakHashSet into a `Vector<Ref<Client>>` and then invokes a callback on each client in the vector. When `FontFace::fontStateChanged` runs as one of those callbacks, it resolves `m_loadedPromise`. The promise resolution path checks whether the result is a thenable -- if it has a `.then` property, the engine calls that getter synchronously.

An attacker places a getter on `FontFace.prototype.then` that removes a style element and forces a synchronous layout. This causes a client to be removed from the WeakHashSet while the callback loop is still iterating. The next iteration invokes a callback on the now-disconnected client -- a use-after-free.

```js
Object.defineProperty(FontFace.prototype, 'then', { get() {
    document.getElementById('victim-style').remove();
    document.body.offsetHeight; // force synchronous layout
}, configurable: true });

const face = new FontFace('test', 'url(font.ttf)');
document.fonts.add(face);
face.load();
```

**Status:** Patched in upstream WebKit (commit `5aedb82`). The WK-1400 build on PS5 14.10 does not include this fix. A device test has been deployed and is awaiting crash confirmation.

### Novel Findings (no CVE assigned)

These are original findings from this research. No matching CVE exists in NVD, WebKit Bugzilla, or Apple security advisories as of 2026-10-19.

**ReadableStream.tee() Private-Name Inversion** -- [writeup](docs/bugs/private-name-inversion.md)

Poison `Array.prototype[Symbol.iterator]` to yield the same object X twice during `rs.tee()`. The engine writes internal private slots (`disturbed`, `state`, `readableStreamController`) onto the attacker's object. Confirmed live on device. Blocked by the JS builtin wall -- all stream operations route through `@getByIdDirectPrivate`, which returns `undefined` on fake objects.

**ReadableStream.tee() fromObject() Type Confusion** -- [writeup](docs/bugs/tee-type-confusion.md)

`InternalReadableStream::fromObject()` wraps any JSObject as an InternalReadableStream with no type validation. An attacker substitutes objects during `tee()` via iterator override. Confirmed live on device. The OOB variant (one-element return) crashes via CrashOnOverflow. Same JS builtin wall limitation.

### Known CVEs (unpatched on PS5 14.10)

**CVE-2026-43705: TransformStream Double-Iteration Substitution** -- [writeup](docs/bugs/transformstream-disconnect.md)

Sony's custom TransformStream constructor iterates the JavaScript builtin return array twice. An attacker overrides `Array.prototype[Symbol.iterator]` on the second pass to substitute their own real streams. The C++ side stores the attacker's streams while the JavaScript side uses the real streams. Patched in upstream WebKit (Safari 26.5.2, June 2026). PS5 14.10 is still vulnerable. Confirmed live on device, but no memory corruption from the disconnect alone.

## PS5 Exploitation Environment

See [docs/EXPLOITATION_ENVIRONMENT.md](docs/EXPLOITATION_ENVIRONMENT.md) for full details.

| Property | Value | Impact |
|----------|-------|--------|
| Gigacage | Disabled | ArrayBuffer backing stores share the same FastMalloc heap as JSC objects. No isolation. |
| StructureID | Pure mask+offset, no validation | A corrupted cell header produces type confusion with no runtime check. |
| Security assertions | Compiled out | `ASSERT_WITH_SECURITY_IMPLICATION` is a no-op on release builds. |
| Freed memory | Stays mapped | Freed blocks retain their contents until reallocated. |
| Allocator | FastMalloc, 256 granules (16KB) | Predictable size classes for heap grooming. |
| JIT | Disabled (LLInt only) | No RWX pages. Code execution requires ROP/JOP or direct syscalls. |

## Kernel Candidates

See [docs/KERNEL_AUDIT.md](docs/KERNEL_AUDIT.md) for the full audit.

| CVE | Bug | Priority |
|-----|-----|----------|
| CVE-2026-7270 | execve memmove out-of-bounds write | Tier 1 (full exploit published) |
| CVE-2026-45251 | poll/select use-after-free | Tier 1 (full exploit published) |
| CVE-2024-43102 | UMTX use-after-free (CVSS 10) | Tier 1 (14.10 patch status open — see [umtx correction](https://github.com/ZigZagBoi1/PS5-14.10-Research/pull/41)) |
| CVE-2025-15547/15576 | FreeBSD jail escapes | Tier 2 |

## Probes

90+ probes across 11+ sessions. See [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) for the full list with device results.

| Probe | What it does | Result |
|-------|-------------|--------|
| p141 | Overflow test (wrong stride) | SIGSEGV |
| p142 | Correct stride (112) | Overflow triggers |
| p143 | Targets before buffer | No corruption, sweep is forward only |
| p144 | Bait and switch | Forward write confirmed |
| p146 | Worker .length polling | **All 14 strings corrupted, .length = 81400** |
| p147, p148 | Substring and main thread views | StringImpl data intact, JSString.m_fiber corrupted |
| p150g-k | Sweep survival (5 strategies) | All OOM or crash, sweep is too long |
| p160 | Relapse CVE set | **All patched on 14.10** |
| p163 | Device fingerprint | Complete |
| V399 | Full API fingerprint | Version/17.0, no WASM/SAB/BYOB/WebGPU, yes RAB/Atomics/Workers/FontFace/Proxy |
| V429 | TransformStream substitution | **Confirmed: double iteration, attacker streams stored in C++** |
| V431 | TransformStream pipeline | Real pipeline consistent, zero anomalies |
| V432 | tee() type confusion | **Confirmed: plain object wrapped as ReadableStream** |
| V438b | tee() OOB heap groom | CrashOnOverflow trap, not exploitable |
| V445 | CSSFontFace UAF | Deployed, awaiting results |

## Attack Surfaces Audited

Over 20 surfaces fully audited. See [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md).

| Surface | Result |
|---------|--------|
| JSC integer overflows | MetadataTable is unique. All others use Checked<> or RELEASE_ASSERT. |
| Streams API (all angles) | JS builtin wall blocks all C++ field access on confused objects. |
| structuredClone / SerializedScriptValue | Well hardened. Pool mismatch patched on 14.10. |
| RAB (set, copyWithin, clone, TOCTOU) | Per-element bounds checks. IDL converters reject resizable views. |
| ClonedArguments | Conservative GC scanning blocks butterfly reclaim. |
| Font parsers | loca OOB returns notdef. BMP OOB returns fill values. |
| Image decoders | All 7 formats tested. No exploitable paths. |
| Yarr regex engine | Lookbehind fixed in WK-1400. C3 displacement causes match failure only. |
| EventTarget lifecycle | `isJSExecutionForbidden()` guard blocks the second handler. |
| XHTML / Custom Elements | XHTML iframes dead on PS5. Main-frame XHTML untested. |
| CSS custom properties | Stack overflow only. No memory corruption. |
| sort() detach | `m_vector` cleared, `m_length` zeroed. |
| DirectArguments OOB | `isMappedArgument` bounds check before `setIndexQuickly`. |
| ProxyObject JSScope leak | Binary-level fix present on PS5 14.10. |

## How to Use

1. Clone the repo.
2. Run `python3 tools/host.py`.
3. Edit `tools/fa-v62-huff.html` to pick a probe.
4. Open the URL on the PS5 browser.
5. Watch the beacon log.

## Models Used

This research was built with multiple LLMs working together.

| Model | Role |
|-------|------|
| Claude Opus 4.6 | Primary workhorse. Probes, source analysis, struct layouts, heap modeling, coordination. |
| GPT-6.1-Sol | Codex dispatches, verification passes, structure recommendations. |
| GPT-6.1-Astra | Flagship analysis (sometimes unavailable). |
| DeepSeek v4.1-Flash | Scene sweep, PUP carving, gap analysis, gadget hunting. |
| DeepSeek v4-Pro | Deep analysis tasks. |
| GLM 5.3 Flash | Router analysis, verification, cross audit. |
| Kimi K3 | Escape sequence analysis, exploit page construction. |
| Qwen 3.8 | Architecture ladder synthesis, verification. |
| Mimo | Analysis support. |

## Progress

| Stage | Status |
|-------|--------|
| Bug identification | Done (2 novel bugs + 2 known CVEs unpatched). |
| 20+ surface audit | Done (all dead-ended except CSSFontFace). |
| CSSFontFace UAF (CVE-2026-43715) | Device test deployed. |
| Stream type confusion (tee + TransformStream) | Confirmed live. Blocked by JS builtin wall. |
| Exploitation environment analysis | Done. Gigacage disabled, StructureID unvalidated. |
| Kernel audit | Done. 3 Tier-1 candidates identified. |
| Arbitrary read/write | Not started. |
| WebKit code execution | Not started. |
| Sandbox escape | Not started. |
| Kernel exploit | Not started. |

## Related Research

The userland/kernel side of the same 14.10 chain is researched in [ZigZagBoi1/PS5-14.10-Research](https://github.com/ZigZagBoi1/PS5-14.10-Research):

- **Complementary stages.** This repo covers browser → WebKit corruption → arbitrary R/W (Stages 1-2). Theirs covers the userland/kernel side: a Lua loader entry (Hamidashi Creative save file, TCP 9026), a complete 14.10 syscall attack-surface map (working/blocked/lethal, 233+ probes), and 13.60 kernel handler reverse engineering (145/145 syscalls).
- **Their Stage 3/4 = our kernel audit.** Their [ATTACK_SURFACE.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/ATTACK_SURFACE.md) is the validation map for our kernel candidates and Sony-syscall table. Their umtx correction ([PR #41](https://github.com/ZigZagBoi1/PS5-14.10-Research/pull/41)) reopened CVE-2024-43102 reachability on 14.10: `_umtx_op` is syscall 454 and is alive, while all earlier "umtx" tests hit syscall 557.
- **Shared browser-entry knowledge.** Their live browser tests documented the 14.10 User's Guide domains (`ps5.np.playstation.net`, `manuals.playstation.net`), DNS kit quirks, and Relapse stage-1 death (54/54) — all confirmed on both consoles here (issue #6). Their PR #36 offers an on-device crash oracle for candidate JS cases; we can run cases on request (issue #6).

## Contact

X: [@Arn0Stride7](https://x.com/Arn0Stride7)

## Support

If you want to help keep this research going, contributions go directly into keeping the lights on.

| Method | Address |
|--------|---------|
| PayPal | [paypal.me/arnoldzap](https://paypal.me/arnoldzap) |
| BTC | `bc1qw2lpq8p0cspdk9dlddv6y0wswh6z6svtjjkn73` |
| ETH | `0xfad7D7e182FC77194AB3737130651Ec85958932b` |
| SOL | `BftaLxgQvgn9WN1YXTJePeUPWzJK5whMnFRVQ8EdLzvv` |

All donations will be disclosed and used for AI subscriptions, PS5 and PS4 hardware for jailbreak research, and continuous improvement of this project.

## License

MIT
