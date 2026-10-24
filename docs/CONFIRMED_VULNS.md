# Confirmed Vulnerabilities — PS5 14.10

Real memory safety bugs confirmed on device. Each hit a secondary wall that prevents full exploitation without an additional primitive.

> **Status key:** CONFIRMED = bug triggers on device. BLOCKED = exploitation blocked by secondary defense. The bugs are real — they become exploitable if the blocking wall is bypassed.

---

## 1. CVE-2026-43720 — Canvas getContext() Reentrant UAF

**Status:** CONFIRMED on device — IsoHeap OFF on PS5; same-type reclaim gives a typed Canvas-state alias, not arbitrary R/W

**Bug:** `HTMLCanvasElement::getContext()` checks `m_context` at line 226, then calls `convert<IDLDictionary>()` at line 268 for settings. Dictionary conversion invokes JS property getters. A getter re-enters `getContext('2d')` on the same canvas — inner call creates context, outer call overwrites `m_context` via `unique_ptr` assignment, freeing the inner context while its JS wrapper survives.

**Correct trigger (bitmaprenderer outer + 2d inner):**
```javascript
var innerCtx;
var canvas = document.createElement('canvas');
var settings = {};
Object.defineProperty(settings, 'alpha', {
  get: function() { innerCtx = canvas.getContext('2d'); return true; }
});
var outerCtx = canvas.getContext('bitmaprenderer', settings);
// innerCtx is now a dangling reference to freed memory
```

The bitmaprenderer outer avoids same-size-class reuse (80B vs 768B) that kills the Proxy+2d trigger.

**Device evidence:**
- V460/V461: Re-entry confirmed, same-type R/W confirmed
- V527/V527b (cobra PR#13): historical AB-reclaim interpretation; superseded by later same-type alias scans and AB class sweeps
- V548-V550: Alias CONFIRMED, full state R/W via aliased pair
- V573: Full same-type reclaim + bidirectional R/W on PS5 14.10
- V589: BMR trigger confirmed working (`uaf-ok: inner=OK`)
- V630: Comprehensive alias diagnostic — ALL 12 Canvas2D APIs confirmed working through alias:
  - lineWidth/miterLimit/globalAlpha: bidirectional double R/W
  - fillStyle/strokeStyle: color string R/W
  - font: string R/W
  - setLineDash(500)/getLineDash: 500-double array round-trip PERFECT
  - getTransform: DOMMatrix object read
  - save/restore: 3-level cycle (333→222→111) works
  - createPattern: HTMLCanvasElement pattern creation works
  - measureText: TextMetrics object returned correctly
- V632: Two-stage test (alias + zero-alloc freed reads) — Stage 1 alias confirmed
- V641: Blob/Worker/Fetch transfer race tests — all DontInitialize paths return zeros

**IsoHeap is OFF on PS5.** `WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on FreeBSD/PlayStation. Gigacage is also disabled, but this does **not** make ArrayBuffer backing stores interchangeable with the 768-byte Canvas2D object slot. Device results confirm same-type Canvas2D reclaim and reject the historical AB-reclaim premise.

**Confirmed primitives:**
1. Same-type Canvas2D reclaim: a live Canvas2D spray reclaims the freed 768B slot
2. Bidirectional R/W: lineWidth, miterLimit, globalAlpha, fillStyle, getTransform, getLineDash all work through stale wrapper
3. State-buffer growth is observable, but ArrayBuffer reclaim/readback of the freed buffer is not confirmed; bare stale reads die and AB-backed attempts did not yield bytes

**Retracted info leak candidate (OOB state stack read):**
The stale wrapper stores only the native `CanvasRenderingContext2D*`; it does not cache a separate `m_stateStack.m_size`. Both the vector header and its size live inside the reclaimed C++ object. A same-type reclaim constructs a new vector with `m_size=1`, so the stale wrapper sees the new size, not the old inner context's `m_size=9`. The previously documented `buffer[8]` read cannot arise from same-type reclaim alone.

**Current blocker:** INFO LEAK. All 12 Canvas2D APIs return typed JS values — no path found to read a raw heap pointer. Dedicated info leak paths are exhausted (see DEAD_ENDS.md "Info Leak Paths" section). Bare freed-memory reads crash, ArrayBuffer storage does not reclaim the Canvas2D slot, and the tested `DontInitialize` paths return zeros on device. V661 also confirmed that the legacy `ImageData` transfer plus `history.state` leak returns a fully zeroed 65,536-byte buffer on PS5 14.10 in both `replaceState` and `pushState` variants.

**Exploitation chain once info leak is solved:** fake lineDash Vector → arbitrary R/W → vtable hijack → ROP → kernel.

**Fix:** Commit `040ef6e21ffa` (2026-06-29, WebKit bug 313175): re-checks `m_context` after dictionary conversion. Not present in WK-1400.

---

## 2. CVE-2026-43715 — CSSFontFace UAF Write

**Status:** CONFIRMED on device, BLOCKED by Timer RELEASE_ASSERT

**Bug:** During `CSSFontFace::setStatus()`, `iterateClients` copies `Ref<Client>` (not `Ref<CSSFontFace>`). Client callback resolves a `DOMPromiseProxy` which fires a synchronous `.then` getter. The getter modifies `@font-face` rules via `setProperty()`, triggering `remove()` + `adopt()` which drops the last `Ref<CSSFontFace>`. The old face is FREED. `iterateClients` returns and `m_status = newStatus` at line 595 **writes to freed memory**.

**Device evidence (p458):**
- `A-RESULT: THEN-1-status=loading` → `.then` fires DURING `iterateClients`
- `B-CHECK: loadedIdx:[55]` → spray face #55's `m_status` overwritten to Success(3)
- `C: CRASHED` → AB sentinel data had invalid enum → `RELEASE_ASSERT`

**CSSFontFace layout (192 bytes):**
- Offset 130: `m_status` (1 byte) — **UAF write target** (writes 3=Success or 4=Failure)
- Offset 144-191: `m_timeoutTimer` (Timer, 48 bytes)
  - Offset 176: `m_thread` (Ref<Thread>) — **RELEASE_ASSERT blocker**

**Why it's blocked:**
`setStatus(Success)` unconditionally calls `m_timeoutTimer.stop()`, which calls `setNextFireTime()` at Timer.cpp:469: `RELEASE_ASSERT(canCurrentThreadAccessThreadLocalData(m_thread))`. AB spray puts garbage at offset 176 → Thread check fails → crash. Same-type groom works but 1-byte `m_status=3` write is harmless (no secondary corruption). CSSFontFace is the **sole occupant** of the 192-byte size class.

**Unblock condition:** Leak of `Thread::current()` address to craft valid Timer at offset 176. Or find a `setStatus()` code path that avoids Timer access (none exists for Success/Failure triggers).

---

## 3. ReadableStream tee() Type Confusion

**Status:** CONFIRMED on device, BLOCKED by JS builtin wall

**Bug:** `InternalReadableStream::fromObject()` (line 76-79) wraps ANY JSObject as InternalReadableStream with zero type check. By poisoning `Array.prototype[Symbol.iterator]` during `rs.tee()`, the SequenceConverter accepts attacker objects as stream branches.

**Two primitives confirmed:**

**Object substitution (V432):** Replace branch2 with any JSObject → `fromObject()` wraps it as a real ReadableStream (`instanceof` = true). `.locked` returns false, `.getReader()` throws.

**Short-result crash (V430/V432), not a stale-byte read:** returning one iterator element reaches the missing second result, but teardown clears the Strong slots and the checked Vector access terminates. Later source/device analysis attributes the crash to null/bounds failure, not an observable 8-byte heap disclosure.

**Device evidence (V432):**
- Plain object wrapped as ReadableStream: confirmed
- ArrayBuffer wrapped as ReadableStream: confirmed
- OOB read: crashes at INTERCEPT (ungroomed)

**Why it's blocked:**
Every InternalReadableStream method goes through `invokeReadableStreamFunction()` → JS builtins. JS builtins read private slots via `@getByIdDirectPrivate`, which returns `undefined` on fake objects. No C++ code path directly accesses internal stream fields. Type confusion only manifests in JavaScript-level behavior, not memory corruption.

---

## 4. Private-Name Inversion via tee()

**Status:** CONFIRMED LIVE on device

**Bug:** Poisoning `Array.prototype[Symbol.iterator]` to yield the same object X twice to `tee()` → engine writes ReadableStream private slots (`disturbed`, `state`, `readableStreamController`) onto X.

**Device evidence:**
- `pidInverted=true` — `firstThrow=TypeError, secondThrow=none`
- Signal: `pair[0].cancel()` writes slots → `pair[1].cancel()` sees `state==@streamClosed` → resolves without throw

**Why it's contained:**
Same JS builtin wall as #3. Controller written to X is real, but operations go through JS builtins that handle state correctly. No memory corruption path from this alone.

---

## 5. TransformStream Double-Iteration Disconnect (V429)

**Status:** CONFIRMED on device

**Bug:** Override `Array.prototype[Symbol.iterator]` during `new ReadableStream(underlyingSource, strategy)` where strategy returns a TransformStream's readable/writable. The C++ layer stores attacker-supplied streams while JS internals use the real streams. This creates a disconnect where data flows through the real pipeline but control references point to attacker objects.

**Device evidence (V429):**
- Double-iteration substitution confirmed
- C++ stores attacker streams, JS internals use real streams
- Pipeline stays consistent under test

**Why it's contained:**
Same JS builtin wall. All stream operations on the confused references go through JS builtins.

---

## 6. HTMLParser Custom Element Double-Parent

**Status:** UNFIXED in WK-1400 source, BLOCKED by post-construction validation

**Bug:** HTML parser `insert()` at HTMLConstructionSite.cpp:137 has `ASSERT(!task.child->parentNode())` — stripped in release. `parserAppendChild()` blindly appends without checking parentNode. A custom element constructor that calls `altDiv.appendChild(this)` creates dual membership — element in both parent's child list and altDiv's child list.

**Why it's blocked:**
Post-construction validation at JSCustomElementInterface.cpp:173 checks `wrappedElement->parentNode()` — if non-null, throws NotSupportedError and creates HTMLUnknownElement fallback. Device-confirmed (V415): fallback inserted in original container, real element stays in altDiv.

**Open lead:** Microtask checkpoint at line 156 runs BETWEEN construction and validation. `document.write()`, DOM removal, or `document.open()` might bypass validation — untested.

---

## 7. CVE-2026-43727 — Clipboard Iterator UAF

**Status:** Real bug, BLOCKED by missing API

**Bug:** `clearItemTypeLoaders` invalidates iterators during clipboard operations.

**Why it's blocked:**
Clipboard API is absent on PS5 14.10 (`navigator.clipboard` undefined despite `isSecureContext: true`).

---

## Summary

| Vuln | Bug Class | Wall | Status |
|------|-----------|------|--------|
| CVE-2026-43720 Canvas | UAF | ~~IsoHeap~~ OFF | Typed Canvas-state alias confirmed; no native disclosure or arbitrary R/W |
| CVE-2026-43715 CSSFontFace | UAF write | Timer RELEASE_ASSERT | DoS-only, sole 192B occupant |
| tee() type confusion | Type confusion | JS builtin dispatch | Contained |
| Private-name inversion | Slot injection | JS builtin dispatch | Contained |
| TransformStream disconnect | Reference confusion | JS builtin dispatch | Contained |
| HTMLParser CE | Double-parent | Post-construction validation | Microtask bypass untested |
| CVE-2026-43727 Clipboard | Iterator UAF | Missing API | Dead (no Clipboard API) |

**CVE-2026-43720 remains the primary exploitation vector.** IsoHeap is OFF on PS5 and same-type reclaim gives typed Canvas state R/W. A separate disclosure or a second corruption that exposes raw bytes is still required before the chain can become: fake lineDash Vector → arbitrary R/W → vtable hijack → ROP → kernel.
