# Confirmed Vulnerabilities  - PS5 14.10

Real memory safety bugs confirmed on device. Each hit a secondary wall that prevents full exploitation without an additional primitive.

> **Status key:** CONFIRMED = bug triggers on device. BLOCKED = exploitation blocked by secondary defense. The bugs are real  - they become exploitable if the blocking wall is bypassed.

---

## 1. CVE-2026-43720  - Canvas getContext() Reentrant UAF

**Status:** CONFIRMED on device  - IsoHeap OFF on PS5, same-type reclaim + R/W WORKING

**Bug:** `HTMLCanvasElement::getContext()` checks `m_context` at line 226, then calls `convert<IDLDictionary>()` at line 268 for settings. Dictionary conversion invokes JS property getters. A getter re-enters `getContext('2d')` on the same canvas  - inner call creates context, outer call overwrites `m_context` via `unique_ptr` assignment, freeing the inner context while its JS wrapper survives.

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
- V527/V527b (cobra PR#13): AB reclaim of 768B slot, lineWidth=9999.99 readback
- V548-V550: Alias CONFIRMED, full state R/W via aliased pair
- V562: ALL 12 Canvas2D APIs work through alias  - clean complete run
- V573: Full same-type reclaim + bidirectional R/W on PS5 14.10
- V589: BMR trigger confirmed working (`uaf-ok: inner=OK`)
- V630: Comprehensive alias diagnostic  - ALL 12 Canvas2D APIs confirmed working through alias:
  - lineWidth/miterLimit/globalAlpha: bidirectional double R/W
  - fillStyle/strokeStyle: color string R/W
  - font: string R/W
  - setLineDash(500)/getLineDash: 500-double array round-trip PERFECT
  - getTransform: DOMMatrix object read
  - save/restore: 3-level cycle (333→222→111) works
  - createPattern: HTMLCanvasElement pattern creation works
  - measureText: TextMetrics object returned correctly
- V632: Two-stage test (alias + zero-alloc freed reads)  - Stage 1 alias confirmed
- V641: Blob/Worker/Fetch transfer race tests  - all DontInitialize paths return zeros

**IsoHeap is OFF on PS5.** `WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on FreeBSD/PlayStation. Gigacage also disabled  - AB backing stores share the same heap as JSC/WebCore objects. Confirmed by Synacktiv writeup + BPlatform.h:341 `BPLATFORM(PLAYSTATION)`.

**Confirmed primitives:**
1. Same-type Canvas2D reclaim: 500x canvas spray reclaims freed 768B slot
2. Bidirectional R/W: lineWidth, miterLimit, globalAlpha, fillStyle, getTransform, getLineDash all work through stale wrapper
3. State buffer reclaim: 8 saves → 6400B out-of-line buffer, AB spray can reclaim

**Info leak candidate (OOB state stack read):**
Inner ctx created with 8 saves → `m_stateStack.m_size=9`. After BMR free + same-type reclaim, new ctx has 0 saves (`m_size=1`). Stale wrapper reads `m_stateStack.last()` using stale `m_size=9` → `buffer[8]` = offset 3200 = 2800 bytes past end of 1-State buffer. Reads adjacent heap allocations as float64. 48-bit x86-64 pointer is exactly representable as float64. libpas uses out-of-band bitmap tracking  - freed chunks retain all stale data, not zeroed.

**Current blocker:** INFO LEAK. All 12 Canvas2D APIs return typed JS values  - no path found to read a raw heap pointer. 10 dedicated info leak paths exhausted (see DEAD_ENDS.md "Info Leak Paths" section). Freed memory reads crash (destructor nulls m_stateStack.m_buffer). AB reclaim zeros data. DontInitialize AB paths return zeros on device. Community help wanted on the info leak primitive.

> **Issue #70 clarification:** `README.md` and `docs/RESEARCH_MAP.md`/`docs/STRATEGY.md` separately report a second info-leak candidate, APNG overread (V674), with a reported device result of 1651 heap pointers. That count is not independently re-verified here and the four documents reviewed here do not identify an original same-session raw capture/producer independently checked by our team. This alone does not establish that the "Current blocker" status above has been resolved; the precise remaining prerequisite requires maintainer clarification.

**Exploitation chain once info leak is solved:** fake lineDash Vector → arbitrary R/W → vtable hijack → ROP → kernel.

**Fix:** Commit 2693828e8d73 (2026-06-29): re-checks `m_context` after dictionary conversion. Not present in WK-1400.

---

## 2. CVE-2026-43715  - CSSFontFace UAF Write

**Status:** CONFIRMED on device, BLOCKED by Timer RELEASE_ASSERT

**Bug:** During `CSSFontFace::setStatus()`, `iterateClients` copies `Ref<Client>` (not `Ref<CSSFontFace>`). Client callback resolves a `DOMPromiseProxy` which fires a synchronous `.then` getter. The getter modifies `@font-face` rules via `setProperty()`, triggering `remove()` + `adopt()` which drops the last `Ref<CSSFontFace>`. The old face is FREED. `iterateClients` returns and `m_status = newStatus` at line 595 **writes to freed memory**.

**Device evidence (p458):**
- `A-RESULT: THEN-1-status=loading` → `.then` fires DURING `iterateClients`
- `B-CHECK: loadedIdx:[55]` → spray face #55's `m_status` overwritten to Success(3)
- `C: CRASHED` → AB sentinel data had invalid enum → `RELEASE_ASSERT`

**CSSFontFace layout (192 bytes):**
- Offset 130: `m_status` (1 byte)  - **UAF write target** (writes 3=Success or 4=Failure)
- Offset 144-191: `m_timeoutTimer` (Timer, 48 bytes)
  - Offset 176: `m_thread` (Ref<Thread>)  - **RELEASE_ASSERT blocker**

**Why it's blocked:**
`setStatus(Success)` unconditionally calls `m_timeoutTimer.stop()`, which calls `setNextFireTime()` at Timer.cpp:469: `RELEASE_ASSERT(canCurrentThreadAccessThreadLocalData(m_thread))`. AB spray puts garbage at offset 176 → Thread check fails → crash. Same-type groom works but 1-byte `m_status=3` write is harmless (no secondary corruption). CSSFontFace is the **sole occupant** of the 192-byte size class.

**Unblock condition:** Leak of `Thread::current()` address to craft valid Timer at offset 176. Or find a `setStatus()` code path that avoids Timer access (none exists for Success/Failure triggers).

---

## 3. ReadableStream tee() Type Confusion

**Status:** CONFIRMED on device, BLOCKED by JS builtin wall

**Bug:** `InternalReadableStream::fromObject()` (line 76-79) wraps ANY JSObject as InternalReadableStream with zero type check. By poisoning `Array.prototype[Symbol.iterator]` during `rs.tee()`, the SequenceConverter accepts attacker objects as stream branches.

**Two primitives confirmed:**

**Object substitution (V432):** Replace branch2 with any JSObject → `fromObject()` wraps it as a real ReadableStream (`instanceof` = true). `.locked` returns false, `.getReader()` throws.

**OOB read (V430/V432):** Return only 1 element from iterator → `results[1]` reads 8 bytes past Vector allocation. ASSERT compiled out on PS5. Crashes on ungroomed heap.

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
- `pidInverted=true`  - `firstThrow=TypeError, secondThrow=none`
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

**Bug:** HTML parser `insert()` at HTMLConstructionSite.cpp:137 has `ASSERT(!task.child->parentNode())`  - stripped in release. `parserAppendChild()` blindly appends without checking parentNode. A custom element constructor that calls `altDiv.appendChild(this)` creates dual membership  - element in both parent's child list and altDiv's child list.

**Why it's blocked:**
Post-construction validation at JSCustomElementInterface.cpp:173 checks `wrappedElement->parentNode()`  - if non-null, throws NotSupportedError and creates HTMLUnknownElement fallback. Device-confirmed (V415): fallback inserted in original container, real element stays in altDiv.

**Open lead:** Microtask checkpoint at line 156 runs BETWEEN construction and validation. `document.write()`, DOM removal, or `document.open()` might bypass validation  - untested.

---

## 7. CVE-2026-43727  - Clipboard Iterator UAF

**Status:** Real bug, BLOCKED by missing API

**Bug:** `clearItemTypeLoaders` invalidates iterators during clipboard operations.

**Why it's blocked:**
Clipboard API is absent on PS5 14.10 (`navigator.clipboard` undefined despite `isSecureContext: true`).

---

## Summary

| Vuln | Bug Class | Wall | Status |
|------|-----------|------|--------|
| CVE-2026-43720 Canvas | UAF | ~~IsoHeap~~ OFF | **R/W CONFIRMED**, info leak candidate found |
| CVE-2026-43715 CSSFontFace | UAF write | Timer RELEASE_ASSERT | DoS-only, sole 192B occupant |
| tee() type confusion | Type confusion | JS builtin dispatch | Contained |
| Private-name inversion | Slot injection | JS builtin dispatch | Contained |
| TransformStream disconnect | Reference confusion | JS builtin dispatch | Contained |
| HTMLParser CE | Double-parent | Post-construction validation | Microtask bypass untested |
| CVE-2026-43727 Clipboard | Iterator UAF | Missing API | Dead (no Clipboard API) |

**CVE-2026-43720 is the primary exploitation vector.** IsoHeap is OFF on PS5  - same-type reclaim gives full R/W. The OOB state stack read via save-count mismatch is a strong info leak candidate. Once a heap address is confirmed, the chain is: fake lineDash Vector → arbitrary R/W → vtable hijack → ROP → kernel.
