# Self-reference, string-as-CRC2D, and address discovery without APNG

**Scope:** PS5 14.10 WK-1400 tree at
`/home/violence/Work/WebKit-1400/WebKit-1400/WebKit-1400`
(`Configurations/Version.xcconfig` = `616.1.27.211.1`).
Cross-checked against `.webkit-src` where noted.
This note answers four questions:

1. Can `m_stateStack.m_buffer` be made to point into the reclaiming string
   without knowing any address?
2. If not, what second technique can discover the address of a sprayed
   string / of the reclaimed 768-byte slot?
3. Can any JS/DOM API leak a heap address on this build?
4. Is there any Canvas2D getter that does not go through `state()`?

**Bottom line:** (1) no, not from string bytes alone; (2) the practical
route is the crash oracle with an `ArrayBuffer(768)` reclaim plus a
*marker scan* of an already-mapped region, and the `save()` oracle
already proves which AB is in the slot. That yields arbitrary **read**
immediately; arbitrary **write** additionally needs one live
`CanvasBase*` for `m_canvas`, because every state setter ends in a
virtual `drawingContext()` call (5.3). (3) no JS API on this build
exposes a heap address (all the usual candidates are dead and the reason
is source-level); (4) only `canvas`, `getContextAttributes`, the
constant `webkitBackingStorePixelRatio`, and `save()`/`restore()` avoid
`state()`, and none of them yields a pointer.

---

## 0. Corrected offsets (read this first)

The project docs (`docs/bugs/canvas-getcontext-uaf.md`,
`docs/analysis/struct-layouts.md`) list the state-stack Vector as
`m_buffer, m_size, m_capacity`. That order is wrong for WK-1400.
`WTF::VectorBufferBase` is (`Source/WTF/wtf/Vector.h:395-397`):

```cpp
T* m_buffer;
unsigned m_capacity;
unsigned m_size;
```

So for `Vector<State, 1> m_stateStack` at `CRC2D + 112`:

| CRC2D offset | Field | Notes |
|---:|---|---|
| +112 | `m_buffer` (8) | `State*`; inline state is at +128 |
| +120 | `m_capacity` (u32) | **not** `m_size` |
| +124 | `m_size` (u32) | this is what `last()` indexes |
| +128 | inline `State[1]` | Vector base is 16 bytes, State aligned 8 |

Consequences:

* `state()` = `m_stateStack.last()` = `m_stateStack.at(m_size - 1)`
  (`CanvasRenderingContext2DBase.h:311`, `Vector.h:807-808`).
* `at()` takes a `size_t` (`Vector.h:775-786`). With `m_size == 0`,
  `size() - 1` is `SIZE_MAX`, and `m_buffer + SIZE_MAX*sizeof(State)` is
  `m_buffer - sizeof(State)` (see 0.1 for why that is 400 or 448).
  (`CrashOnOverflow::overflowed()` is
  `ASSERT_NOT_REACHED()` and compiles away when `ASSERT_ENABLED=0`;
  do not rely on this in a debug build.)
* `m_size = 1` reads `m_buffer[0]`; `m_size = 2` reads
  `m_buffer + sizeof(State)`. So with one chosen `m_buffer` value you
  can select `-S`, `0`, `+S`. That is the only arithmetic the primitive
  gives you for free.
* The AB-forge probes that write `capacity` at +120 and `size` at +124
  (e.g. `probes/deployed/fa-v696-sametype-forge.html`) are correct.
  Probes that write "`m_size` at +120" only (older drafts, e.g. the
  comment block in `probes/canvas-uaf/v587.html`) set capacity and
  leave size at 0; a `lineWidth` read then lands one `State` earlier
  than intended, which looks like a "hit" if the target page is mapped.

### 0.1 `sizeof(State)` is not settled -- and it changes the state-buffer class

The member order in `CanvasRenderingContext2DBase.h:436-444` is

```cpp
Vector<State, 1> m_stateStack;   // +112: 16-byte Vector base + inline State[1]
FloatRect m_dirtyRect;           // 16 bytes
unsigned m_unrealizedSaveCount;  // right after m_dirtyRect
```

So `offsetOf(m_unrealizedSaveCount) = 112 + 16 + sizeof(State) + 16
= 144 + sizeof(State)`.

* The project docs say `sizeof(State) = 400` **and**
  `m_unrealizedSaveCount = +592`. Those cannot both be true:
  400 would put the counter at **+544**, while +592 implies
  `sizeof(State) = 448`.
* This is not cosmetic. Eight lazy saves make the vector grow
  1 -> 2 -> 4 -> 8 -> 16 States. The out-of-line request is
  `16 * sizeof(State)`: **6400 bytes (bmalloc class 6656)** for 400, or
  **7168 bytes (bmalloc class 7168)** for 448. The V587/V589 state-buffer
  spray uses 3200-6400-byte ABs, which can never land on a 7168-byte
  buffer. If the true size is 448, that whole plan was dead on arrival
  for a second reason (the first is the destructor nulling in section 4).
* The same 48-byte uncertainty shifts everything after the inline State
  (`m_dirtyRect`, `m_unrealizedSaveCount`, `m_settings`, ...). The
  inline State itself still starts at +128 and the State-internal field
  offsets are unchanged. The counter offset should be calibrated on
  device, not assumed.

Cheap calibration that needs no address: after the UAF + AB(768)
reclaim, call `save()` N times through the stale wrapper (use a
distinctive N such as 0xBEEF) and scan the **whole 768-byte AB** for
the 32-bit value N, stepping by 4. `V696` scans only +580..+608;
widen it. A hit at offset `X` gives `sizeof(State) = X - 144` directly
(and tells you the counter offset). This also validates the reclaim:
if no AB contains N, the AB did not take the slot, or the counter is
not where you think.

---

## 1. The string reclaim: exactly what the engine writes

`'A'.repeat(748)` goes through `repeatCharacter()` ->
`StringImpl::tryCreateUninitialized(748, buffer)` and `std::fill_n`
(`Source/JavaScriptCore/runtime/JSStringInlines.h:86-100`).
`StringImpl` allocates one block of `tailOffset + length` bytes with the
characters inline at `B + 20` (`StringImpl.h`, `tailOffset<LChar>() =
20`; see `.tmp/jsc-charcodeat-addendum.md` for the derivation).
`20 + 748 = 768`, which is exactly a bmalloc size class
(`Source/bmalloc/bmalloc/Sizes.h`: `logObjectSize(3) = 768`; the class
covers requests 705..768).

So a 748-char Latin-1 string produces this at the reclaimed slot `B`:

| Offset | Bytes | Written by |
|---:|---|---|
| +0 | `m_refCount` = 1 (u32) | StringImpl ctor |
| +4 | `m_length` = 748 (`0x2EC`, u32) | StringImpl ctor |
| +8 | `m_data8` = **`B + 20`** | StringImpl ctor |
| +16 | `m_hashAndFlags` (u32) | StringImpl ctor |
| +20..+767 | 748 characters | `fill_n` |

**The string content cannot express `B`.** The only occurrence of `B`
anywhere in the 768 bytes is the engine-written `B+20` at +8. Every
byte at +20 and above is a constant chosen before the allocation. There
is no `memcpy`/`realloc` in the string path that would copy `B+20` down
into the controlled region, and `StringImpl` is immutable after
construction.

Two tempting "partial overwrite" variants were checked and are
impossible in this allocator:

* **Short string in the 768 class.** A 768-class request needs
  `20 + L` in 705..768, so `L >= 685`; the write always passes +112.
* **`TextDecoder`/`StringBuilder` buffer with a short logical length.**
  `StringImpl::adopt(StringBuffer)` keeps the original allocation and
  only records the shorter length (`StringImpl.cpp:1498-1512`,
  `StringBuffer::shrink` only sets `m_length`). But to reach a
  768-byte *allocation* the decoder must consume ~705-768 input bytes.
  The LChar UTF-8 path emits at least one char per two input bytes
  (>=~353 bytes written); the UChar path allocates `length*2` and emits
  at least one UChar per three input bytes (>=256 bytes written, or
  384 for astral chars). Both always overwrite +112. `StringBuilder`
  either fills its buffer or `reifyString()` makes a small
  substring-sharing `StringImpl` (`StringBuilder.cpp:66-72`), so the
  768-byte buffer's first bytes are always written too.

So: **the freed 768-byte slot cannot be made self-referential by
content alone.** A valid address for `m_buffer` must come from somewhere
else.

---

## 2. The one free self-pointer, and why it is a dead end

At `B+8` the engine leaves `B+20`. In CRC2D terms offset +8 is
`ScriptWrappable::m_wrapper` (a `JSC::Weak<JSDOMObject>`, one pointer;
`Source/WebCore/bindings/js/ScriptWrappable.h:41-56`). After the string
reclaim the CRC2D's "wrapper" pointer is therefore **the address of the
string's own data**. This is the only self-reference the reclaim gives
you for free. It is not reachable:

* `ScriptWrappable::wrapper()` is only called by `toJS`/`getExistingWrapper`
  for the C++ object (`ScriptWrappableInlines.h:39-53`). No
  Canvas2D IDL attribute or method returns the
  `CanvasRenderingContext2D` itself. `canvas` returns `m_canvas`
  (`CanvasRenderingContext2D.h:43`); `getContextAttributes` returns
  `m_settings`; `HTMLCanvasElement::m_context` is a `unique_ptr` that
  the bug already replaced with the bitmaprenderer
  (`HTMLCanvasElement.h:192`, `HTMLCanvasElement.cpp:224-263`), so
  `getContext` cannot hand the stale 2d context back to `toJS`.
* The only other `toJS(CanvasRenderingContext2D)` call in the tree is
  the inspector's (`Source/WebCore/inspector/InspectorCanvas.cpp:135`).
  `InspectorFrontendHost` is `[LegacyNoInterfaceObject]` and is only
  installed in inspector pages, not in web content.
* `JSCanvasRenderingContext2DCustom::visitAdditionalChildren` and the
  weak owner use the JS wrapper's `wrapped()` and then `canvas()`
  (`m_canvas`, +32), never the C++ `m_wrapper`
  (`JSCanvasRenderingContext2DCustom.cpp:32-42`). GC reads *m_canvas*,
  not *m_wrapper*.
* If the stale JS wrapper is ever finalized, `clearWrapper()` ->
  `weakClear(m_wrapper, wrapper)` -> `Weak::clear()` treats `B+20` as a
  `WeakImpl` and does `pointer->clear()` then `m_impl = nullptr`
  (`WeakImpl.h:74-78, 121-128`). That writes the `Deallocated` enum at
  `B+28` and **zeroes the StringImpl's `m_data8` at B+8**, destroying
  the JS string. It does not disclose anything.

So the `m_data8` self-pointer cannot be consumed by any reachable path
today. It is worth keeping in mind as a fake-`WeakImpl` primitive if a
`toJS` on the context ever becomes reachable (e.g. an inspector surface
on a future firmware), but it is not usable for `lineWidth`.

---

## 3. Getter audit: what actually bypasses `state()`

`CanvasRenderingContext2DBase` getters are almost all one-liners over
`state()` (`CanvasRenderingContext2DBase.h:100-234`). The complete list
of paths that do **not** go through `m_stateStack`:

| IDL surface | Implementation | Reads | Reachable pointer? |
|---|---|---|---|
| `canvas` | `CanvasRenderingContext2D::canvas()` -> `downcast<HTMLCanvasElement>(canvasBase())` = `m_canvas` at +32 (`CanvasRenderingContext2D.h:43`, `CanvasRenderingContext.h:65,123`) | +32 | yes, but needs a *valid* pointer; `toJS` reads fake+`offsetOfWrapper`, refs/derefs fake, etc. |
| `getContextAttributes()` | returns `const CanvasRenderingContext2DSettings& m_settings` (`...Base.h:100`) | tail of object | only `bool desynchronized`, `PredefinedColorSpace colorSpace`; no deref |
| `webkitBackingStorePixelRatio` | `static constexpr float ... { return 1; }` | none | no |
| `save()` | `++m_unrealizedSaveCount` at +592 (`...Base.h:143`) | none | no |
| `restore()` | if `m_unrealizedSaveCount` nonzero, decrement; else if `m_stateStack.size() <= 1` return (`...Base.cpp:459-479`) | +592, +124 | no deref on the early-return path |

Everything else -- `lineWidth`, `miterLimit`, `globalAlpha`,
`globalCompositeOperation`, `lineCap`, `lineJoin`, `lineDashOffset`,
`shadowOffsetX/Y`, `shadowBlur`, `shadowColor`,
`imageSmoothingEnabled`, `imageSmoothingQuality`, `font`, `textAlign`,
`textBaseline`, `direction`, `fillStyle`, `strokeStyle`, the `webkit*`
aliases, `getLineDash`, `getTransform` -- begins with `state()`.

Drawing/text/imageData methods (`measureText`, `fillText`, `fill`,
`stroke`, `drawImage`, `createImageData`, `getImageData`,
`createPattern`, ...) reach the canvas through
`canvasBase()`/`drawingContext()` and therefore dereference `m_canvas`
at +32 *before* or in addition to `state()`. `setLineDash` does
`realizeSaves()` then `modifiableState().lineDash = ...`, so it needs
both `m_unrealizedSaveCount == 0` and a valid `m_buffer`.

`m_path` (a `std::variant` inside `CanvasPath` at +40/+48) is read by
`beginPath`, `moveTo`/`lineTo`/`rect`/..., `isPointInPath`,
`getPath`, `setPath`, `drawFocusIfNeeded`. None of these yields a heap
pointer as a value, and the variant is attacker-controlled only as
constants.

**No Canvas2D getter returns a pointer-derived number.** The only
pointer-shaped engine value in the object is the `m_data8` self-pointer
in the `m_wrapper` slot, and nothing above consumes it.

---

## 4. Why the documented "state-buffer free -> AB reclaim" plan is broken

The current chain doc (steps 4-8) is: grow the state stack out-of-line
to `M`, let the BMR outer `getContext` destroy the 2d context (freeing
`M`), spray `ArrayBuffer(6400)` so one AB lands on `M`, then read
`lineWidth` through the stale wrapper so `m_buffer` points into the AB.

In WK-1400 the destruction nulls the pointer you need:

```cpp
// Vector.h:500-503
~VectorBuffer() { deallocateBuffer(buffer()); }

// Vector.h:513-518 (inline-capacity version)
void deallocateBuffer(T* bufferToDeallocate)
{
    if (bufferToDeallocate == inlineBuffer())
        return;
    Base::deallocateBuffer(bufferToDeallocate);
}

// Vector.h:349-360
void deallocateBuffer(T* bufferToDeallocate)
{
    if (!bufferToDeallocate) return;
    if (m_buffer == bufferToDeallocate) {
        m_buffer = nullptr;
        m_capacity = 0;
    }
    Malloc::free(bufferToDeallocate);
}
```

So on destruction of an out-of-line stack:

* CRC2D +112 (`m_buffer`) = 0
* CRC2D +120 (`m_capacity`) = 0
* CRC2D +124 (`m_size`) **unchanged** (the destructor never touches it)

After that, `lineWidth` computes `nullptr[m_size-1]`:
`m_size = 9` -> address `3200`, `m_size = 0` -> address `-400`. Both
are unmapped; the AB reclaim of `M` never gets a chance because its
address is no longer in the object.

Two side notes that matter:

* If the context is destroyed while the stack is still **inline**
  (`m_buffer == inlineBuffer()`), `deallocateBuffer` returns early
  *without* nulling. The freed 768-byte block then still holds
  `m_buffer = B+128`, `capacity = 1`, `size = 1` -- a valid
  self-pointer into the freed block. That is the only free
  self-reference the destruction path leaves behind, and it only ever
  points at the old inline State.
* `CanvasRenderingContext::ref()`/`deref()` are *not* refcounts of the
  context; they forward to `m_canvas.refCanvasBase()`/
  `derefCanvasBase()` (`CanvasRenderingContext.cpp:80-88`). The
  `JSDOMWrapper`'s `Ref` therefore touches +32, not the object
  lifetime. This is why a wrapper can outlive the context, and why
  `m_canvas` must stay plausible if the wrapper is ever destroyed.

### 4.1 A repair primitive: grow-after-free re-creates `m_buffer`

If the context is destroyed while the stack is inline and
`m_unrealizedSaveCount` is nonzero (it is *not* reset by destruction;
it is a plain `unsigned` at +592), then a later setter on the stale
wrapper resurrects the vector **inside the freed block**:

1. UAF -> slot `B` freed.
2. Same-type reclaim with a fresh CRC2D `C`: `m_buffer = B+128`,
   `size = 1`, `capacity = 1`.
3. `C.save()` x N (lazy: only `m_unrealizedSaveCount` at +592 grows).
4. Destroy `C` **without running GC while it is pinned**. The
   straightforward BMR replacement is not available here: the canvas
   that owns `C` already has a 2d `m_context`, so the outer
   `getContext('bitmaprenderer', ...)` returns at the early
   `m_context->is2d()` check before converting arguments
   (`HTMLCanvasElement.cpp:226-241`). GC is also blocked: whenever the
   stale wrapper `W` is marked, `visitAdditionalChildren` adds
   `wrapped().canvas()` (= `C`'s canvas) as an opaque root
   (`JSCanvasRenderingContext2DCustom.cpp:38-42`), so `C` and its canvas
   are uncollectible while `W` is alive. The remaining candidates are
   synchronous document/frame teardown (remove a same-origin iframe
   while the parent holds `W`, navigate the frame, `document.open`,
   ...), which frees the canvas and its `m_context` without GC. That
   path is unverified on device and would need a dedicated probe.
   If it works: the vector is still inline at destruction, so the
   destructor does **not** null +112. `B` is freed with
   `m_buffer = B+128`, `size = 1`, `capacity = 1`, and +592 = N.
5. Call a setter through the stale wrapper, e.g. `innerCtx.lineWidth = v`.
   `setLineWidth` does `state()` (valid, `B+128`), then
   `realizeSaves()` -> `m_stateStack.append(state())` N times.
   `Vector::reserveCapacity` (`Vector.h:1284-1308`) sees
   `capacity == inlineCapacity == 1`, mallocs a new buffer `M`
   (2, 4, ... then 16 States = ~6400 bytes), moves the inline State
   there, and **writes `M` into the freed `B+112`**, with
   `m_capacity = 16`, `m_size = N+1`.

You now have a freed 768-byte block that contains a live, engine-written
`m_buffer = M` and a valid `size`. `lineWidth`, `globalAlpha`,
`miterLimit`, `getTransform`, `getLineDash` etc. all work through the
stale wrapper again, and `M` stays allocated forever (the Vector that
owned it no longer exists, so nothing frees it).

What this does **not** give you is `M`'s value or a way to place it in a
JS-visible object: no getter returns `m_buffer`, and the only objects
that consume +112 as a vector are `CanvasRenderingContext2D` instances,
whose constructors overwrite +112. Reclaiming `B` with an
`ArrayBuffer(768)` memsets all 768 bytes, so it wipes `M` too. It is a
useful way to *repair* the state pointer in freed memory for further
same-object experiments, not a leak.

---

## 5. Address discovery without APNG

### 5.1 The dead ends (and why they are dead)

All of these were checked against the WK-1400 source / the device API
fingerprint (`docs/API_FINGERPRINT.md`):

* **`WeakRef` / `FinalizationRegistry`.** `WeakRef.prototype.deref` is a
  native function returning the target `JSObject*` or `undefined`
  (`JSWeakObjectRef.cpp`, `WeakObjectRefPrototype.cpp`). The
  `Symbol.toStringTag` is a literal (`JSC_TO_STRING_TAG_WITHOUT_TRANSITION`),
  so `String(new WeakRef(x))` is `"[object WeakRef]"`. No address, no
  bit pattern. `FinalizationRegistry` callbacks carry held values, not
  addresses.
* **Comparing ArrayBuffer backing stores.** There is no JS-visible
  identity of a backing store. `slice` copies, `structuredClone` copies,
  `transfer` moves ownership and detaches the source; none of these
  expose or preserve an observable address. Two buffers cannot alias
  without SAB.
* **`postMessage` transfer.** Moves the same allocation to another
  realm and detaches the source; the pointer lives in
  `ArrayBufferContents::m_data` (`ArrayBuffer.cpp:119-147`) and is
  never converted to a JS number.
* **SharedArrayBuffer.** Not available (device-confirmed). `Atomics`
  alone is useless.
* **ResizableArrayBuffer.** Present, but `resize` goes through
  `BufferMemoryManager`/`OSAllocator` and only changes
  `m_sizeInBytes`/`m_maxByteLength`; no address is exposed. The
  documented RAB byteLength inversion is dead (all sinks re-validate).
* **`Error.stack`, `Function.prototype.toString`, `console`, `Intl`,
  `performance.now`.** No addresses on this build; already audited in
  `docs/FINDINGS.md`.
* **`debugDescription()` strings.** Several WebCore classes build
  `"Event 0x%p"`, `"Document 0x%p"`, `"CSSStyleSheet 0x%p"` etc.
  (`Event.cpp:192`, `Document.cpp:9601`, `CSSStyleSheet.cpp:474`), but
  `debugDescription` is not in any `.idl`, is not a `toString`, and is
  only used by `TextStream` logging. Not reachable from JS.
* **Inspector surfaces.** `InspectorCanvas` does
  `toJS(ctx)` (`InspectorCanvas.cpp:135`), which would consume the
  fake `m_wrapper` at +8. But `InspectorFrontendHost` is
  `[LegacyNoInterfaceObject]`/inspector-only and there is no inspector
  on the PS5 browser.

So an address must come from a memory primitive, not from a JS API.

### 5.2 The practical route: crash-oracle marker scan with a mutable AB reclaim

The key realisation is that **you do not need to scan with the string**.
The string is immutable, so it gives one probe per page load. An
`ArrayBuffer(768)` reclaimed at the same slot gives a JS-visible,
*mutable* fake `CanvasRenderingContext2D`: you can rewrite
`m_buffer` (+112), `m_capacity` (+120) and `m_size` (+124) between
probes, and read `lineWidth` as an 8-byte read at `m_buffer + 48`.
`probes/deployed/fa-v696-sametype-forge.html` already uses exactly this
and additionally confirms the reclaim without needing an address:
`save()` is non-virtual and does `++m_unrealizedSaveCount` (project
offset +592; calibrate per 0.1). Write a distinctive number of saves
through the stale wrapper and scan every 4-byte offset of the sprayed
ABs for that number -- the AB that contains it is at the freed slot.

That gives you a confirmed, JS-writable window at `B` but still not
`B`'s value. To get it:

1. **Find one mapped address first.** The scan is only safe while every
   probe address is mapped; the first unmapped probe is a SIGSEGV and
   a WebProcess restart. Candidate anchors:
   * External VM-map intel (a *different* PS5 process, so only a
     hypothesis for WebContent): `SceLibcHeap 0x310744000-0x310754000`
     (rw), `0x310D40000`, heap objects `0x3105AF000-0x31071E000`,
     `mmap 0x310620000` (external research,
     `probes/canvas-uaf/v654.html` header).
   * FreeBSD's traditional fixed stack top `0x7FFFFxxxxxxx`, if PS5
     does not randomize the stack. V650 already tried this list.
   * The 24 MB window `0x310000000-0x311800000` used by V655.
   Probe a candidate with `m_buffer = candidate - 48` and `m_size = 1`;
   survive => mapped, crash => try the next guess after reload.
2. **Verify determinism across reloads.** This is the make-or-break
   assumption of the localStorage scanners: if the WebContent process
   is forked from a pre-warmed process with a fixed ASLR slide, the
   heap is identical after every crash and the map accumulates. If it
   is not, every crash reshuffles the heap and the cross-reload map is
   worthless. Test cheaply: probe the same anchor twice, once from a
   fresh page and once after a forced crash/reload. Same result =>
   deterministic enough; different => abandon this route and go back
   to APNG.
3. **Marker scan inside the confirmed mapped island.** Fill the
   reclaimed AB with a position-dependent table of *normal* doubles
   (avoid NaN), e.g. qword `k` = bits `0x4140000000000000 | k`.
   For each candidate `C` in the island, step 8 bytes, set
   `m_buffer = C`, `m_size = 1`, read `lineWidth`, convert the
   returned Number to bits through a `Float64Array`, and look the bits
   up in the table. The `save()` oracle from step 1 tells you *which*
   sprayed AB is at `B`; write only that one `DataView` per probe, not
   all 200. Because the read is `*(C + 48)`, a hit at table
   index `k` means `C + 48 = B + 8k`, so **`B = C + 48 - 8k`** -- one
   hit gives the exact slot address, not just "somewhere in the
   string". The forged `+112..+127` words are a 16-byte blind spot in
   the table; handle those indices separately. (For the anchor test in
   step 1, probe a literal address `A` by setting `m_buffer = A - 48`.)
   * Keep the loop allocation-free: `DataView.setUint32`/`getUint32`
     and double arithmetic do not allocate; `jsNumber(double)` in JSC
     is an inline bit pattern, not a heap double. Avoid string
     concatenation and beacon `Image` creation inside the scan.
   * `m_canvas` = 0 after the AB memset is *safe* for GC: the owner
     hashes the null opaque root (`AbstractSlotVisitorInlines.h:123-145`)
     and `addOpaqueRoot(0)` just returns false. It is only dangerous if
     the wrapper is destroyed (`deref()` -> `m_canvas.derefCanvasBase()`)
     or code calls `canvasBase()`/`drawingContext()`. Keep the wrapper
     strongly referenced and do not call drawing APIs during the scan.
4. **Once `B` is known, reads are immediate -- writes are not.** Set
   `m_buffer = B` (the AB is at `B`, so `state()` is now the AB itself,
   fully JS-controlled) and forge the `State` in the AB. The
   `lineDash` Vector at State+168 gives **arbitrary read**:
   `{m_buffer = target, m_capacity = N, m_size = N}` plus
   `getLineDash()` (the getter copies N doubles out and never touches
   `m_canvas`). `lineWidth`/`globalAlpha`/`miterLimit`/`shadowBlur`/
   `getTransform` are likewise m_canvas-free. The copy is a plain
   `double` load/store plus JSC's integer double encoding, so the
   subnormal-shaped pointer values should survive; prefer
   `getLineDash` over `lineWidth` for the actual dump and verify with
   the V696 DAZ baseline.
   The write half is blocked by `m_canvas`; see 5.3. Once a valid
   CanvasBase pointer is recovered with the new read primitive, the
   same forged State's `lineDash` copy-assignment writes in place
   (`setLineDash` when capacity >= N) and the full arbitrary R/W chain
   follows.

This is the answer to "what second technique can discover one of their
addresses": **use the mutable AB reclaim as the oracle, find any mapped
island once (fixed anchor or crash-scan), then marker-scan the island in
one page for the slot's own address**. It needs no APNG and no JS
address leak; it needs only that one mapped island is known and that
probing inside it does not crash.

### 5.3 The write-side catch: every setter goes through `m_canvas`

After an AB(768) reclaim, `m_canvas` at +32 is 0 (memset). Reads do not
care, but every state setter ends with a `drawingContext()` call:

```cpp
// CanvasRenderingContext2DBase.cpp:532-544
void CanvasRenderingContext2DBase::setLineWidth(double width)
{
    ...
    modifiableState().lineWidth = width;
    GraphicsContext* c = drawingContext();
    if (!c) return;
    c->setStrokeThickness(width);
}

// CanvasRenderingContext2DBase.cpp:706-715
void CanvasRenderingContext2DBase::applyLineDash() const
{
    GraphicsContext* c = drawingContext();   // <- m_canvas deref
    if (!c) return;
    ...
}
```

`drawingContext()` is `canvasBase().drawingContext()`; `CanvasBase::
drawingContext()` calls the **virtual** `renderingContext()`
(`CanvasBase.cpp:79-86`), i.e. a vtable dispatch through `m_canvas`.
With `m_canvas == 0` this is a null-vtable crash. So the V696-style
`setLineDash` write would perform the in-place copy and then die in
`applyLineDash()` -- a one-shot write followed by a process kill.

There are two ways past it:

* **Recover a live CanvasBase pointer with the read primitive.** Now
  that `B` is known, the 768 slab around `B` is addressable: allocate a
  batch of `CanvasRenderingContext2D` objects (each 768 bytes, same
  class) after the reclaim, then use `getLineDash` with
  `lineDash.m_buffer = B + delta` to dump the surrounding slab and look
  for a CRC2D shape (a code pointer at +0, a heap pointer at +32).
  Write that pointer into the AB's `m_canvas` and every setter works.
  A canvas whose current context is a `bitmaprenderer` is ideal:
  `CanvasBase::drawingContext()` returns nullptr early because the
  context is neither 2d nor offscreen-2d, so `applyLineDash()` returns
  without touching an ImageBuffer.
* **Forge a CanvasBase.** Not viable without a code leak: the first
  thing `drawingContext()` does is the virtual `renderingContext()`
  call, which reads a vtable pointer from `m_canvas + 0`. A fake
  CanvasBase therefore needs a real WebCore vtable address, i.e. the
  binary base.

The same catch applies to the string reclaim: chars 12..19 are
`m_canvas`, so `setLineDash` through a string-reclaimed context crashes
at `applyLineDash()` even when `m_buffer` is perfectly valid. Any
"bidirectional R/W" result in the probe logs must have come from the
same-type alias, where `m_canvas` is the real canvas.

### 5.4 The other promising route: reclaim with a non-string object that has a Vector at +112

A live `CanvasRenderingContext2D` is the known self-referential object:
its constructor writes `m_buffer = B + 128` at +112, `capacity = 1` at
+120, `size = 1` at +124, so `state()` works with no address knowledge.
That is the same-type alias, and it only ever reads the object's own
inline State.

The generalisation is worth a targeted search: **any 768-class WebCore
object whose field at +112 is a pointer to a buffer, and whose field at
+124 is a small `m_size`-like integer, turns the stale context into a
reader of that buffer.** If the buffer contains engine-written heap
pointers (a `Vector<Ref<T>>`, `Vector<String>`, queue of JSValues,
`Vector<KeyValuePair>`, etc.), then `lineWidth`/`globalAlpha`/
`miterLimit` read those pointers as float64 and you get a heap leak
with no address at all. The CRC2D itself is the template; its
destructor is the only reason the trick dies for it.

Test protocol (one candidate per page load):

1. UAF trigger, free `B`.
2. Allocate N candidates of the suspected class immediately; the class
   must be 705..768 bytes (bmalloc class 768).
3. Call `innerCtx.lineWidth`. Crash -> +112 was not a mapped pointer
   (or +124 was huge). Survive and return nonzero -> +112 pointed
   somewhere readable; record the value.
4. If it survives, call `globalAlpha`, `miterLimit`, `getTransform`,
   `getLineDash` to sample other offsets of the buffer.
5. If any returned double has the shape `0x0000000?xxxxxxxx`
   (PS5 user pointers are `0x00000003_xxxxxxxx`), you have a heap
   pointer; scan around it for the 768 slab.

Classes with vectors near the front and a JS-reachable allocation path
are the best candidates (`URLSearchParams`, `Headers`, `FormData`,
`DOMTokenList`, `MediaSource`/`SourceBuffer`, `TextTrackList`,
`DataTransferItemList`, `FontFaceSet`, `StaticNodeList`/`HTMLCollection`,
`SharedBuffer`-backed readers). The exact +112 offset depends on the
class hierarchy and member order, so this has to be measured, not
guessed from source alone.

### 5.5 The `canvas` getter as an amplifier *after* a leak

Once any address is known, `innerCtx.canvas` is the most powerful
non-`state()` surface: it reads `m_canvas` at +32 and calls `toJS` on
the fake `HTMLCanvasElement`. The generated wrapper creation reads the
fake object's `ScriptWrappable::m_wrapper` at `fake + offsetOfWrapper`,
and `JSDOMWrapper` stores `Ref<HTMLCanvasElement>` (so it calls
`HTMLCanvasElement::ref()` on the fake object). That turns a forged
pointer into a JS object whose `width`/`height`/`getContext`/style
operations read and write fields at controlled offsets. It is not a
bootstrap (it needs a valid pointer to begin with), but together with
the marker scan it is a clean second-stage primitive: it hands you a
real JS object whose C++ backing store is memory you control, without
having to forge a vtable by hand.

---

## 6. Recommended order of experiments

1. **Confirm the reclaim oracle** with V696 (`save()` -> scan ABs for
   the counter at +592). If the AB reclaim does not hit reliably, the
   whole scan route is moot; try allocating the AB immediately after
   the trigger (bmalloc is LIFO per size class) instead of spraying 200.
2. **Correct the vector offsets** in every probe/exploit to
   `m_capacity` +120 / `m_size` +124; re-run any "hit" that was
   obtained with the old +120-only write.
3. **Test one fixed anchor** (`0x310744000`, `0x7FFFFFFFC000`) with
   `m_buffer = anchor - 48`, `m_size = 1`. Repeat after a forced reload.
   This tests both "is there a fixed mapping" and "is the heap stable".
4. **If stable:** marker-scan the mapped island for `B` (5.2), then
   use `m_buffer = B` and the forged `lineDash` Vector for arbitrary
   **read**. Do not call a setter yet: `m_canvas = 0` (5.3) makes every
   setter die in `drawingContext()`.
5. **Recover one CanvasBase pointer** with the new read primitive: dump
   the 768 slab around `B` (allocate a batch of 2d contexts first so
   their `m_canvas` fields sit nearby), take a `+32` heap pointer from a
   CRC2D-shaped object, write it into the AB's `m_canvas`, then
   `setLineDash` gives arbitrary write. Prefer a canvas whose current
   context is a `bitmaprenderer` so `drawingContext()` returns nullptr
   early.
6. **In parallel:** try 2-3 candidate classes from 5.4 for a
   no-address heap leak.
7. **If neither works:** fall back to APNG, but use the V696 `save()`
   oracle to identify the reclaimed AB and the `lineWidth` crash oracle
   to validate the APNG pointers before dereferencing them -- this
   avoids the "AB spray crashes" confusion, which was a symptom of the
   destroyed Vector pointer, not of GC.

---

## 7. Source index

* `Source/WTF/wtf/Vector.h`: 349-360 (deallocate), 395-397 (field
  order), 483-518 (inline buffer/destructor), 775-808 (`at`/`last`),
  1227-1308 (grow/reserve).
* `Source/WebCore/html/canvas/CanvasRenderingContext2DBase.h`: 100
  (settings), 102-234 (getters), 311 (`state`), 436-444 (members).
* `Source/WebCore/html/canvas/CanvasRenderingContext2D.h`: 43
  (`canvas`).
* `Source/WebCore/html/canvas/CanvasRenderingContext.h`: 65, 118, 123.
* `Source/WebCore/html/canvas/CanvasRenderingContext.cpp`: 80-88
  (`ref`/`deref`).
* `Source/WebCore/html/HTMLCanvasElement.{h,cpp}`: 192 / 224-263,
  345-358.
* `Source/WebCore/bindings/js/ScriptWrappable.h`: 41-56;
  `ScriptWrappableInlines.h`: 39-53;
  `JSCanvasRenderingContext2DCustom.cpp`: 32-42.
* `Source/JavaScriptCore/heap/WeakImpl.h`: 64-78, 121-128.
* `Source/JavaScriptCore/runtime/JSStringInlines.h`: 86-100.
* `Source/WTF/wtf/text/StringImpl.{h,cpp}`: `tailOffset`, 1498-1512;
  `StringBuffer.h`: 48-62.
* `Source/bmalloc/bmalloc/Sizes.h`: `logObjectSize`.
* `Source/WebCore/inspector/InspectorCanvas.cpp`: 135;
  `InspectorFrontendHost.idl`: `[LegacyNoInterfaceObject]`.
