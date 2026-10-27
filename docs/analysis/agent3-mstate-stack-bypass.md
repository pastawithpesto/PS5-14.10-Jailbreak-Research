# Agent 3 — empty/huge `m_stateStack`, and a working string-reclaim read path

**Scope:** PS5 14.10, WK-1400 reference tree. Answers the specific question:
what happens when `Vector<State,1>` is empty or has a huge `m_size`, and can
`state()` be avoided? Cross-checked against
`docs/analysis/state-free-canvas-interactions.md` (agent 1) and
`.scratch/agent2_mmu_shared_page_findings.md` (agent 2). Corrections to both
are called out.

---

## TL;DR

1. **An empty stack does not read `m_data[-1]`.** In this WTF::Vector,
   `last()` is `at(size() - 1)` and `at()` has an unconditional bounds
   check. With `m_size == 0` it calls `CrashOnOverflow::overflowed()` →
   `CRASH()` → on PS5 release `WTFBreakpointTrap()` (SIGTRAP). There is no
   fallback and no read. The premise "`last()` = unchecked `m_data[m_size-1]`"
   (also stated in agent 1's doc) is wrong for WK-1400.
2. **A huge `m_size` cannot wrap the address space.** `m_size` is a 32-bit
   `unsigned`; max index is `0xFFFFFFFE`, max byte offset is
   `0xFFFFFFFE * 448 = 0x1BFFFFFFC80` (~1.75 TiB). No 48/64-bit wrap. And
   `m_buffer` is already a fully attacker-controlled 64-bit field, so a wrap
   would buy nothing even if it were possible.
3. The string reclaim **does** control `m_buffer`; the "unknown address"
   crash is a bad pointer / bad `m_size`, not a limitation of `state()`.
   The `StringImpl` data offset is **20** (not 24), so:
   `m_buffer` = string-data index **92**, `m_capacity` = **100**,
   `m_size` = **104**. Set `size = 1` and `m_buffer = B`; `lineWidth` then
   returns the 8 bytes at `B + 48` as an exact double.
4. The object is **728 bytes → bmalloc class 768**. A 704-byte string
   (agent 1's `len=342` 16-bit payload) is a different size class and
   **cannot** reclaim the context. Use a 768-byte request: 748 Latin-1
   bytes, or 374 UTF-16 code units.
5. `save()` gives a **JS-readable reclaim oracle and header-offset
   calibrator**: it increments the u32 at object `+592` (string-data index
   572 for a 20-byte header; 568 if the header were 24). After one `save()`,
   scan the sprayed strings with `charCodeAt(572)`; the string that changed
   is the reclaimer. No `state()`, no `m_canvas`, no vptr.
6. `getContextAttributes()` is a second, non-destructive reclaim check:
   `m_settings` is the last member at object `+720`, `desynchronized` at
   data index **700**. Zero the colour-space bytes so an invalid enum can
   never reach the unchecked `values[enum]` in the generated binding.
7. Fixed-address reality (agent 2 is right): the PS5 stack top is
   randomised, so `ps_strings`/auxv are **not** at a fixed address. The
   shared page is the only architectural fixed mapping and contains no
   user pointers. Use the read primitive with a leaked heap pointer
   (V674/V695) rather than a fixed pointer; the shared-page candidates are
   only a safe-ish smoke test.
8. Do **not** try to bootstrap a fake State by writing into the shared page
   with `lineWidth = ...`: the store happens, but `applyLineWidth()` calls
   `drawingContext()` → virtual `m_canvas->renderingContext()`, so a garbage
   `m_canvas` crashes right after the store and the COW copy dies with the
   process. You need a valid `m_canvas` first.
9. `reset()` (the one path that would self-heal `m_buffer = inlineBuffer()`)
   is not reachable from JS in this WebKit: no `reset` in the 2D IDL, and
   `HTMLCanvasElement::reset()` only resets its *current* context (the
   bitmaprenderer), never the stale 2D context.
10. DAZ is not a blocker for the double channel. JSC encodes a double as
    `bit_cast<int64>(d) + (1 << 49)` (integer add) and decodes by integer
    subtract; no FP operation is involved. A denormal pointer survives
    `getter -> JSValue -> Float64Array` bit-exactly **as long as JS does no
    arithmetic on the number** before storing it.

---

## 1. Exact empty-stack path (source)

`CanvasRenderingContext2DBase.h:311`

```cpp
const State& state() const { return m_stateStack.last(); }
```

`Source/WTF/wtf/Vector.h`

```cpp
807  T& last() { return at(size() - 1); }
775  T& at(size_t i)
776  {
777      if (UNLIKELY(i >= size()))
778          OverflowHandler::overflowed();
779      return Base::buffer()[i];
780  }
```

With `m_size == 0`, `size() - 1 == SIZE_MAX`, the check is true, and
`OverflowHandler` is the default `CrashOnOverflow`
(`Forward.h:99`). `CheckedArithmetic.h:100`:

```cpp
static NO_RETURN_DUE_TO_CRASH void overflowed() { crash(); }
static NO_RETURN_DUE_TO_CRASH void crash() { CRASH(); }
```

On PS5, `NDEBUG && PLATFORM(PLAYSTATION)` selects the inline-asm trap
(`Assertions.h:275-279`):

```c
#define CRASH() do { WTFBreakpointTrap(); __builtin_unreachable(); } while (0)
```

So: **SIGTRAP, deterministic, before any memory access.** The empty stack is
strictly a DoS/oracle-reset, never a leak. Also `modifiableState()` has only
an `ASSERT` and then calls the same `last()`, so setters die the same way.

---

## 2. Exact huge-`m_size` path

`VectorBufferBase` (`Vector.h:395-397`):

```cpp
T* m_buffer;
unsigned m_capacity;
unsigned m_size;   // 32-bit
```

`size()` widens the 32-bit value. `at(size()-1)` therefore indexes at most
`0xFFFFFFFE`, and the byte offset is `0xFFFFFFFE * sizeof(State)`:

| `sizeof(State)` | max byte offset | TiB |
|---:|---:|---:|
| 448 (correct) | `0x1BFFFFFFC80` | 1.75 |
| 400 (old note) | `0x18FFFFFFCE0` | 1.56 |

That is far below the 48-bit user limit (128 TiB) and far below 2^64, so the
index cannot wrap to a low/high fixed address. The "pick `m_size` so
`m_buffer + (m_size-1)*sizeof(State)` wraps to the shared page" idea cannot
work:

* the stride multiplication never overflows 64 bits (`< 2^41`);
* `m_size` cannot even express `0x0001000000000001` — it is truncated to
  32 bits;
* `m_buffer` is a full 64-bit field read from the reclaim data. If you knew
  a target address, you would write it directly and use `size = 1`; the
  wrap adds no capability.

The only real use of a large `m_size` would be to read at
`m_buffer + k*448` for `k < 2^32`; that still requires `m_buffer` to be a
mapped base, i.e. exactly the known-address problem.

---

## 3. What the string reclaim actually provides

`StringImpl` (`Source/WTF/wtf/text/StringImpl.h`):

* shape: `m_refCount` (+0), `m_length` (+4), `m_data8/16` (+8),
  `m_hashAndFlags` (+16) — 20 bytes;
* data starts at `tailOffset<T>() = roundUp(20, alignof(T)) = 20`
  (`StringImpl.h:1204`, `1192`, `1219-1226`); the allocation is
  `20 + length` (8-bit) or `20 + 2*length` (16-bit);
* `String.fromCharCode` with all arguments ≤ 0xFF takes the 8-bit path
  (`StringConstructor.cpp:64-90`), so **748 arguments ⇒ malloc(768)** and
  every object byte from +20 to +767 is directly controllable.

A 16-bit payload works too (374 code units ⇒ 20 + 748 = 768), but 8-bit is
simpler: byte index = object offset − 20.

**Object layout (self-consistent with the device-measured +112/+592):**

```
+0     StringImpl refCount/length          (engine)
+8     StringImpl m_data8  = object+20      (engine)  (was m_wrapper)
+16    StringImpl hashAndFlags = 4 (8-bit)  (engine)  (was weak factory)
+20    string data starts                   (controlled)
+24    m_checkedPtrCount                    data[4]
+28    m_hasActiveInspectorCanvasCallTracer data[8]
+32    m_canvas                             data[12]
+40    CanvasPath vptr                      data[20]
+48    Path variant                         data[28]
+112   m_stateStack.m_buffer                data[92]
+120   m_stateStack.m_capacity              data[100]
+124   m_stateStack.m_size                  data[104]
+128   inline State                         data[108]
+592   m_unrealizedSaveCount                data[572]
+600   m_recordingContext                   data[580]
+608   m_suppliedColors (HashSet = 24 B)    data[588]
+632   optional<CachedImageData> (88 B)      data[612]
+720   m_settings                           data[700]
+728   object end -> bmalloc class 768
```

`sizeof(State) = 448` follows from `m_dirtyRect` (16) + `+592`, and was
reproduced by compiling the real `State` fields and the real
`DeferrableOneShotTimer`/`HashSet`/`optional` tail:

```
State: lineWidth 48, miterLimit 64, shadowOffset 72, shadowBlur 80,
       shadowColor 88 (Color is 8), globalAlpha 96, transform 112,
       lineDash 168, lineDashOffset 184, unparsedFont 216, font 224
Tail : m_dirtyRect 576, saveCount 592, recordingContext 600,
       suppliedColors 608, cachedImageData 632, settings 720
```

Corrections to agent 1's doc:

* `Vector::last()` is bounds-checked (§1), not a raw `m_buffer[size-1]`.
* The 8-bit `hashAndFlags` is 4, so `m_weakPtrFactory.m_impl` at +16 is
  **non-null** for an 8-bit payload. `createLinearGradient()` on an 8-bit
  reclaimer will treat pointer `0x4` as a `WeakPtrImpl` and crash. Agent 1
  correctly notes this for their 16-bit payload only.
* The object is class **768**, not 704. `len=342` (20+684=704) cannot
  reclaim the context; `len=374` can. This is critical for V700.
* V700's pattern writes `units[j] = 0x0101` for `(j-54)%4==0`. At object
  +592 that is unit `(592-20)/2 = 286`, `(286-54)%4 = 0`, so the initial
  `m_unrealizedSaveCount` is `0x00000101 = 257`, not 0. Harmless for the
  save/restore pair (the counter stays non-zero, so no `state()`), but it
  breaks any assumption that the counter starts at zero and it changes
  what a save-count oracle would read. A payload that wants a zero counter
  must explicitly zero data bytes 572..575.

---

## 4. Crash-free reclaim oracle: `save()` + `charCodeAt`

`save()` is the one state-free *write* (`CanvasRenderingContext2DBase.h:143`):

```cpp
void save() { ++m_unrealizedSaveCount; }
```

It is non-virtual, does not touch `m_stateStack`, `m_canvas`, or the vptr.
For a string reclaimer it increments the u32 at object +592, i.e. string
data bytes 572..575 (little-endian). JS can read those bytes back with
`charCodeAt`.

Probe sequence (one UAF, no AB spray):

1. Build an 8-bit string of 748 bytes, default all zero, with
   `bytes[92..99] = B`, `bytes[100..103] = 1`, `bytes[104..107] = 1`,
   `bytes[700] = 1` (desync), and bytes 560..580 zero.
2. Trigger the UAF, then allocate N copies (all identical) with
   `String.fromCharCode.apply(null, units)`; keep them in an array.
3. Call `innerCtx.save()` once.
4. Scan `payloads[i].charCodeAt(572)` and `charCodeAt(568)`.
   * `572 -> 1` ⇒ this string reclaimed the object and the header is 20.
   * `568 -> 1` ⇒ header is 24 (then all the offsets shift by −4).
   * neither ⇒ no reclaimer; **abort before any `lineWidth` read**.
5. Confirm with `innerCtx.getContextAttributes().desynchronized === true`.
6. Only now read `innerCtx.lineWidth`. `state()` = `B`,
   `lineWidth` = `*(double*)(B + 48)`.

Properties:

* steps 3–5 never dereference `m_buffer`, `m_canvas`, or a vptr;
* a failed reclaim is observed in JS instead of crashing;
* the write into a live JS string also proves the engine address == the
  string data, and calibrates the StringImpl header on the target build.

Caveat: use the string only with `charCodeAt`/`length`. Do not use it as a
property key/Map key/atom (hash computation), and do not let a GC move it
(strings do not move, but hashing changes `hashAndFlags` at +16, which only
matters for paths that read the weak factory).

---

## 5. The read itself

With `m_buffer = B`, `m_size = 1`, `m_capacity >= 1`,
`m_unrealizedSaveCount = 0`, the following getters are non-virtual,
non-allocating, and read fixed State offsets from `B` (target `T = B+48`):

| getter | State offset | reads |
|---|---:|---:|
| `lineWidth` | 48 | `T` (8 B) |
| `miterLimit` | 64 | `T+16` |
| `shadowOffsetX` | 72 (float) | `T+24` |
| `shadowOffsetY` | 76 (float) | `T+28` |
| `shadowBlur` | 80 (float) | `T+32` |
| `globalAlpha` | 96 | `T+48` |
| `lineDashOffset` | 184 | `T+136` |
| `imageSmoothingEnabled` | 192 | `T+144` |

Avoid `shadowColor`, `fillStyle`, `strokeStyle`, `font`, `getLineDash`,
`getTransform` on an arbitrary `B`: they dereference `String`/`RefPtr`/
`Vector` fields (or allocate). `getTransform` would give a 48-byte window
(`T+64 .. T+112`) but constructs a `DOMMatrix` and calls
`AffineTransform::toTransformationMatrix()`; it is only worth using after a
live-context round-trip proves the six doubles survive.

**Bit exactness.** `JSCJSValueInlines.h:574` encodes a double as
`reinterpretDoubleToInt64(d) + (1ll << 49)` and decodes by integer
subtraction. No FP instruction touches the denormal, so the 0x00007FFF...
pointer bits survive `lineWidth -> JSValue -> Float64Array -> BigUint64Array`.
Never do `lw + 0`, `lw * 1`, `String(lw)`, etc.; those are where DAZ/FTZ
kills denormals.

`getContextAttributes()` itself allocates a dictionary object. The GC path
is safe: `JSCanvasRenderingContext2D::visitAdditionalChildren` calls
`wrapped().canvas()`, which is `downcast<HTMLCanvasElement>(canvasBase())`;
on PS5 `ASSERT_WITH_SECURITY_IMPLICATION` is compiled out, so `downcast` is
a static_cast and the only use of the garbage `m_canvas` is as an opaque-root
pointer value (`addWebCoreOpaqueRoot` takes its address, no dereference).
Do not call `innerCtx.canvas` (that one does wrap the pointer).

---

## 6. Addresses

* **Stack/ps_strings:** agent 2's on-device `kern.usrstack` values
  (`0x7EF5A8000`, `0x7EF1CC000`) show a randomised stack top. `ps_strings`
  and the auxv are therefore not at a fixed address; the elegant
  "read PS_STRINGS → ps_argvstr → auxv → AT_PHDR" path only works if a
  future build has a fixed `sv_usrstack`.
* **Shared page:** the only fixed mapping. Candidates (agent 2's ladder):
  `0x7FFFFFFFF000` (last 4 KB inside the 16 KB page), `0x7FFFFFFFC000`
  (16 KB base for a 128 TB layout), `0x7EFFFC000` (16 KB base for a 32 GiB
  layout), and the empirical fixed pages `0xF0000000` / `0xFB000000`.
  Its contents are sigcode + timekeep; no user pointers. Use it to prove the
  primitive, not to defeat ASLR.
* **Real ASLR defeat:** use a leaked heap pointer from V674/V695 as `B`.
  The string reclaim's forged `m_buffer` is exactly the missing consumer for
  that leak. If the leak gives a pointer into a mapped, readable page,
  `lineWidth` at that pointer cannot crash; the returned bytes are the
  arbitrary read.

---

## 7. Why not write a fake State into the shared page?

`setLineWidth` writes `state().lineWidth` **before** `applyLineWidth()`:

```cpp
if (!std::isfinite(width) || width <= 0) return;
if (state().lineWidth == width) return;
realizeSaves();
modifiableState().lineWidth = width;   // 8-byte write at m_buffer + 48
applyLineWidth();                      // drawingContext()
```

`applyLineWidth()` → `drawingContext()` →
`CanvasBase::drawingContext()` → `renderingContext()` which is **pure
virtual** (`CanvasBase.h:99`). With `m_canvas` pointing at the shared page,
the virtual call reads a "vtable" from the shared page (sigcode bytes) and
jumps. The store succeeds, then the process dies; the COW/private page is
lost on reload. A fixed writable scratch is not enough — a valid `m_canvas`
is required first, which is the same address problem.

The state-free setters that do **not** call `drawingContext()`
(`setTextAlign`, `setTextBaseline`, `setDirection`,
`setImageSmoothingEnabled`, `setImageSmoothingQuality`) only write small
enums/bools at fixed State offsets. They can build a few bytes of a fake
State but cannot write a pointer (`lineDash.m_buffer`) or a 32-bit
capacity/size. No bootstrap.

---

## 8. Recommended next probe (V703)

One page load, no AB spray, no APNG required for the calibration run:

1. `String.fromCharCode` 748-byte payload as in §4 with target
   `T = 0x7FFFFFFFF000` (shared-page candidate; a crash here is a miss,
   next reload tries the next candidate), so `bytes[92..99] = T - 48`.
2. Trigger the UAF, spray 800–1600 copies.
3. `save()`; scan `charCodeAt(572)` / `charCodeAt(568)`; beacon the hit
   index and which offset changed.
4. If hit: `getContextAttributes().desynchronized` must be true.
5. `lineWidth`; store the double in a `Float64Array`/`BigUint64Array`
   immediately; beacon the bits.
6. If step 3/4 fails, beacon `no-reclaim` and stop — do not touch
   `lineWidth`.

Once a hit is confirmed, replace `T` with a leaked V674/V695 pointer and
repeat; that is the arbitrary-read primitive the chain needs.
