# Cross-type reclaim audit of the 768 B Canvas2D FastMalloc slot

Date: 2026-10-23
Method: source only. No Guide reload, no HTML, no deployment.
Tree: `tmp/source-audit/wk1400-src/Source` (WebKit 616.1.27, 15,547 files
`Source/{WebCore,WTF,JavaScriptCore}/*.{idl,h,cpp}`) plus targeted
`Source/bmalloc/**` fetches. All CRC-verified from Sony's `WebKit-1400.zip`.

Supersedes the granularity assumption in `SIZECLASS_AUDIT_2026-10-23.md`.

---

## 1. The allocator, settled

Three facts decide this audit, all read from source.

**One shared heap.** `WTF/wtf/IsoMalloc.h:30-36` — under
`#if USE(SYSTEM_MALLOC) || !USE(ISO_MALLOC)`, `WTF_MAKE_ISO_ALLOCATED(name)`
expands to `WTF_MAKE_FAST_ALLOCATED`. `WTF/wtf/FastMalloc.h:312-352` shows
`WTF_MAKE_FAST_ALLOCATED_IMPL` routing `operator new` to
`::WTF::fastMalloc(size)` and `operator delete` to `::WTF::fastFree(p)`.
Per-type heap identifiers exist only under `ENABLE(MALLOC_HEAP_BREAKDOWN)`,
which is `0` at `WTF/wtf/PlatformEnable.h:567-568`; the `#else` branch at
`FastMalloc.h:409-417` collapses
`WTF_MAKE_FAST_ALLOCATED_WITH_HEAP_IDENTIFIER(classname)` to plain
`WTF_MAKE_FAST_ALLOCATED_IMPL`. With `USE_ISO_MALLOC=OFF` there is exactly one
FastMalloc heap and no type segregation.

**libpas is the live allocator.** `bmalloc/bmalloc/BPlatform.h:96` defines
`BPLATFORM_PLAYSTATION 1`; `:339-356` gives `BENABLE_LIBPAS 1` then
`BUSE_LIBPAS 1` for `BPLATFORM(PLAYSTATION)`.
`WTF/wtf/FastMalloc.cpp:529-533` — `fastMalloc` calls `bmalloc::api::malloc`.
The legacy `bmalloc/bmalloc/Sizes.h` 64-byte log classes (`logWasteFactor = 8`,
`logAlignmentMin = 64`) are **not** the live path.

**Granularity is 16 bytes, not 64.**
`bmalloc/libpas/src/libpas/bmalloc_heap_config.h:38-52` —
`BMALLOC_MINALIGN_SHIFT ((size_t)4)`, used as
`.small_segregated_min_align_shift`.
`bmalloc/libpas/src/libpas/pas_segregated_heap.h:156-168` —

```
pas_segregated_heap_index_for_size(size_t size, pas_heap_config config)
{
    min_align_shift = pas_heap_config_segregated_heap_min_align_shift(config);
    min_align = (size_t)1 << min_align_shift;
    return (size + min_align - 1) >> min_align_shift;
}
```

The size-directory index is `ceil(size / 16)`. The 768 B slot is index 48.

### The acceptance window

**An occupant must have an allocation size of 753 to 768 bytes inclusive.**
16 bytes wide. This is the single most important number in the audit and it
invalidates the whole "pick a promising WebCore type" approach: for an object
of a few hundred bytes the chance of landing in a named 16-byte window is
about 2%, and no fixed-size class can be computed statically to better than
+/-8 bytes anyway. Fixed-size candidates are a lottery, not a plan.

It also explains the only device result we have. `XMLHttpRequest` was computed
at ~775 B in `SIZECLASS_AUDIT_2026-10-23.md`; 775 rounds to index 49 (784 B),
one directory away. V674 tested it on hardware and the alias still formed
(`A-ALIAS idx=9` control, `B-ALIAS idx=4` after 1500 XHRs,
`B-VERDICT XHR-NOT-SAME-CLASS`). Estimate and device agree.

---

## 2. Fixed-size candidates: exhausted

Enumeration method, over `wk1400-src/Source`:

```
grep -rl "WTF_MAKE_ISO_ALLOCATED\|WTF_MAKE_FAST_ALLOCATED" WebCore --include=*.h
  -> keep only those with a matching basename .idl   (JS-visible)
  -> rank by data-member count
  -> filter out webgl|webgpu|webaudio|offscreen|serviceworker|webcodecs|
     mediastream|speech|webauthn|webxr|PAL/ThirdParty|testing
```

Sizes anchored on the pinned `SameSizeAs*` structs, not guesswork:
`EventTarget` 24 (`dom/EventTarget.cpp:61-65`), `Node` 72
(`dom/Node.cpp:109-125`), `ContainerNode` 88 (`dom/ContainerNode.cpp:74-79`),
`Element`/`StyledElement` 104 (`dom/Element.cpp:157-162`,
`dom/StyledElement.cpp:59`), `Vector<T>` 16 (`WTF/wtf/Vector.h:395-397`),
`RefCounted` 4 (`WTF/wtf/RefCounted.h:39-92`), `ScriptWrappable` 8
(`bindings/js/ScriptWrappable.h:55`), `Event` 64 (`dom/Event.h:47,170-197`),
`MediaTime` 16 (`WTF/wtf/MediaTime.h:140-146`), `URL` ~40
(`WTF/wtf/URL.h:229-246`), `HTTPHeaderMap` 32
(`platform/network/HTTPHeaderMap.h:208-209`).

| Candidate | Source | Allocation route | Size | Index | JS read/write surface | Verdict |
|---|---|---|---|---|---|---|
| `TimeRanges` | `html/TimeRanges.h:33,64` | `TimeRanges::create` via `HTMLMediaElement::buffered/seekable/played` (`html/HTMLMediaElement.cpp:5792-5839`, works with `!m_player`) | **24** | 2 | `length` reads `Vector::m_size` (`platform/graphics/PlatformTimeRanges.h:63`); `start/end` read the `int64_t` arm of the `MediaTime` union | REJECT: 24 vs 753-768, 32x short |
| `DOMStringList` | `dom/DOMStringList.h:43,60,64` | `location.ancestorOrigins`, `IDBDatabase.objectStoreNames` | **24** | 2 | `length` = Vector header; `item(i)` derefs a `StringImpl*` from a Vector slot | REJECT: 32x short |
| `NamedNodeMap` | `dom/NamedNodeMap.h:36` | `Element::attributes` | **24** | 2 | `length` | REJECT: 32x short |
| `StaticCSSRuleList` | `css/CSSRuleList.h:33,68` | `styleSheet.cssRules` | **32** | 2 | `length` = `Vector<RefPtr<CSSRule>>::m_size`; `item(i)` derefs a `RefPtr` slot | REJECT: 24x short |
| `StyleSheetList` | `css/StyleSheetList.h:59,63` | `document.styleSheets` | **~40** | 3 | `length` | REJECT: 19x short |
| `DOMRectList` | `dom/DOMRectList.h:38-48` | `getClientRects()` | **~32** | 2 | `length`, `item(i)` | REJECT |
| `Event` | `dom/Event.h:47,170-197` | `new Event()` | **64** | 4 | `timeStamp` double | REJECT: 12x short |
| `ProgressEvent` | `dom/ProgressEvent.h:33,62-64` | XHR/fetch progress, `new ProgressEvent()` | **88** (Event 64 + bool/pad 8 + 2x u64) | 6 | `loaded`/`total` return `unsigned long long` members raw | REJECT: 8.7x short |
| `Blob` | `fileapi/Blob.h:66,102,152` | `new Blob([...])` | **~96** | 6 | `size` returns `optional<unsigned long long> m_size`; `Blob.cpp:237-247` clamps only on the compute path | REJECT: 8x short |
| `Element`/`HTMLElement` | `dom/Element.cpp:157-162` | `createElement` | **104** | 7 | attributes, `classList` | REJECT |
| `DOMMatrix` | `css/DOMMatrixReadOnly.h:69-91` | `new DOMMatrix()`, `ctx.getTransform()` | **~152** (TransformationMatrix 16 doubles + bases) | 10 | 22 `double` getters, full 64-bit | REJECT: 5x short |
| `IDBVersionChangeEvent` | `Modules/indexeddb/IDBVersionChangeEvent.h:70-71` | IDB upgrade event | **~112** | 7 | `oldVersion` u64, `newVersion` `optional<u64>` | REJECT |
| `XMLHttpRequest` | `xml/XMLHttpRequest.h:56,205-259` | `new XMLHttpRequest()` | **~775** | **49** | `status`, `responseText`, `timeout` | REJECT: **device-confirmed negative, V674** |
| `FetchResponse` | `Modules/fetch/FetchResponse.h:188-189` | `new Response()` | ~700-800, cannot be pinned to +/-8 statically (embeds `ResourceResponse` ~262) | 44-50 | `status`, `url`, body | REJECT: unpinnable inside a 16-byte window; lottery ticket, not a plan |
| `VTTCue` | `html/track/VTTCue.h` (33 members) | `new VTTCue(0,1,"x")` | ~300-400 | 19-25 | `line`, `position`, `size`, `text` | REJECT |
| `KeyframeEffect` | `animation/KeyframeEffect.h` (25 members) | `new KeyframeEffect(...)` | ~250-350 | 16-22 | `getKeyframes()` | REJECT |
| `HTMLMediaElement` | `html/HTMLMediaElement.h` (167 members) | `createElement('video')` | >= 1500 | >= 94 | many | REJECT: overshoots by ~2x |
| `Document` | `dom/Document.h` (262 members) | `createDocument` | several kB | >> 48 | many | REJECT |
| `LocalDOMWindow` | `page/LocalDOMWindow.h` (38 members) | not freely allocatable | n/a | n/a | n/a | REJECT: no allocation control |

Element subclasses all start from the 104 B `Element` anchor and the largest
realistic ones (`HTMLFormElement` 16 members, `HTMLSelectElement`) reach only
~250-350 B. Nothing in the JS-visible fixed-size set lands in index 48.

**Conclusion: the fixed-size cross-type reclaim search is exhausted.** Not
because a candidate is missing, but because the target is a 16-byte window and
fixed-size C++ objects cannot be aimed.

---

## 3. What does fit: JS-sized FastMalloc allocations

The correct vehicle is an allocation whose **byte size JS chooses**, so the
index match is exact by construction rather than by luck. Two exist in-tree,
both on the same FastMalloc heap, both Guide-reachable, neither in Gigacage.

This is the distinction that killed DASHFORGE and was misattributed to size.
`DEAD_ENDS.md` records that ArrayBuffer storage does not reclaim the slot. The
reason is not the size class: JSC ArrayBuffer storage is Gigacage-primitive, a
different region entirely. Both vehicles below are `fastMalloc`.

### 3.1 `Vector<double> lineDash` — exact 768 B

- **Source:** `WTF/wtf/Forward.h:67` `using VectorBufferMalloc = FastMalloc`;
  `WTF/wtf/Vector.h:400-403` `VectorBuffer<T, 0, Malloc = VectorBufferMalloc>`.
- **Allocation route:** `CanvasRenderingContext2DBase::setLineDash` does
  `modifiableState().lineDash = dash` (Vector copy-assign).
  `Vector.h:993-997` — for an empty target, `other.size() > capacity()` so
  `clear(); reserveCapacity(other.size());`.
  `Vector.h:304-328` `VectorBufferBase::allocateBuffer` does
  `sizeToAllocate = newCapacity * sizeof(T); Malloc::malloc(sizeToAllocate)`
  with **no `mallocGoodSize` rounding**, then `m_capacity = sizeToAllocate / sizeof(T)`.
- **Size:** `fastMalloc(n * 8)` exactly. **n = 96 -> 768 B -> index 48.**
  Window index 48 is n = 95 (760, rounds to 768) through n = 96.
- **Content control:** every one of the 96 doubles is attacker-chosen. Use an
  even element count: `setLineDash` duplicates odd-length arrays via
  `appendVector` (`SINK_AUDIT_2026-10-23.md`), which would change the byte size.
  Non-finite and negative values are rejected, positive finite doubles are not.
- **Verdict: ACCEPT.** Exact-size, same-heap, fully controlled contents.

### 3.2 `StringImpl` tail — exact 768 B, and the better spray

- **Source:** `WTF/wtf/text/StringImpl.h:183`
  `WTF_MAKE_FAST_ALLOCATED_WITH_HEAP_IDENTIFIER(StringImpl)`, which collapses to
  plain FastMalloc per `FastMalloc.h:409-417` given
  `ENABLE_MALLOC_HEAP_BREAKDOWN 0`. `StringImpl.h:1030` allocates through
  `StringImplMalloc::tryMalloc(allocationSize<CharacterType>(length))`.
- **Allocation route:** `StringImpl.h:1298-1301`
  `allocationSize<T>(n) = tailOffset<T>() + n * sizeof(T)`.
  `StringImplShape` (`StringImpl.h:161-171`) is
  `unsigned m_refCount; unsigned m_length; union { const LChar* m_data8; ... };
  mutable unsigned m_hashAndFlags;` = 20 bytes of fields, 8-byte alignment,
  so `sizeof(StringImpl) = 24` and `tailOffset<LChar>() = 24`.
- **Size:** 8-bit string of length n allocates **24 + n**.
  **n = 744 -> 768 B -> index 48.** Window: n = 729 to 744.
  16-bit path is `24 + 2n`, so n = 372.
- **Content control:** bytes 0-23 are the StringImpl header written by WTF
  (refcount, length, data pointer, hash/flags). Bytes 24-767 are the character
  data, fully attacker-chosen. The canvas fields of interest sit far past
  offset 24 (`m_stateStack` inline `State`, with lineWidth at State+48 and the
  `lineDash` Vector header at State+168 per the V630 header notes), so the
  controlled region covers them.
- **Why this is the better vehicle:** a JS string is sprayable in the tens of
  thousands with one expression, needs no canvas donor per allocation, and
  resolves to a real `StringImpl` (not a `JSRopeString`) when built with
  `repeat`/`padEnd`. The lineDash route needs one live donor context per
  live buffer, and each donor is itself a 768 B index-48 allocation that
  competes with the target.
- **Verdict: ACCEPT, preferred.**

---

## 4. The precise blocker

Both vehicles supply **one** of the two blockers in
`HANDOFF_PLAN_2026-10-23.md`. They do not supply both.

- **Solved: raw bytes into the freed slot.** A 768 B index-48 allocation whose
  contents JS chose can occupy the slot. That is the "raw Vector-header write"
  the campaign has been stuck on since V650/V655, now on the correct heap.
- **Still open: the address disclosure.** Forging `m_stateStack.m_buffer` to a
  useful target requires knowing an address at the moment the string or dash
  array is constructed. Strings are immutable after creation, and a dash buffer
  can only be rewritten by reallocating it, so neither vehicle can be patched
  after a leak arrives in the same slot. Writing a chosen pointer still needs a
  prior leak.

Honest statement of where this lands: the occupancy half is solved on paper and
is cheap to confirm on device; the disclosure half is untouched and every
in-tree disclosure path audited so far is closed (`DEAD_ENDS.md` "Info Leak
Paths", plus V673's on-device closure of the `LanguagePlayStation.cpp`
`getenv_np(buf[16])` sink at `host-beacons.log` seq 2306-2310:
`len=5, s=en-US, over15=false, nonlang=false`).

---

## 5. Best independent disclosure / raw-write family to attack next

Ranked by what the audit actually supports.

1. **A second UAF or overflow landing in index 48, giving a write with a
   *leaked* operand.** The occupancy vehicle above means any second bug that
   discloses even 6 bytes of a heap pointer completes the chain. Search target:
   FastMalloc objects of 753-768 B with a lifetime bug, not a JS-visible getter.
   This is the highest-value remaining search and it is not yet done.
2. **`CSSPrimitiveValue::m_value` union mis-tag**
   (`css/CSSPrimitiveValue.h:229-237`: `double number; StringImpl* string;
   const CSSCalcValue* calc;` discriminated by `m_primitiveUnitType`; `:126`
   already does `*reinterpret_cast<const Color*>(&m_value.colorAsInteger)`).
   Previously filed as needing a raw write, which is exactly what section 3
   now supplies. Read back through `cssText`, not `getFloatValue`, which is
   `unrestricted float` and truncates. `CSSPrimitiveValue` is small, so this
   needs its own index, not index 48, but the vehicle generalises: pick
   `n = (target_size - 24)` for the string route.
3. **`MediaTime` union arm** (`WTF/wtf/MediaTime.h:140-146`,
   `MediaTime.cpp:149-160`): with `m_timeFlags` clear and `m_timeScale == 1`,
   `toDouble()` returns `static_cast<double>(m_timeValue) / m_timeScale`, i.e.
   a native `int64_t` verbatim, surfaced by `TimeRanges.idl:33-34`
   `start(i)`/`end(i)`. `TimeRanges` is only 24 B so it cannot take index 48,
   but it is a legitimate int64-to-Number read if a 24 B (index 2) corruption
   is ever found.
4. **Do not reopen:** Canvas2D typed doubles over a legitimately initialized
   State, `UniqueArray`/`png_byte` (memset via `Vector.h:78-86` forwarding into
   the `<true,...>` branch, `VectorTraits.h:48-51`), JIT/WASM/WebGL/
   OffscreenCanvas/WebAudio (compiled out), `SerializedScriptValue` object
   pool, `ImageBackingStore::clear`, JSC-side `JSBigInt`/`JSArrayBufferView`
   (MarkedSpace and Gigacage, wrong heap).

---

## 6. Minimal probe spec for Grok

Source-derived, not deployed. One page, one Circle. Reuses the V573/V630
trigger and the V674/V675 beacon conventions.

**Goal:** confirm that an index-48 allocation with attacker-chosen contents
occupies the freed `CanvasRenderingContext2D` slot.

**Oracle:** negative alias. Run the V573 trigger, interpose the candidate
allocations, then run the identical same-type Canvas2D spray and alias scan.
If the canvas spray can no longer reclaim the slot, the interposed allocation
owns it.

| Arm | Interposed allocation | Expected if the vehicle works |
|---|---|---|
| A | none (control) | `A-ALIAS idx>=0`, baseline idx=9 |
| B | 20000 x `'A'.repeat(744)`, kept referenced | `B-ALIAS idx=-1` |
| C | 20000 x `'A'.repeat(700)` (724 B, index 46) | `C-ALIAS idx>=0` (negative control, wrong index) |

Arm C is what makes arm B meaningful: it proves the effect is index-specific
and not just heap pressure from 20k strings.

Constraints from source:
- Build the strings with `repeat`/`padEnd` so JSC materializes a resolved
  8-bit `StringImpl`, not a `JSRopeString`. Keep every string in a live array.
- Latin-1 characters only, so the 8-bit path and `24 + n` sizing hold.
- Do not create canvases during the interpose phase; a fresh 2D context is
  itself an index-48 allocation and would contaminate the arm.
- Touch the stale wrapper with the single `lineWidth` store only, the one
  operation V573 proved safe. Do not read through it: if a string owns the
  slot, `state()` dereferences `m_stateStack.m_buffer` built from character
  data and will fault.
- Beacon before and after every step, including an `END`, so a crash localises.

**Readout:** `B-ALIAS idx=-1` with `C-ALIAS idx>=0` means the string route
works and the raw-write-into-slot blocker is cleared. `B-PREWRITE` then
silence means the slot holds something foreign and `state()` faulted, which is
also a positive. Both `idx>=0` means strings do not take the slot and the
Gigacage reasoning in section 3 is wrong somewhere, which would need rechecking
against `StringImpl.h:1030` on the live binary.

**Pending, not circled:** V675 is already deployed on Spark
(`/home/trojan_horse/ps5-jb/v675.html`, with `v674.html` and `index.html`
redirecting to it) and tests the lineDash variant of the same question with
96-element (768 B) and 88-element (704 B) arms. It was never circled because
this audit was ordered source-only. Either circle V675 as-is or replace it with
the string-route page above, which is the stronger of the two.
