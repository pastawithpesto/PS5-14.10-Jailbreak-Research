# Canvas2D layout + CSS/SVG filter readback

Date: 2026-10-23. Source only. `tmp/source-audit/wk1400-src`. Guide STOP.

## CanvasRenderingContext2D size

`WTF_MAKE_ISO_ALLOCATED` on both `CanvasRenderingContext2D` and `CanvasRenderingContext2DBase`. IsoHeap is **off** on PlayStation, so FastMalloc. Device occupancy audit already treated the live object as **768 B = libpas index 48**. Header layout is consistent with a large object: `Vector<State,1> m_stateStack` (inline State is huge: strings, FontProxy, AffineTransform, `Vector<double> lineDash`, …) plus `m_settings`, `m_cachedImageData`, `m_suppliedColors`. Not 24 B. Not TimeRanges-class.

`getLineDash()` returns `state().lineDash` (`Vector<double>` copy-out to JS as a sequence of doubles). Header still not IDL-writable.

## getImageData / createImageData

`createImageData` / empty-buffer `getImageData` call `ImageData::createUninitialized` then `initializeEmptyImageData` → `imageData.data().zeroFill()` (`CanvasRenderingContext2DBase.cpp:2295-2298, 2440`). No leftover heap in the Uint8ClampedArray.

Buffered `getImageData` uses `ImageBuffer::getPixelBuffer`. That is backing-store contents, not a native pointer.

## CSS / SVG filter paint

`FilterImage` is `RefCounted`, not ScriptWrappable. No IDL. Pixel path `copyPixelBuffer` `zeroFill()`s the destination (`FilterImage.cpp:173`). JS can only see filter output by painting a filtered element to a canvas then `getImageData`, which hits the zero/buffer paths above.

## Verdict

Filter/readback family is not a pointer leak. Canvas2D remains the 768 B typed-double object. No new Guide probe.
