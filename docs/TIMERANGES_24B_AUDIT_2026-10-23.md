# TimeRanges / 24 B class audit

Date: 2026-10-23. Source only. Tree: `tmp/source-audit/wk1400-src` (616.1.27).
No HTML. Guide stays STOP.

## Layout (64-bit, packed as declared)

| Type | Members | Est. sizeof | FastMalloc class |
|---|---|---|---|
| `MediaTime` | union `{int64, double}` + `uint32 m_timeScale` + `uint8 m_timeFlags` | **16 B** | value type, embedded |
| `PlatformTimeRanges::Range` | two `MediaTime` | **32 B** | Vector element |
| `Vector<Range>` | `m_buffer`, `m_size`, `m_capacity` | **24 B** | embedded in `PlatformTimeRanges` |
| `PlatformTimeRanges` | one Vector | **24 B** | embedded in `TimeRanges` |
| `RefCounted` header | refcount | **8 B** | |
| **`TimeRanges` JS object** | RefCounted + `PlatformTimeRanges` | **~32 B** | index 32, **not 24** |

Opus “24 B TimeRanges” was the inner Vector header, not the object JS holds. Reclaimer of the Canvas2D **768 B** slot cannot land a 32 B `TimeRanges`.

`MediaTime::toDouble()` (`MediaTime.cpp:149-159`): if `DoubleValue` flag, returns the double arm; else `int64 / scale`. Never a raw pointer. A flag-flip still yields a float, not a JS-visible address.

## Guide JS constructors

- `HTMLMediaElement::buffered()` / `seekable()`: `TimeRanges::create()` empty if no player (`HTMLMediaElement.cpp:5792-5838`). Guide can call `document.createElement('video').buffered`.
- `played()` returns `m_playedTimeRanges->copy()` — **copy**, `RefPtr` stored on the element.
- No `new TimeRanges()` from script without media APIs. IndexedDB `DOMStringList` is not Guide.

## Lifetime / UAF

- All `TimeRanges*` in WebCore are `RefPtr` / `Ref`. `played()` copies. No raw pointer UAF in this tree.
- `StyleSheetList::detach()` snapshots into `m_detachedStyleSheets` then nulls document (`StyleSheetList.cpp:64-76`). `item()` after detach uses the snapshot.
- `LiveCSSRuleList` forwards `ref`/`deref` to the owning `Rule&`. List cannot outlive the rule via the IDL wrapper.
- `NamedNodeMap` holds `Element&` and refs the element.

No 24 B or 32 B UAF chain with a Guide JS entry in 616.1.27.

## Verdict

The 24 B path is closed as a *class*: the leak sink (`MediaTime` union) is not a separately allocated JS object, and `TimeRanges` is ~32 B RefCounted with copy-on-read. No in-tree UAF to tag-flip it. Stage 4 is still native-pointer disclosure or a Vector-header write, neither of which this family provides.
