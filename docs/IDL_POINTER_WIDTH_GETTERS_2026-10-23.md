# IDL getters with pointer-width / union-arm C++ backing

Date: 2026-10-23
Method: source only. No HTML, no Guide reload.
Tree: `tmp/source-audit/wk1400-src/Source` (WebKit 616.1.27), cross-checked
against `webkit1400/Source`. All files CRC-verified from Sony's `WebKit-1400.zip`.

Scope: Guide-reachable **getters** (not setters) returning a JS Number or
JSString whose C++ backing is a pointer (`void*`, `T*`), a heap-header
`size_t`, or a union/variant arm — not an IEEE double, CSS pixel length, or
Canvas2D state float. Excluded per order: WebGL, WebAudio, OffscreenCanvas,
WASM, JIT, `ImageBackingStore::clear`, `UniqueArray` memset.

## Framing (important)

A correctly-tagged IDL getter never returns a raw pointer to JS on its own:
each reads the arm its discriminator selects and converts it to the typed JS
value. The value of this list is the **backing**: these are the getters where,
if a prior corruption flips the discriminator or the object is reclaimed, the
pointer/heap word is already wired to a Number/String return. They are leak
*sinks* awaiting a tag-flip, not standalone leaks. None of them is a clean
read primitive.

---

## Qualifying set

### 1. DeprecatedCSSOMPrimitiveValue — union arm incl. `StringImpl*`

- **Getters:** `getStringValue()` -> DOMString; `cssText()` -> String;
  `getFloatValue()` -> `unrestricted float`.
  `WebCore/css/DeprecatedCSSOMPrimitiveValue.idl:53-59`,
  `.../DeprecatedCSSOMPrimitiveValue.h:77` (`cssText()` forwards to
  `m_value->cssText()`).
- **Backing:** the wrapped `CSSPrimitiveValue::m_value`,
  `WebCore/css/CSSPrimitiveValue.h:229-237`:
  ```
  union {
      CSSValueID valueID;         // 4-byte enum
      CSSPropertyID propertyID;   // 4-byte enum
      double number;              // IEEE
      StringImpl* string;         // POINTER-WIDTH
      const CSSCalcValue* calc;   // POINTER-WIDTH
      CSSUnresolvedColor* unresolvedColor;  // POINTER-WIDTH
      // colorAsInteger reinterpreted at :126
  } m_value;
  ```
  discriminated by `m_primitiveUnitType`. `:126` already does
  `*reinterpret_cast<const Color*>(&m_value.colorAsInteger)`.
- **Why pointer-width:** the `string`/`calc`/`unresolvedColor` arms are native
  pointers. Read back through `cssText` / `getStringValue` (String), not
  `getFloatValue` (truncates to `unrestricted float`). A tag that says "string"
  over a `number`-arm write, or vice versa, surfaces the raw 8 bytes.

### 2. TimeRanges.start / TimeRanges.end — `int64_t` union arm

- **Getters:** `start(index)` / `end(index)` -> `unrestricted double`.
  `WebCore/html/TimeRanges.idl:33-34`.
- **Backing:** each `PlatformTimeRanges::Range` is two `MediaTime`
  (`WebCore/platform/graphics/PlatformTimeRanges.h:81-83`). `MediaTime` is a
  union, `WTF/wtf/MediaTime.h:140-146`:
  ```
  union { int64_t m_timeValue; double m_timeValueAsDouble; };
  uint32_t m_timeScale; uint8_t m_timeFlags;
  ```
  `MediaTime.cpp:149-160` `toDouble()`: with `m_timeFlags` clear and
  `hasDoubleValue()` false, returns `static_cast<double>(m_timeValue) / m_timeScale`.
- **Why pointer-width:** `m_timeValue` is a full native `int64_t`. With
  `m_timeScale == 1` and the double-flag clear, `start(i)`/`end(i)` return that
  64-bit word (as `double(int64)/1`), exact for 48-bit userland VAs. The arm is
  not a float; it is a 64-bit integer that aliases a double slot.
- **Allocation note:** `TimeRanges` is 24 B (index 2), reachable without a
  media engine via `HTMLMediaElement.buffered/seekable/played`
  (`html/HTMLMediaElement.cpp:5792-5839`). It cannot take the 768 B canvas slot;
  it qualifies only as an int64-to-Number sink for a 24 B corruption.

### 3. CSSRule.parentRule / parentStyleSheet — pointer union (DISQUALIFIED on return type)

- **Backing:** `WebCore/css/CSSRule.h:68-71`
  `union { CSSRule* m_parentRule; CSSStyleSheet* m_parentStyleSheet; }`,
  tagged by `m_parentIsRule`. Two pointer arms.
- **Why excluded:** both getters (`parentRule`, `parentStyleSheet`) return
  wrapper objects, never a Number or JSString. Flipping the tag confuses two
  wrapper types, it does not surface the pointer *as a number*. Listed so it is
  not re-investigated as a Number/String leak.

---

## Rejected after grep (backing is not pointer-width)

- **All `length` / `size` / `numberOfItems` getters** (`CSSRuleList.idl:32`,
  `MediaList.idl:33`, `CSSStyleDeclaration.idl:33`, `NamedNodeMap.idl:27`,
  `DOMStringList.idl:29`, `NodeList.idl:31`, `DOMRectList.idl:30`,
  `SVG*List.idl`, `StyleSheetList.idl:26`, `SourceBufferList.idl:38`,
  `CharacterData.idl:24`, `MediaKeyStatusMap.idl:46`, `XPathResult.idl:43`):
  each returns a container `m_size` / element count (`Vector::size()`), a small
  bounded `unsigned`, not a pointer or leftover heap. The `m_size` word sits
  next to `m_buffer` in the Vector header, but the getter returns the count
  value, not the adjacent pointer. Not a leak absent a header overwrite.
- **`WebCore::Length`** (`platform/Length.h:141-146`): union
  `{ int m_intValue; float m_floatValue; unsigned m_calculationValueHandle; }`.
  The calc arm is a **32-bit handle**, not a pointer; the float arm is lossy.
  Disqualified.
- **`KeyboardEvent.keyCode/charCode/which/location`**
  (`dom/KeyboardEvent.idl:33-51`), **`Touch.identifier`** (`dom/Touch.idl:37`):
  plain `unsigned` from the event, not heap-backed.
- **`SQLResultSet.insertId`** (`Modules/webdatabase/SQLResultSet.idl:34`,
  `long long`): a database rowid, not a pointer; and `SQLValue`
  (`platform/sql/SQLValue.h:36`) is `variant<nullptr_t, String, double>` whose
  `std::get` aborts on wrong-index with exceptions off. No WEB_SQL enable flag
  found in `PlatformEnable.h`.
- **`IDBDatabase.version` / `IDBVersionChangeEvent.oldVersion/newVersion`**
  (`uint64_t`): a database version counter, not a heap address.
- **CSS Typed OM variants** (`CSSNumericValue` `CSSNumberish`,
  `CSSUnparsedValue` `CSSUnparsedSegment`, `CSSKeywordish`, `CSSColorPercent`,
  etc.): the `variant` members found are **method-argument** `using` aliases,
  not discriminated getter storage, and no enable flag was found for CSS Typed
  OM in `PlatformEnable.h` / `OptionsPlayStation.cmake`.
- **`MessageEvent.data`** (`dom/MessageEvent.idl`,
  `DataType = variant<JSValueTag, Ref<SerializedScriptValue>, String, ...>`):
  deserialization goes through the SerializedScriptValue object pool, excluded
  per order.
- **`DOMMatrix`/`DOMMatrixReadOnly` m11..m44** (`css/DOMMatrixReadOnly.h:69-91`):
  22 `double` getters over a `TransformationMatrix` of 16 real doubles. 64-bit
  wide, but the backing is genuine IEEE doubles, not a pointer or union arm.
  The `variant<String, Vector<double>>` at `:48` is a constructor parameter.
  Does not qualify under the pointer-width rule.
- **JSC `JSBigInt` radix string, `JSArrayBufferView.length/byteLength/byteOffset`,
  `ArrayBuffer.byteLength`**: genuine pointer-width/native-word reads
  (`runtime/JSBigInt.h:624-627`, `runtime/JSArrayBufferView.h:368-370`,
  `runtime/ArrayBuffer.h:114`), but these cells live in MarkedSpace /
  Gigacage-primitive, a different allocator from the FastMalloc canvas slot, so
  they are not reclaim-reachable from the Canvas2D UAF. Listed for completeness;
  out of scope for a WebCore FastMalloc leak.

---

## Result

Non-empty but thin. Exactly **two** getters return a JS Number/String over a
pointer-width or 64-bit-integer union arm:

1. `DeprecatedCSSOMPrimitiveValue::getStringValue()` / `cssText()` ->
   `CSSPrimitiveValue::m_value.string` (`StringImpl*`) and `.calc` /
   `.unresolvedColor` arms.
2. `TimeRanges::start()` / `end()` -> `MediaTime::m_timeValue` (`int64_t` arm).

Both are **tag-flip sinks, not standalone leaks**: each needs a prior
corruption that puts a pointer or heap word into the arm the discriminator does
not expect. Neither reads a raw pointer when correctly tagged. No clean
Guide-reachable IDL getter in 616.1.27 WebCore returns a native pointer to JS
without a preceding type confusion.

Cross-reference: the write primitive that could flip arm #1's tag is the
FastMalloc-slot occupancy question tracked in
`CROSSTYPE_RECLAIM_AUDIT_2026-10-23.md`, which the device has now closed (store
through the stale Canvas2D faults). So arm #1 is a sink without a matching
in-tree write, and arm #2 needs a 24 B-class corruption not yet found.

---

## Greps run

```
grep -rnE "bitwise_cast<(double|uint64_t|int64_t|unsigned long long)>|reinterpret_cast<(double|uint64_t)" WebCore --include=*.cpp --include=*.h
grep -rnE "readonly attribute (unsigned long|unsigned long long|long long|unrestricted double) " WebCore --include=*.idl
  | grep -iE "length|size|count|index|offset|id|identifier|pointer|handle|address|key"
grep -rl "std::variant\|union {" WebCore --include=*.h
  -> for each with a matching basename .idl, dump the variant/union member
cat WebCore/css/DeprecatedCSSOMPrimitiveValue.idl   (getStringValue / cssText / getFloatValue)
grep -n "union {" WebCore/css/CSSPrimitiveValue.h    (:229-237)
grep -n "union {" WTF/wtf/MediaTime.h                (:140-146)
grep -n "toDouble" WTF/wtf/MediaTime.cpp             (:149-160)
grep -n "union {" WebCore/css/CSSRule.h              (:68-71)
grep -n "union {" WebCore/platform/Length.h          (:141-146)
```

All filtered with
`grep -viE "PAL/ThirdParty|webgl|webgpu|webaudio|offscreen|webcodec|mediastream|speech|webauthn|webxr|payment|gpu"`.
