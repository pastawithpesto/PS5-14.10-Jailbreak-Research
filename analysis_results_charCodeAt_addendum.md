
---

# Addendum — `String.prototype.charCodeAt` on a `TextDecoder`-backed `StringImpl`: live read vs. JIT reuse

**Scope:** PS5 14.10 WebKit reference tree at
`/home/violence/Work/WebKit-1400/WebKit-1400/WebKit-1400`
(`Configurations/Version.xcconfig` = `616.1.27.211.1`; PlayStation port).
Unless stated otherwise, paths below are relative to that root.

**Cross-check:** the `.webkit-src` tree in this workspace (WebKitGTK 2.42.5
`NEWS`, mixed revision) has the same `StringImpl`, `StringPrototype`,
`DFGSpeculativeJIT`, `DFGClobberize`, `DFGCSEPhase`, `DFGLICMPhase`,
`FTLLowerDFGToB3`, `TextDecoder`, and text-codec code for every cited path.
Line numbers differ by a few lines in a few files; the `.webkit-src`
equivalent is given in the evidence index where useful.

**Method:** source-only audit. No PS5 runtime, no JIT dump, no ASan run. The
allocator-reuse premise (a freed 704-byte block is reused by the 684-byte
`StringImpl`) is taken as given for the read-semantics questions; the
allocator-class caveat is recorded in Section 10.

**Prior work:** this file previously audited the Canvas `lineDash` vector
lifecycle and already established that `StringImpl` allocates its header and
character data in one block (`StringImpl.cpp:184-191`). This addendum does
**not** re-open that lifecycle. It answers the follow-up question: if a
`StringImpl` occupies a block that an external writer still references, does
`charCodeAt` read the written bytes, and can the JIT serve a stale value?

---

## A.0 Answers at a glance

| # | Question | Answer |
|---|----------|--------|
| 1 | 704-byte block freed by FastMalloc, then reused? | The scenario's 684-byte `StringImpl` request is `20 + 664`; in the PS5 reference build the CMake configuration sets `ENABLE_LIBPAS=OFF` / `-DBENABLE_LIBPAS=0`, so bmalloc's `Sizes.h` class arithmetic applies and a 684-byte request falls in the 704-byte class. A freed 704-class block can therefore be reused; if the shipping binary enables libpas, re-derive (Section 10). |
| 2 | Does `TextDecoder.decode()` create a 684-byte `StringImpl`? | **Only for the inline 8-bit codec paths.** `windows-1252`/`latin1`/`ascii` (`TextCodecLatin1`) call `String::createUninitialized(664)`, which asks FastMalloc for `20 + 664 = 684` bytes. The default `utf-8` decoder does **not**: it allocates a separate 664-byte `StringBuffer` and a separate `StringImpl` object (`sizeof(StringImpl)` = 24 bytes here). |
| 3 | Does block offset 168-175 correspond to string data 148-155? | **Yes for the inline 8-bit layout**: data starts at `B + 20`, so `B + 168 = data[148]`. It is **not** true for the UTF-8 `BufferOwned` layout (data starts at a separate buffer, so `B + 168 = data[168]`) or for a 16-bit string (`data[148]` is at `B + 20 + 2*148 = B + 316`). |
| 4 | Does `charCodeAt(148)` immediately reflect the external write? | **A call that actually executes the load: yes.** The C++ host function and a fresh DFG/FTL `StringCharCodeAt` node read `m_data8[148]` directly; there is no character cache or defensive copy for a flat string. **A call that was CSE'd or LICM-hoisted: no** — it may return a value computed before the write. |
| 5 | Does the 8-bit path do `m_data8[index]` directly or copy? | **Direct `m_data8[index]`.** C++: `StringView::characterAt` → `characters8()[index]`. DFG: `loadPtr(StringImpl::dataOffset)` then `load8(BaseIndex(data, index, 1, 0))`. FTL: the same `load8ZeroExt32`. Only rope flattening copies. |
| 6 | Are two `charCodeAt` calls with a write in between guaranteed to see the new value? | **No guarantee.** Interpreter/LLInt/baseline re-enter the native host function and re-read. DFG/FTL model `StringCharCodeAt` as a pure value (`def(PureValue(node))`), so local/global CSE can replace the second call with the first result; LICM can hoist it out of a loop; a `clobberTop` from a native write does not invalidate it. |
| 7 | Is there a JIT optimization that caches `charCodeAt` results? | **Yes: DFG CSE (local and global), LICM, and DCE.** The intrinsic is inlined only by the DFG/FTL (`DFGByteCodeParser.cpp:2836-2850`); the baseline call path does not inline it. There is no `StringImpl` byte cache; the compiler-level reuse is the caching. |

The one-sentence conclusion: **for a flat 8-bit string, `charCodeAt` is a live
memory read, not a snapshot; JSC does not copy the characters at decode time.
But the DFG/FTL is entitled to assume `StringImpl` bytes are immutable, and it
uses that assumption to CSE/hoist the load. An out-of-band write into a live
string therefore produces a read that is fresh in the interpreter and
possibly stale in optimized code — there is no guarantee either way.**

---

## A.1 The allocation arithmetic: 704, 684, and the 20-byte header

`StringImpl` derives from `StringImplShape`, whose fields are
(`StringImpl.h:161-171`):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | `m_refCount` |
| 4 | 4 | `m_length` |
| 8 | 8 | `m_data8` / `m_data16` (union pointer) |
| 16 | 4 | `m_hashAndFlags` |
| 20 | ... | inline character data (`tailOffset<LChar>()`) |

The inline-data offset is not `sizeof(StringImpl)` (which is 24 on a 64-bit
build because of alignment); it is computed by
`StringImpl::tailOffset<T>()`:

```cpp
// Source/WTF/wtf/text/StringImpl.h:1310-1313
template<typename T> inline size_t StringImpl::tailOffset()
{
    return roundUpToMultipleOf<alignof(T)>(offsetof(StringImpl, m_hashAndFlags) + sizeof(StringImpl::m_hashAndFlags));
}
```

For `LChar` this is `roundUpToMultipleOf<1>(16 + 4) = 20`. For `UChar` it is
`roundUpToMultipleOf<2>(20) = 20` as well. The allocation size is
(`StringImpl.h:1298-1301`):

```cpp
// Source/WTF/wtf/text/StringImpl.h:1298-1301
template<typename T> inline size_t StringImpl::allocationSize(Checked<size_t> tailElementCount)
{
    return tailOffset<T>() + tailElementCount * sizeof(T);
}
```

So an 8-bit string of 664 characters requests `20 + 664 = 684` bytes. The
allocation path is `StringImpl::createUninitialized`
(`StringImpl.cpp:180-192`):

```cpp
// Source/WTF/wtf/text/StringImpl.cpp:184-191
// Allocate a single buffer large enough to contain the StringImpl
// struct as well as the data which it contains. This removes one
// heap allocation from this call.
if (length > maxInternalLength<CharacterType>())
    CRASH();
StringImpl* string = static_cast<StringImpl*>(StringImplMalloc::malloc(allocationSize<CharacterType>(length)));
data = string->tailPointer<CharacterType>();
return constructInternal<CharacterType>(*string, length);
```

`StringImplMalloc` is `FastMalloc` when `ENABLE(MALLOC_HEAP_BREAKDOWN)` is 0
(`DebugHeap.h:91-92`; the default is 0 at `PlatformEnable.h:567-568`), and
`FastMalloc::malloc` calls `bmalloc::api::malloc`
(`FastMalloc.cpp:529-533`). In the PS5 reference build (`BUSE_LIBPAS=0`), the
size-class arithmetic in `Sizes.h:91-119` maps 684 to 704:

* `size > maskSizeClassMax (512)`, so `sizeClass = 64 + logSizeClass(684)`.
* `logSizeClass(684)` = `(log2(683) - log2(512)) * 8 + (683 - 512) / 64`
  = `0 + 2` = 2.
* `objectSize(64 + 2)` = `logObjectSize(2)` = `(512 << 0) + (2 + 1) * 64` =
  `704`.

Thus a 684-byte request and a 704-byte request are in the same 704-byte
class in that configuration. `StringImpl::destroy` frees the whole block with
`StringImplMalloc::free(stringImpl)` (`StringImpl.cpp:153-157`), so the
inline data is freed with the header.

Two caveats matter for the scenario:

1. The 704-byte request in the prior `lineDash` audit was `20 + 684 = 704`
   bytes (684 characters). The current scenario is `20 + 664 = 684` bytes
   (664 characters). Both fall in the 704 class under `Sizes.h`, but they are
   different string lengths.
2. The `BPlatform.h` default for PlayStation is `BENABLE_LIBPAS 1`
   (`BPlatform.h:340-345`), but the PS5 reference build's CMake overrides it:
   `OptionsPlayStation.cmake:283-287` defines `ENABLE_LIBPAS` as OFF, and
   `:741-742` adds `-DBENABLE_LIBPAS=0`; `BPlatform.h:352-358` then sets
   `BUSE_LIBPAS=0`. The reference build therefore uses bmalloc's `Sizes.h`
   classes, not libpas. If the shipping binary passes `-DENABLE_LIBPAS=ON`,
   the class must be re-derived; Section 10 records that caveat.

**The "20-byte header" is therefore correct for the allocation layout**, but
do not confuse it with `sizeof(StringImpl)` (24) or with
`StringImpl::dataOffset()` (8). `dataOffset()` is the offset of the `m_data8`
*pointer*, not of the character data (`StringImpl.h:297`); the JIT loads the
pointer at offset 8 and then indexes the pointed-to data.

---

## A.2 Which `TextDecoder.decode()` path actually produces the 684-byte `StringImpl`?

`TextDecoder::decode` is a thin wrapper around the selected codec
(`TextDecoder.cpp:53-79`):

```cpp
// Source/WebCore/dom/TextDecoder.cpp:70-71
bool sawError = false;
String result = m_codec->decode(reinterpret_cast<const char*>(data), length, !options.stream, m_options.fatal, sawError);
```

The codec determines the allocation shape. The default constructor label is
`"utf-8"` (`TextDecoder.idl:38`), and the method returns `USVString`
(`TextDecoder.idl:43`). The relevant paths are:

| Label / codec | Allocation path | 684-byte inline `StringImpl`? |
|---|---|---|
| `utf-8` (default), `TextCodecUTF8` | `StringBuffer<LChar> buffer(length)` (`TextCodecUTF8.cpp:299`) then `String::adopt(WTFMove(buffer))` (`:378`; 16-bit branch `:458`) | **No.** The `StringBuffer` is a separate 664-byte allocation; `String::adopt` creates a separate `StringImpl` object (24 bytes) whose `m_data8` points at that buffer (`BufferOwned`). |
| `windows-1252`, `latin1`, `ascii`, `iso-8859-1`, `cp1252`, etc., `TextCodecLatin1` | `String::createUninitialized(length, characters)` (`TextCodecLatin1.cpp:105`) | **Yes.** `String::createUninitialized` is `StringImpl::createUninitialized` (`WTFString.h:212-213`), which allocates `20 + length` in one block and returns the inline data pointer. |
| `iso-8859-3/6/7/8`, `windows-874/1253/1255/1257`, `ibm866`, `koi8-u`, `TextCodecSingleByte` | `StringBuilder result; result.reserveCapacity(length)` (`TextCodecSingleByte.cpp:275-276`) → `StringBuilder::allocateBuffer` → `StringImpl::tryCreateUninitialized` (`StringBuilderInternals.h:37`) → `StringBuilder::toString` (`StringBuilder.h:251-258`) | **Yes for 8-bit input.** `StringBuilder::reifyString` shares the buffer when `m_length == m_buffer->length()` (`StringBuilder.cpp:66-72`). Non-ASCII code points above `0xFF` upconvert the builder to 16-bit. |
| ICU-based encodings, `TextCodecICU` | `StringBuilder result` (`TextCodecICU.cpp:226`), `appendCharacters(UChar*, ...)` (`:237`), `result.toString()` (`:248`) | Usually **no** for the 8-bit case: appending `UChar` through `appendCharacters` upconverts the builder to 16-bit. |

So the premise is internally consistent with the **`windows-1252`/`latin1`/
`ascii`** decoder (or an 8-bit single-byte codec), not with the default
`new TextDecoder()` UTF-8 path. This is important because the block-offset
mapping in the question (`168 -> 148`) assumes the inline layout:

* **Inline `BufferInternal` (Latin1 / 8-bit builder):** `StringImpl` object at
  `B`, data at `B + 20`; `charCodeAt(148)` reads `B + 168`.
* **`BufferOwned` (UTF-8):** `StringImpl` header at some `H`, data buffer at
  `D`; `charCodeAt(148)` reads `D + 148`, and the 684-byte `StringImpl` does
  not exist (the `StringImpl` object is 24 bytes and the data block is 664 bytes).

For the rest of this addendum, "the string" means the inline 8-bit
`BufferInternal` case, because that is the only case in which the question's
arithmetic is exact. The UTF-8 case is called out where it changes the answer.

The binding does not copy the characters. The `USVString` return converter is
`JSConverter<IDLUSVString>::convert(const String&)`:

```cpp
// Source/WebCore/bindings/js/JSDOMConvertStrings.h:130-133
static JSC::JSValue convert(JSC::JSGlobalObject& lexicalGlobalObject, const String& value)
{
    return JSC::jsStringWithCache(JSC::getVM(&lexicalGlobalObject), value);
}
```

`jsStringWithCache` (`JSString.h:1049-1067`) either returns the last
`JSString` for the same `StringImpl` pointer or calls
`jsStringWithCacheSlowCase` (`JSString.cpp:328-334`), which does
`JSString::create(vm, stringImpl)` and stores the `JSString` in
`vm.lastCachedString`. `JSString::create` takes a `Ref<StringImpl>&&`
(`JSString.h:183-191`), so the `JSString` holds a reference to the same
`StringImpl`; there is no character copy. The 664-character length is also
above the single-character fast path, so no small-string table is involved.

---

## A.3 The object model: where the bytes live, and where they do not

`JSString` stores a `String` (a `RefPtr<StringImpl>`) in its `m_fiber` field;
`JSString::offsetOfValue()` is the offset of `m_fiber`
(`JSString.h:234`). The `String` constructor from `Ref<StringImpl>&&` stores
the ref; it does not copy characters (`WTFString.h:70-73`, `:315`).

`StringImpl` exposes the characters as a raw pointer:

```cpp
// Source/WTF/wtf/text/StringImpl.h:309-310
bool is8Bit() const { return m_hashAndFlags & s_hashFlag8BitBuffer; }
ALWAYS_INLINE const LChar* characters8() const { ASSERT(is8Bit()); return m_data8; }
```

`StringView` is a non-owning view: it stores `m_characters`, `m_length`, and
an `m_is8Bit` flag. Constructing a `StringView` from a `String` copies those
three fields, not the characters (`StringView.h:423-435`). Indexing it is a
direct read (`StringView.h:550-561`):

```cpp
// Source/WTF/wtf/text/StringView.h:550-561
inline UChar StringView::characterAt(unsigned index) const
{
    ASSERT(index < length());
    if (is8Bit())
        return characters8()[index];
    return characters16()[index];
}

inline UChar StringView::operator[](unsigned index) const
{
    return characterAt(index);
}
```

`StringImpl::at` is the same direct read
(`StringImpl.h:1268-1272`):

```cpp
// Source/WTF/wtf/text/StringImpl.h:1268-1272
inline UChar StringImpl::at(unsigned i) const
{
    ASSERT_WITH_SECURITY_IMPLICATION(i < m_length);
    return is8Bit() ? m_data8[i] : m_data16[i];
}
```

There is **no character cache** in `StringImpl`, `String`, or `JSString`.
`StringImpl::hash()` caches a hash in `m_hashAndFlags`, but `charCodeAt`
does not call `hash()`, and the hash is not the characters. `StringView`
caches the pointer and length in the view object on the stack, not the bytes.
`jsStringWithCache` caches the `JSString` object (by `StringImpl` identity),
not the character data.

The only copies in this area are:

* **Rope flattening.** A non-substring `JSRopeString` is flattened on first
  access: `resolveRopeWithFunction` allocates a new `StringImpl` and copies
  the rope's characters into it (`JSString.cpp:227-266`), then
  `convertToNonRope` installs the flat `String` in the same `JSString`
  (`JSStringInlines.h:103-113`). A substring rope shares the base string and
  does not copy (`JSString.cpp:232-237`). A `TextDecoder` result is a flat
  `String`, not a rope, so this path does not apply to it.
* **Explicit conversions.** `StringImpl::create` copies
  (`StringImpl.cpp:256-264`), and `String::convertTo16Bit` allocates a new
  16-bit representation (`WTFString.cpp:469-478`). `charCodeAt` invokes
  neither.
* **`BufferOwned` adoption with a different allocator type.** In the
  `ENABLE(MALLOC_HEAP_BREAKDOWN) == 1` configuration, the `StringImpl`
  constructor copies from a `StringBufferMalloc` buffer into a
  `StringImplMalloc` buffer (`StringImpl.h:907-922`). In the release
  configuration used here, both aliases are `FastMalloc`, so the
  `std::is_same_v` branch adopts the buffer without copying. This is a
  configuration detail, not a `charCodeAt` copy.

`StringImpl::isExternal()` means `bufferOwnership() == BufferExternal`
(`StringImpl.h:324`, `:498`). That is the WTF `ExternalStringImpl` case, where
`m_data8` points at caller-owned memory; `at()` still reads `m_data8[i]`
directly. It is **not** what `TextDecoder` creates: `ExternalStringImpl` has
no callers in this tree (`ExternalStringImpl::create` is defined in
`ExternalStringImpl.cpp:31-43` but not used), and `TextDecoder` returns a
normal `BufferInternal` (Latin1) or `BufferOwned` (UTF-8) string. In this
addendum, "external" therefore means "an out-of-band writer still holds a
pointer to the block", not the WTF `BufferExternal` ownership tag.

---

## A.4 The exact `charCodeAt` call paths

### A.4.1 C++ host function (LLInt, baseline, and DFG exits)

`String.prototype.charCodeAt` is registered as a native intrinsic function:

```cpp
// Source/JavaScriptCore/runtime/StringPrototype.cpp:135
JSC_NATIVE_INTRINSIC_FUNCTION_WITHOUT_TRANSITION("charCodeAt"_s, stringProtoFuncCharCodeAt, static_cast<unsigned>(PropertyAttribute::DontEnum), 1, ImplementationVisibility::Public, CharCodeAtIntrinsic);
```

The host function is (`StringPrototype.cpp:992-1017`):

```cpp
// Source/JavaScriptCore/runtime/StringPrototype.cpp:992-1017
JSC_DEFINE_HOST_FUNCTION(stringProtoFuncCharCodeAt, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
    ...
    auto* thisString = thisValue.toString(globalObject);
    ...
    auto viewWithString = thisString->viewWithUnderlyingString(globalObject);
    ...
    StringView view = viewWithString.view;
    JSValue a0 = callFrame->argument(0);
    if (a0.isUInt32()) {
        uint32_t i = a0.asUInt32();
        if (i < view.length())
            return JSValue::encode(jsNumber(view[i]));
        return JSValue::encode(jsNaN());
    }
    ...
}
```

The trace is:

1. `thisValue.toString(globalObject)` returns the primitive `JSString` (or
   the wrapped string of a `String` object); no character copy.
2. `JSString::viewWithUnderlyingString` for a non-rope returns
   `{ valueInternal(), valueInternal() }` (`JSString.h:1151-1156`). The
   `underlyingString` member is a `String` ref that keeps the `StringImpl`
   alive during the call.
3. `StringView view = viewWithString.view` stores the data pointer and
   length (`StringView.h:423-435`).
4. `view[i]` → `StringView::operator[]` → `characterAt` →
   `characters8()[i]` → `StringImpl::characters8()` → `m_data8[i]`
   (`StringView.h:550-561`; `StringImpl.h:309-310`).

For an 8-bit flat string, the final read is exactly `m_data8[i]`. There is no
`StringImpl` copy, no `StringView` copy, and no `String` copy in this path.

For a rope, step 2 can flatten: a substring rope returns a view into the base
(no copy), while a non-substring rope calls `resolveRope` and copies into a
new flat `StringImpl` (`JSString.cpp:227-266`). That copy is cached in the
`JSString` by `convertToNonRope`, so subsequent `charCodeAt` calls on the same
rope read the flat copy, not the original rope storage. This is the one
"first call copies, later calls cache" behavior in the C++ path.

### A.4.2 DFG: the intrinsic is inlined as `StringCharCodeAt`

The DFG decides to inline the intrinsic in `handleCall` by consulting the
callee's `Intrinsic` (`DFGByteCodeParser.cpp:1989-1995`;
`CallVariant.h:113-118`). The `CharCodeAtIntrinsic` case
(`DFGByteCodeParser.cpp:2836-2850`) inserts:

```cpp
// Source/JavaScriptCore/dfg/DFGByteCodeParser.cpp:2843-2849
insertChecks();
VirtualRegister thisOperand = virtualRegisterForArgumentIncludingThis(0, registerOffset);
VirtualRegister indexOperand = virtualRegisterForArgumentIncludingThis(1, registerOffset);
Node* charCode = addToGraph(StringCharCodeAt, OpInfo(ArrayMode(Array::String, Array::Read).asWord()), get(thisOperand), get(indexOperand));
setResult(charCode);
return CallOptimizationResult::Inlined;
```

Fixup then rewrites the string operand:

```cpp
// Source/JavaScriptCore/dfg/DFGFixupPhase.cpp:1019-1028
case StringCharAt:
case StringCharCodeAt:
case StringCodePointAt: {
    // Currently we have no good way of refining these.
    ASSERT(node->arrayMode() == ArrayMode(Array::String, Array::Read));
    blessArrayOperation(node->child1(), node->child2(), node->child1()); // Rewrite child1 with ResolveRope.
    fixEdge<KnownStringUse>(node->child1());
    fixEdge<Int32Use>(node->child2());
    break;
}
```

`blessArrayOperation` inserts a `Check` with `StringUse` and, for
`Array::String`, a `ResolveRope` node
(`DFGFixupPhase.cpp:3931-3932`). `ResolveRope` is itself pure
(`DFGClobberize.h:1413-1415`), so it can be CSE'd; at runtime it branches on
the `JSString` value being a rope and calls `operationResolveRopeString` on
the slow path (`DFGSpeculativeJIT.cpp:8817-8836`). For a flat string, the fast
path is just a load of `m_value`.

The 8-bit code generation is (`DFGSpeculativeJIT.cpp:3144-3177`):

```cpp
// Source/JavaScriptCore/dfg/DFGSpeculativeJIT.cpp:3157-3166
loadPtr(Address(stringReg, JSString::offsetOfValue()), scratchReg);

// unsigned comparison so we can filter out negative indices and indices that are too large
speculationCheck(Uncountable, JSValueRegs(), nullptr, branch32(AboveOrEqual, indexReg, Address(scratchReg, StringImpl::lengthMemoryOffset())));

// Load the character into scratchReg
Jump is16Bit = branchTest32(Zero, Address(scratchReg, StringImpl::flagsOffset()), TrustedImm32(StringImpl::flagIs8Bit()));

loadPtr(Address(scratchReg, StringImpl::dataOffset()), scratchReg);
load8(BaseIndex(scratchReg, indexReg, TimesOne, 0), scratchReg);
```

So the DFG emits a load of the `StringImpl*` from the `JSString`, a bounds
check against `m_length`, an 8-bit flag test, a load of the data pointer from
`m_data8` (offset 8), and a direct `load8` at `data + index`. No copy. The
16-bit branch is the analogous `load16` at `TimesTwo` (`:3171-3172`).

`StringCharCodeAt` is declared with only `NodeResultInt32` and no
`NodeMustGenerate` (`DFGNodeType.h:348`); `DFGDoesGC` returns false for it
(`DFGDoesGC.cpp:202`, with the `return false` at `:266`); `DFGSafeToExecute`
returns true when the string array mode is already checked
(`DFGSafeToExecute.h:393`), and `Array::String` is checked as `SpecString`
(`DFGArrayMode.cpp:511-512`). These properties are what allow the optimizer
to treat it as a pure, removable, hoistable value.

### A.4.3 FTL: the same load, lower-level

The FTL lowers the same DFG node in `compileStringCharCodeAt`
(`FTLLowerDFGToB3.cpp:9922-9967`):

```cpp
// Source/JavaScriptCore/ftl/FTLLowerDFGToB3.cpp:9931-9951
LValue stringImpl = m_out.loadPtr(base, m_heaps.JSString_value);

speculate(
    Uncountable, noValue(), nullptr,
    m_out.aboveOrEqual(
        index, m_out.load32NonNegative(stringImpl, m_heaps.StringImpl_length)));

m_out.branch(
    m_out.testIsZero32(
        m_out.load32(stringImpl, m_heaps.StringImpl_hashAndFlags),
        m_out.constInt32(StringImpl::flagIs8Bit())),
    unsure(is16Bit), unsure(is8Bit));

LBasicBlock lastNext = m_out.appendTo(is8Bit, is16Bit);

ValueFromBlock char8Bit = m_out.anchor(
    m_out.load8ZeroExt32(m_out.baseIndex(
        m_heaps.characters8, m_out.loadPtr(stringImpl, m_heaps.StringImpl_data), m_out.zeroExtPtr(index),
        provenValue(m_node->child2()))));
```

Again: load `JSString::m_value`, bounds check `m_length`, test the 8-bit flag,
load the data pointer, and perform a zero-extending 8-bit load at
`data + index`. The FTL keeps the base alive with `ensureStillAliveHere(base)`
(`:9964-9965`), which keeps the `StringImpl` storage alive; it does not copy
it.

### A.4.4 Baseline and LLInt

The baseline JIT compiles an `op_call` as a `CallLinkInfo` fast path
(`JITCall.cpp:243-315`; `compileOpCall` at `:243`, the fast/slow paths at
`:302-339`). It does not consult `CallVariant::intrinsicFor` and does not
inline `StringCharCodeAt`; the call reaches the native
`stringProtoFuncCharCodeAt` thunk, which executes the C++ path of A.4.1. The
LLInt likewise executes the native function. Therefore, in the interpreter,
LLInt, and baseline tiers, each `charCodeAt` call constructs a fresh
`StringView` and performs a fresh `m_data8[i]` read.

---

## A.5 Q4/Q5: what `charCodeAt(148)` reads in the scenario

Assume the inline 8-bit layout: `StringImpl` at `B`, `m_length = 664`,
`m_data8 = B + 20`, data bytes `B + 20 .. B + 683`.

* The external write at block offsets 168-175 is:
  `data[168 - 20 .. 175 - 20] = data[148 .. 155]`.
* `charCodeAt(148)`: `148 < 664`, so the bounds check passes; the 8-bit flag
  is set; the read is `m_data8[148] = *(B + 20 + 148) = *(B + 168)`.
* The first byte of the external 8-byte write is therefore exactly the value
  returned by `charCodeAt(148)`; the remaining seven bytes are returned by
  `charCodeAt(149 .. 155)`.

This is a direct read, not a copy. `StringImpl::at` (`StringImpl.h:1268-1272`),
`StringView::characterAt` (`StringView.h:550-555`), the DFG `load8`
(`DFGSpeculativeJIT.cpp:3166`), and the FTL `load8ZeroExt32`
(`FTLLowerDFGToB3.cpp:9948-9951`) all read the same byte at `B + 168`.

The answer is conditional on the layout:

* **Inline 8-bit (`BufferInternal`, Latin1/8-bit builder):** `B + 168` is
  `data[148]`; the read reflects the write.
* **`BufferOwned` 8-bit (UTF-8):** the `StringImpl` header is at some `H` and
  the data buffer is at `D`; `charCodeAt(148)` reads `D + 148`. A write at
  `B + 168` is `D + 168` only if `B == D` (i.e., if the write is into the data
  buffer, not into the header). The question's `168 -> 148` mapping no longer
  holds; the correct mapping is `168 -> 168`.
* **16-bit string:** `m_data16[148]` is at `B + 20 + 2*148 = B + 316`; a write
  at `B + 168` hits `m_data16[74..77]` (four 16-bit units), not `charCodeAt(148)`. The
  scenario's "8-bit" premise is essential.

For the inline 8-bit case, a **fresh** call sees the write immediately. There
is no JSC-level character cache or defensive copy that would hide it. The only
way the call does not see it is if the compiler has already evaluated the
`StringCharCodeAt` node (CSE) or hoisted it above the write (LICM), which is
the subject of A.6/A.7.

Also note that the write is 8 bytes, not one byte. `charCodeAt(148)` returns
only the first byte; the other seven bytes are observable through
`charCodeAt(149 .. 155)`, but each is a separate read. If the exploit needs
the full 8-byte value, it must issue eight `charCodeAt` calls (or use a wider
read primitive); the JIT is free to optimize each of them independently.

---

## A.6 Q6: two calls with the external write in between

### A.6.1 Interpreter/LLInt/baseline: re-executed, sees the new value

In the interpreter, LLInt, and baseline, `charCodeAt` is the native host
function of A.4.1. Each call:

1. gets the `JSString`,
2. builds a fresh `StringView` from the current `StringImpl` (`m_data8`,
   `m_length`, `m_hashAndFlags`),
3. reads `m_data8[148]`.

The native function does not retain a result cache between calls. If the
external write happens before the second call and the second call reaches the
host function, the second read is `*(B + 168)` with the new byte. Under the
C++ memory model, an unsynchronized write from another thread is a data race
and undefined behavior; if the writer is in the same thread (e.g., a native
callback that mutates the block), the read is ordinary memory access and sees
the new value.

### A.6.2 DFG/FTL: not guaranteed — the node is pure and can be CSE'd

In the DFG, `StringCharCodeAt` is modeled as a pure value:

```cpp
// Source/JavaScriptCore/dfg/DFGClobberize.h:226-262 (excerpt)
case ArithIMul:
...
case StringCharCodeAt:
case StringCodePointAt:
...
    def(PureValue(node));
    return;
```

`PureValue` is keyed by the node's opcode and child edges (and an optional
info word); it has **no read set** and **no write set**
(`DFGPureValue.h:43-49`, `:112-127`). The local CSE replaces a matching node
with an earlier one in the same block (`DFGCSEPhase.cpp:609-617`). The global
CSE is even more explicit:

```cpp
// Source/JavaScriptCore/dfg/DFGCSEPhase.cpp:765-790
void def(PureValue value)
{
    // With pure values we do not have to worry about the possibility of some control flow path
    // clobbering the value. So, we just search for all of the like values that have been
    // computed. We pick one that is in a block that dominates ours. ...
    auto result = m_pureValues.add(value, Vector<Node*>());
    ...
    if (m_graph.m_ssaDominators->dominates(candidate->owner, m_block)) {
        m_node->replaceWith(m_graph, candidate);
        m_changed = true;
        return;
    }
    ...
}
```

Two `charCodeAt` calls with the same string and index produce the same
`PureValue` key only if their child nodes are the same. In a function such as:

```js
let a = s.charCodeAt(148);
externalWrite();       // native write into the block, not a JS SetLocal
let b = s.charCodeAt(148);
```

the `GetLocal` for `s` is a `HeapLocation(StackLoc, ...)` definition
(`DFGClobberize.h:930-934`) and can be CSE'd if there is no intervening
`SetLocal` of the same slot. `ResolveRope` is pure (`DFGClobberize.h:1413-1415`)
and is CSE'd from the same string child. The second `StringCharCodeAt` then
has the same `ResolveRope` and index children as the first, so the global CSE
can replace it with the first result. The intervening native write is a
`clobberTop` (`read(World); write(Heap)`), but a `PureValue` is not
invalidated by any clobber — that is the point of the comment at
`DFGCSEPhase.cpp:767-769`.

If the index is different (e.g., `148` then `149`), the `PureValue` keys
differ and CSE will not merge them; each emits its own load. If the two calls
are in different functions/inlined frames and the string operand is a
different node, CSE may not merge them either. The optimization is
shape-dependent, which is exactly why the answer is "not guaranteed" rather
than "always stale" or "always fresh".

### A.6.3 DFG/FTL: LICM can hoist the load out of a loop

Even if the two calls are not textually adjacent, LICM can move a
loop-invariant `StringCharCodeAt` to the loop preheader
(`DFGLICMPhase.cpp:389-428`):

* `edgesDominate` checks that the string and index children dominate the
  preheader (`:389`).
* `doesWrites` is false for `StringCharCodeAt` (`:397`).
* `readsOverlap` is false because the node has no reads (`:409`).
* `safeToExecute` is true when the AI knows the child is a `SpecString`
  (`DFGSafeToExecute.h:393`; `DFGArrayMode.cpp:511-512`).

So a loop like:

```js
for (let i = 0; i < n; i++) {
    sink(s.charCodeAt(148));
    externalWrite();   // native call, clobbers World/Heap
}
```

can be transformed to read `s.charCodeAt(148)` once in the preheader and reuse
that value for every iteration, even though the loop body calls a native
function that writes memory. The `World`/`Heap` clobber does not invalidate a
`PureValue`; the compiler assumes the string bytes cannot change. This is the
strongest form of the "stale read" behavior.

### A.6.4 The rope exception

If the string is a `JSRopeString`, the first `charCodeAt` may flatten it:

* A **substring** rope returns a `StringView` into the base string
  (`JSString.h:1128-1136`); no copy, and writes into the base are visible.
* A **non-substring** rope calls `resolveRope`, which allocates a new flat
  `StringImpl` and copies the rope characters (`JSString.cpp:227-266`), then
  installs the flat string in the `JSString` via `convertToNonRope`
  (`JSStringInlines.h:103-113`). Subsequent calls read the flat copy, not the
  original rope storage. If the external write targets the original rope
  operands, the flattened copy does not see it.

`TextDecoder` returns a flat string, so this exception is not triggered by the
scenario's decode itself. It matters if the JS code later concatenates or
slices the string before calling `charCodeAt`.

### A.6.5 Bottom line for Q6

**No, the second call is not guaranteed to see the new value.** In the
interpreter/LLInt/baseline it does (each call re-enters the native function and
re-reads). In DFG/FTL it does only if the compiler emits a fresh
`StringCharCodeAt` load; CSE and LICM are allowed to replace or hoist it, and
the compiler's purity model explicitly ignores intervening memory writes.

---

## A.7 Q7: the JIT optimizations that can cache `charCodeAt`

### A.7.1 DFG common-subexpression elimination

`StringCharCodeAt` is grouped with the pure nodes in `DFGClobberize.h`
(`:226-262`), and `def(PureValue(node))` is at `:261`. The local CSE
(`DFGCSEPhase.cpp:609-617`) and the global CSE (`:765-790`) both replace a
matching node with an earlier one. This is a true value cache: the second
node is deleted and its uses are rewired to the first node's result. There is
no runtime check that the string data is unchanged.

### A.7.2 DFG loop-invariant code motion

`DFGLICMPhase` hoists a node when it does not write, does not read anything
the loop writes, is safe to execute at the preheader, and its children
dominate the preheader (`DFGLICMPhase.cpp:389-428`). `StringCharCodeAt` has
no reads and no writes, so the read/write tests are trivially satisfied; the
only practical constraints are dominance and `safeToExecute`, which the
`Check`/`SpecString` type proof usually satisfies. The hoisted load runs once,
before the loop, and the result is reused for every iteration.

### A.7.3 Dead-code elimination

`StringCharCodeAt` is declared as `macro(StringCharCodeAt, NodeResultInt32)`
(`DFGNodeType.h:348`), with no `NodeMustGenerate`. If the result is unused,
the node can be removed. This is not a value cache, but it means the call has
no observable side effect from the compiler's point of view; the compiler is
free to move or delete it.

### A.7.4 What is *not* caching it

* **Baseline JIT:** `compileOpCall` uses a `CallLinkInfo` and does not consult
  the intrinsic (`JITCall.cpp:243-315`). The native host function runs on
  every call.
* **`StringImpl`/`StringView`:** there is no byte cache. `StringView` caches
  only the pointer and length in the view object; `StringImpl::characters8`
  returns `m_data8` every time (`StringImpl.h:309-310`).
* **`jsStringWithCache`:** it caches the `JSString` object by `StringImpl`
  identity (`JSString.h:1049-1067`; `JSString.cpp:328-334`), not the
  characters. It does not make `charCodeAt` return a stale character.
* **`StringImpl::hash()`:** the hash is cached in `m_hashAndFlags`, but
  `charCodeAt` never calls it.

### A.7.5 Why the JIT is "correct" and the write is the bug

The JIT's purity model is valid under the JavaScript language semantics:
strings are immutable, and no JavaScript operation can change the bytes of an
existing `StringImpl`. Every apparent mutation creates a new `StringImpl`.
The model is only violated by an out-of-band native write into a live
`StringImpl` — a UAF, an arbitrary write, or an unsynchronized cross-thread
write. In that situation the JIT is not "wrong" in the language sense; it is
operating outside its invariants, and the observed value is
implementation-dependent.

For a memory-safety review, the actionable conclusion is therefore not "use
`charCodeAt` to read the modified bytes"; it is "an out-of-band write into a
live `StringImpl` is the vulnerability, and `charCodeAt` must not be relied
on as a deterministic read-after-write primitive."

---

## A.8 Security assessment for the scenario

### A.8.1 If the write is confined to the data bytes (the stated case)

The write at `B + 168 .. B + 175` changes `data[148 .. 155]` and leaves the
header (`m_refCount`, `m_length`, `m_data8`, `m_hashAndFlags`) intact. The
consequences are:

* A fresh `charCodeAt(148)` reads the new `data[148]` (the first written byte).
  This is true in the interpreter/LLInt/baseline and for a fresh DFG/FTL load.
* A CSE'd or LICM-hoisted call returns the old value. The second call is not
  guaranteed to see the new byte.
* `charCodeAt(149 .. 155)` can read the remaining written bytes, subject to
  the same tier/optimization caveats.
* The string remains a valid 8-bit 664-character string; there is no
  out-of-bounds read from this write alone.

### A.8.2 If the write can reach the header (a stronger primitive)

The header fields are much more dangerous than the data bytes:

| Field | Offset | Consequence of corruption |
|---|---:|---|
| `m_length` | 4 | The DFG/FTL bounds check uses `m_length` (`DFGSpeculativeJIT.cpp:3160`; `FTLLowerDFGToB3.cpp:9933-9936`). A larger length turns `charCodeAt` into an out-of-bounds read; a smaller length only causes a false `NaN`. |
| `m_data8` | 8 | The DFG/FTL loads the data pointer from offset 8 (`DFGSpeculativeJIT.cpp:3165`; `FTLLowerDFGToB3.cpp:9950`). Corrupting it turns `charCodeAt` into an arbitrary read at `controlled_pointer + index`. |
| `m_hashAndFlags` | 16 | Bit 2 is `s_hashFlag8BitBuffer`; flipping it changes the read width (8-bit vs. 16-bit) and the index scaling (`DFGSpeculativeJIT.cpp:3163`; `FTLLowerDFGToB3.cpp:9938-9942`). Flipping other bits can change atom/symbol behavior. |
| `m_refCount` | 0 | Refcount corruption can cause a premature free or a leak; the read path itself uses it only for lifetime management. |

The scenario's 8-byte write at offset 168 avoids the header, but an attacker
with a wider or differently placed write could target offsets 0-19. The
`charCodeAt` path would then read through the corrupted length/pointer/width,
which is a much stronger exploitation primitive than the stated data-byte
mutation. This is worth calling out in the compliance review: the safety
property is not "charCodeAt is safe"; it is "the write must not exist".

### A.8.3 Threading

If the external write is performed by a different thread while the main
thread calls `charCodeAt`, the read and write are unsynchronized accesses to
the same `StringImpl` bytes. That is a C++ data race and undefined behavior;
the JIT's assumption of immutability is one way the race manifests. Even the
interpreter path is not a synchronization primitive. The only safe design is
to prevent the write or to use an explicit synchronization/ownership
mechanism, neither of which `StringImpl` provides.

### A.8.4 Practical reliability note

If a test or exploit needs the new value, the reliable options are:

* Force the call through the native host function (e.g., keep the call site
  out of the DFG/FTL, or call a wrapper that the DFG does not inline).
* Use a different index for each read (CSE keys on the index child) — but
  LICM can still hoist each loop-invariant read separately.
* Use a different string object (a fresh `StringImpl`) for each read — but
  that changes the target block.
* Do not rely on a second read at the same index after an out-of-band write.

None of these is a guarantee; they are ways to avoid the specific
`PureValue`/LICM optimizations. The only sound fix is to eliminate the UAF or
out-of-band write that makes the mutation possible.

---

## A.9 Evidence index

Paths are relative to `/home/violence/Work/WebKit-1400/WebKit-1400/WebKit-1400`.
The `.webkit-src` column gives the corresponding line in the workspace
cross-check tree where it differs.

| Fact | WK-1400 citation | `.webkit-src` cross-check |
|---|---|---|
| `StringImpl` field layout (refCount, length, data pointer, flags) | `Source/WTF/wtf/text/StringImpl.h:161-171` | `:157-167` |
| `flagsOffset` / `dataOffset` / `lengthMemoryOffset` | `StringImpl.h:292`, `:297`, `:306` | `:288`, `:293`, `:302` |
| `is8Bit` / `characters8` | `StringImpl.h:309-310` | `:305-306` |
| `isExternal` / `bufferOwnership` | `StringImpl.h:324`, `:498` | `:320`, `:514` |
| `StringImpl::at` direct `m_data8[i]` | `StringImpl.h:1268-1272` | `:1162-1166` |
| `allocationSize` / `tailOffset` / `tailPointer` | `StringImpl.h:1298-1301`, `:1310-1313`, `:1325-1332` | `:1192-1195`, `:1204-1207`, `:1219-1222` |
| `StringImpl::createUninitialized` one-block allocation | `StringImpl.cpp:180-192` (malloc at `:189`, data at `:190`) | `:180-194` |
| `StringImpl::destroy` frees the block | `StringImpl.cpp:153-157` | `:146-151` |
| `StringImpl::adopt(StringBuffer<LChar>&&)` | `StringImpl.cpp:1498-1504` | same |
| `StringImpl(MallocPtr<...>)` ownership/adopt branch | `StringImpl.h:907-922` | `:923-938` |
| `String::createUninitialized` → `StringImpl::createUninitialized` | `Source/WTF/wtf/text/WTFString.h:212-213` | same |
| `StringBuffer` allocation | `Source/WTF/wtf/text/StringBuffer.h:47-50` | same |
| `StringBuilder::allocateBuffer` → `StringImpl::tryCreateUninitialized` | `Source/WTF/wtf/text/StringBuilderInternals.h:34-37` | same |
| `StringBuilder::toString` / `reifyString` | `StringBuilder.h:251-258`; `StringBuilder.cpp:50-72` | same |
| `TextDecoder::decode` codec call and return | `Source/WebCore/dom/TextDecoder.cpp:71`, `:78` | same |
| `TextDecoder` default label `utf-8` / `USVString decode` | `Source/WebCore/dom/TextDecoder.idl:38`, `:43` | same |
| Latin1/windows-1252 codec uses `String::createUninitialized` | `Source/WebCore/PAL/pal/text/TextCodecLatin1.cpp:105` | same |
| UTF-8 codec uses `StringBuffer<LChar>` + `String::adopt` | `TextCodecUTF8.cpp:299`, `:378`, `:458` | same |
| Single-byte codec uses `StringBuilder` + `reserveCapacity` | `TextCodecSingleByte.cpp:275-276`, `:297` | same |
| ICU codec uses `StringBuilder` + `appendCharacters(UChar*)` | `TextCodecICU.cpp:226`, `:237`, `:248` | same |
| `USVString` return converter uses `jsStringWithCache` | `Source/WebCore/bindings/js/JSDOMConvertStrings.h:126-133` | `:100-107` |
| `jsStringWithCache` (identity cache, no character copy) | `Source/JavaScriptCore/runtime/JSString.h:1049-1067` | `:1030-1048` |
| `jsStringWithCacheSlowCase` creates a JSString from the same `StringImpl` | `Source/JavaScriptCore/runtime/JSString.cpp:328-334` | same |
| `jsString` wraps `s.impl()` directly | `JSString.h:903-913` | `:902-912` |
| `JSString::offsetOfValue` is `m_fiber` | `JSString.h:234` | `:247` |
| `JSString::viewWithUnderlyingString` (non-rope returns the same `String`) | `JSString.h:1151-1156` | `:1132-1137` |
| `JSRopeString::viewWithUnderlyingString` (substring shares base) | `JSString.h:1128-1136` | `:1109-1120` |
| `JSRopeString::resolveRopeWithFunction` (non-substring copies) | `JSString.cpp:227-266` | `:225-266` |
| `convertToNonRope` caches the flat string | `Source/JavaScriptCore/runtime/JSStringInlines.h:103-113` | `:110-120` |
| `StringView` construction copies pointer/length only | `Source/WTF/wtf/text/StringView.h:423-435` | same |
| `StringView::characterAt` / `operator[]` direct read | `StringView.h:550-561` | same |
| `charCodeAt` host function and `view[i]` | `Source/JavaScriptCore/runtime/StringPrototype.cpp:992-1017` (`view[i]` at `:1009`) | `:996-1021` |
| `charCodeAt` registered with `CharCodeAtIntrinsic` | `StringPrototype.cpp:135` | same |
| DFG intrinsic dispatch | `Source/JavaScriptCore/dfg/DFGByteCodeParser.cpp:1989-1995`; `CharCodeAtIntrinsic` at `:2836-2850` | `:2022-2028`, `:2889-2903` |
| `CallVariant::intrinsicFor` | `Source/JavaScriptCore/bytecode/CallVariant.h:113-118` | same |
| Fixup rewrites child1 with `ResolveRope` | `Source/JavaScriptCore/dfg/DFGFixupPhase.cpp:1019-1028`, `:3931-3932` | `:1021-1029`, `:3947` |
| `ResolveRope` is a `PureValue` | `Source/JavaScriptCore/dfg/DFGClobberize.h:1413-1415` | `:1414` |
| `StringCharCodeAt` is grouped as pure; `def(PureValue(node))` | `DFGClobberize.h:226-262` (case at `:231`, def at `:261`) | same |
| `StringCharCodeAt` node type has no `NodeMustGenerate` | `Source/JavaScriptCore/dfg/DFGNodeType.h:348` | `:349` |
| `StringCharCodeAt` does not GC | `Source/JavaScriptCore/dfg/DFGDoesGC.cpp:202`, `:266` | `:202`, `:266` |
| `StringCharCodeAt` safe-to-execute check | `Source/JavaScriptCore/dfg/DFGSafeToExecute.h:393` | same |
| `Array::String` AI check is `SpecString` | `Source/JavaScriptCore/dfg/DFGArrayMode.cpp:511-512` | same |
| DFG direct 8-bit load (`loadPtr` data, `load8`) | `Source/JavaScriptCore/dfg/DFGSpeculativeJIT.cpp:3144-3177` (ptr at `:3165`, load at `:3166`) | same |
| FTL direct 8-bit load (`load8ZeroExt32`) | `Source/JavaScriptCore/ftl/FTLLowerDFGToB3.cpp:9922-9967` (load at `:9948-9951`) | `:9939-9984` |
| Baseline call path does not inline the intrinsic | `Source/JavaScriptCore/jit/JITCall.cpp:243-315` | same |
| Local CSE `def(PureValue)` | `Source/JavaScriptCore/dfg/DFGCSEPhase.cpp:609-617` | same |
| Global CSE `def(PureValue)` and its "no clobber" comment | `DFGCSEPhase.cpp:765-790` (comment `:767-773`) | same |
| LICM hoisting criteria (`edgesDominate`, `doesWrites`, `readsOverlap`, `safeToExecute`) | `Source/JavaScriptCore/dfg/DFGLICMPhase.cpp:389-428` | same |
| `PureValue` key is opcode + children (+ info) | `Source/JavaScriptCore/dfg/DFGPureValue.h:43-49`, `:112-127` | `:43-49`, `:99-120` |
| `GetLocal` CSE via stack heap location | `DFGClobberize.h:930-934` | `:931-934` |
| `StringImplMalloc` = `FastMalloc` when heap breakdown is off | `Source/WTF/wtf/DebugHeap.h:91-92`; `PlatformEnable.h:567-568` | same |
| `FastMalloc::malloc` → `bmalloc::api::malloc` | `Source/WTF/wtf/FastMalloc.cpp:529-533` | same |
| bmalloc 684 → 704 size-class arithmetic | `Source/bmalloc/bmalloc/Sizes.h:91-119` | same |
| PS5 reference build: `ENABLE_LIBPAS` OFF → `-DBENABLE_LIBPAS=0`; bmalloc classes apply | `Source/cmake/OptionsPlayStation.cmake:283-287`, `:741-742`; `Source/bmalloc/bmalloc/BPlatform.h:340-358` | same |
| `ExternalStringImpl` creation is defined but unused | `Source/WTF/wtf/text/ExternalStringImpl.cpp:31-43` | same |

---

## A.10 Limitations

* **Source-only.** This addendum does not run the PS5 browser, does not dump
  JIT IR, and does not use ASan. The CSE/LICM behavior is derived from the
  optimizer's source and phase semantics, not from a runtime trace of the
  shipping binary.
* **Build divergence.** The cited tree is the workspace PS5 reference
  (`616.1.27.211.1`). If the shipping 14.10 binary differs in
  `StringPrototype.cpp`, `DFGClobberize.h`, `DFGCSEPhase.cpp`,
  `DFGLICMPhase.cpp`, `DFGSpeculativeJIT.cpp`, or `FTLLowerDFGToB3.cpp`, the
  line numbers and possibly the inlining conditions must be re-checked. The
  `.webkit-src` cross-check agrees on the code shape, which makes a silent
  semantic divergence less likely but does not prove binary identity.
* **Allocator class.** The 684 → 704 class arithmetic is the bmalloc
  `Sizes.h` model, which is the reference build's backend:
  `OptionsPlayStation.cmake:283-287` defines `ENABLE_LIBPAS` OFF and
  `:741-742` adds `-DBENABLE_LIBPAS=0`, so `BUSE_LIBPAS=0`. If the shipping
  binary is built with `-DENABLE_LIBPAS=ON`, the small-object class is chosen
  by libpas and the 684/704 reuse must be re-derived. The read-semantics
  analysis applies in either case *if* the string occupies the block.
* **"Guaranteed" is deliberately avoided.** CSE and LICM are
  optimization-dependent. The report says "can" and "may" where the compiler
  has a choice. A specific call site may be fresh, stale, or optimized away;
  only a runtime IR dump or a controlled JIT test can decide a particular
  build.
* **Data race.** If the external writer is another thread, the C++ memory
  model makes the access undefined behavior independent of JSC. The report's
  "sees the new value" statements for the interpreter path assume a
  same-thread writer or an externally synchronized writer.
* **Not a claim about the lineDash UAF.** The prior audit's conclusion that
  the Canvas `lineDash` lifecycle does not free a live State's buffer is
  unchanged. This addendum assumes a 704-class block was freed by some path
  (as the question states) and analyzes what `charCodeAt` does if a
  `StringImpl` subsequently occupies it.
