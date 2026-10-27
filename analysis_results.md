# bmalloc 704-byte free-slot reuse — audit findings

**Questions under test:** for a 704-byte object freed with `fastFree` and later
re-allocated with `fastMalloc`:

1. is the freed slot put on a per-page free list, a per-thread cache, or a
   global free list;
2. does the next allocation reuse the most recently freed slot (LIFO), the
   oldest (FIFO), or an address-ordered slot;
3. does a 704-byte double array and a 684-byte string compete for the same
   freed slot;
4. are frees batched or processed immediately;
5. is any metadata written into the freed slot that could corrupt the new
   allocation's data?

**Short answer.** In this bmalloc revision a freed small object is **not** put on
any per-object free list. `fastFree` appends it to a per-thread (per-cache)
deferred-free log; when that log is flushed the only per-object state updated is
a line refcount. A slot becomes reusable when the `SmallLine` containing its
start has no live object; its page is then queued in a per-thread page cache.
Allocation is a bump allocator, so the next 704-byte allocation normally takes
the *next untouched slot*, not the freed one. When a page is re-scanned, slots
are taken in **ascending address order** — not LIFO, not FIFO. A 684-byte
8-bit string plus the 20-byte `StringImpl` header is exactly 704 bytes, so it
lands in the **same size class (66)** as the 704-byte array; the two calls draw
from the same class-66 state but can only consume the freed slot one at a time.
Frees are batched (512 per thread) and no metadata is written into the 704-byte
payload; freed bytes retain stale user data.

**Prior content.** This file previously held a `CanvasRenderingContext2D`
`lineDash` audit. It is preserved at
`.scratch/analysis_results.canvas-linedash.final.md` (and an earlier draft at
`.scratch/analysis_results.canvas-linedash.md`).

---

## 0. Answers at a glance

| # | Question | Finding |
|---|---|---|
| 1 | Where does a freed 704-byte object go? | **Per-thread deferred-free log**, then a line-refcount update. The *page* goes to a per-thread page cache when a line frees. There is **no per-page object free list** and **no global object free list**. |
| 2 | Which freed slot is reused? | **Address-ordered at page-rescan granularity**, not LIFO/FIFO. The immediate next allocation usually advances the bump pointer past the freed slot. |
| 3 | Do 704-byte array and 684-byte string compete? | **Yes — both are class 66 (704 bytes)** for an 8-bit string (`684 + 20 = 704`). Same thread/Primary heap ⇒ same bump allocator and page cache. They can consume the freed slot sequentially, never simultaneously. A 16-bit 684-character string (`20 + 1368 = 1388`) is class 74 (1408), so it does not compete. |
| 4 | Batched or immediate? | **Batched per thread**: up to 512 frees in `m_objectLog`, flushed when full, on `scavenge()`, or at an allocation slow-path refill. |
| 5 | Metadata in the freed slot? | **None written by the small allocator.** Line/page metadata is out of band in the 1 MB chunk header; the 704 payload is untouched. Consequence: stale data is returned (no zeroing), and a UAF write lands directly in the next allocation's payload. |

The rest of this document substantiates each row with source citations and
records one build-configuration finding that changes the applicability of the
"PS5 uses libpas" claim in the repository's earlier notes.

---

## 1. Scope, provenance, and backend selection

### 1.1 Source identity

Two trees in this workspace contain the same bmalloc generation:

| Alias | Absolute root | Role |
|---|---|---|
| `WK1400` | `/home/violence/Work/WebKit-1400/WebKit-1400/WebKit-1400` | PS5 14.10 WK-1400 reference tree (`Configurations/Version.xcconfig:24`, `MAJOR_VERSION = 616`) |
| `WK242` | `/home/violence/Work/PS5-14.10-Jailbreak-Research/.webkit-src` | WebKitGTK 2.42.5 tree used as a cross-check |

The bmalloc files relevant to this audit are **byte-identical** between the two
trees for:

`Sizes.h`, `Deallocator.h`, `Deallocator.cpp`, `Allocator.h`, `Allocator.cpp`,
`BumpAllocator.h`, `SmallLine.h`, `SmallPage.h`, `Chunk.h`, `LineMetadata.h`,
`HeapConstants.h`, `HeapConstants.cpp`, `List.h`, `FixedVector.h`, `FreeList.h`,
`IsoAllocator.h`, `ObjectType.h`.

`WK1400/.../Heap.cpp` and `Heap.h` differ only in (a) a PlayStation-only
`releaseLargeFree` hook and (b) two chunk-list `remove` lines; `bmalloc.h`
additionally omits the `tryZeroedMalloc`/`zeroedMalloc` wrappers that `WK242`
has. None of these affects the small-object free/allocation path cited below. All
citations use the `WK1400` tree first; where a file is identical, the same line
numbers apply to `WK242`.

`WK1400/.../Heap.cpp` is also byte-identical to upstream
`WebKit/WebKit` at commit `3fca1b37291f10c1bc0b672f96542994873c8f4c`
(2023-04-27, the last change to that file before the 2.42-era snapshot) except
for the PlayStation `releaseLargeFree` hook and two chunk-list `remove` lines.
This is a stock bmalloc, not a locally re-written allocator.

### 1.2 Backend selection: the PS5 reference build compiles bmalloc, not libpas

This matters because `BPlatform.h`'s platform default is misleading if read in
isolation.

```cmake
# WK1400:Source/cmake/OptionsPlayStation.cmake:283-287
if (NOT ENABLE_WEBCORE)
    WEBKIT_OPTION_DEFINE(ENABLE_LIBPAS PRIVATE "Toggle libpas support" OFF)
else ()
    WEBKIT_OPTION_DEFINE(ENABLE_LIBPAS PRIVATE "Toggle libpas support" OFF)
endif ()
...
# :741-742
if (NOT ENABLE_LIBPAS)
    add_definitions(-DBENABLE_LIBPAS=0)
endif ()
```

`ENABLE_LIBPAS` defaults **OFF** in both branches. When it is off, the build
adds `-DBENABLE_LIBPAS=0`. `BPlatform.h` then skips its PlayStation default
because `BENABLE_LIBPAS` is already defined:

```cpp
// WK1400:Source/bmalloc/bmalloc/BPlatform.h:340-358
#if !defined(BENABLE_LIBPAS)
#if BCPU(ADDRESS64) && (BOS(DARWIN) || ... || BPLATFORM(PLAYSTATION))
#define BENABLE_LIBPAS 1
...
#endif
#endif

#if !defined(BUSE_LIBPAS)
#if defined(BENABLE_LIBPAS) && BENABLE_LIBPAS
#define BUSE_LIBPAS 1
#else
#define BUSE_LIBPAS 0      // <- PS5 default: -DBENABLE_LIBPAS=0
#endif
#endif
```

With `BUSE_LIBPAS == 0`, `bmalloc::api::free` takes the bmalloc branch:

```cpp
// WK1400:Source/bmalloc/bmalloc/bmalloc.h:141-149
BINLINE void free(void* object, HeapKind kind = HeapKind::Primary)
{
#if BUSE(LIBPAS)
    BUNUSED(kind);
    bmalloc_deallocate_inline(object);
#else
    Cache::deallocate(kind, object);   // <- default PS5 build
#endif
}
```

and `malloc` takes `Cache::allocate` at `bmalloc.h:68-77`.

**Repository note corrected.** `docs/DEAD_ENDS.md:293` says "libpas confirmed on
PS5 (`BPLATFORM(PLAYSTATION)` at `BPlatform.h:341`)". That citation only shows
the *platform capability default*. The PS5 CMake option above overrides it to
`BENABLE_LIBPAS=0` and no file in the reference tree re-enables libpas (grep for
`ENABLE_LIBPAS` finds only `OptionsPlayStation.cmake:284,286,741,742`). Unless
the shipping build passes `-DENABLE_LIBPAS=ON` (or the binary shows `pas_*`
symbols), the bmalloc path analyzed here is the relevant one.

If the target build *does* enable libpas, this document does not describe its
allocator; the five answers must be re-derived against libpas. That is a
separate audit. The remainder of this document assumes the reference tree's
default: `BUSE_LIBPAS == 0`.

---

## 2. Size-class arithmetic for 704 and 684

`Sizes.h` defines the classes:

```cpp
// WK1400:Source/bmalloc/bmalloc/Sizes.h:46-57, 68-69
static constexpr size_t alignment = 8;
static constexpr size_t smallLineSize = 256;
static constexpr size_t smallPageSize = 4 * kB;
static constexpr size_t maskSizeClassMax = 512;
static constexpr size_t smallMax = 32 * kB;
...
static constexpr size_t deallocatorLogCapacity = 512;
static constexpr size_t bumpRangeCacheCapacity = 3;
```

Requests ≤ 512 use 8-byte mask classes; requests above 512 use 64-byte
logarithmic buckets (`Sizes.h:91-119`). Compiling the actual header gives:

| bmalloc request | class | object size |
|---|---|---|
| 640 | 65 | 640 |
| 641 | 66 | **704** |
| 684 | 66 | **704** |
| 688 | 66 | **704** |
| 704 | 66 | **704** |
| 705 | 67 | 768 |
| 1388 | 74 | 1408 |

Two points that matter for the questions:

* **684 does not round to 688.** There is no 688-byte class in this scheme.
  Class 66 covers requests 641–704 and always hands out 704-byte slots.
* 704 `> 512`, so the allocation path is `allocateSlowCase` →
  `allocateLogSizeClass` (`Allocator.cpp:157-172`, `:146-155`), i.e. the
  by-object bump path, not the ≤512 inline fast path.

For a 4 KB VM page (x86-64/PS5), `HeapConstants::initializePageMetadata`
(`HeapConstants.cpp:112-131`) chooses an **8 KB page** for class 66: 8192 % 704
= 448, which is below the 1/8 waste threshold. That page holds
`floor(8192 / 704) = 11` objects, at page-relative offsets 0, 704, …, 7040.
This is the layout used in the worked example in §4.3.

---

## 3. Q1 — Where a freed 704-byte object goes

### 3.1 `fastFree` puts the pointer in a per-thread deferred-free log

```cpp
// WK1400:Source/WTF/wtf/FastMalloc.cpp:564-571
void fastFree(void* object)
{
    bmalloc::api::free(object);
    ...
}
```

```cpp
// WK1400:Source/bmalloc/bmalloc/Deallocator.h:76-80
inline void Deallocator::deallocate(void* object)
{
    if (!deallocateFastCase(object))
        deallocateSlowCase(object);
}

// :63-74
inline bool Deallocator::deallocateFastCase(void* object)
{
    BASSERT(mightBeLarge(nullptr));
    if (mightBeLarge(object))
        return false;
    if (m_objectLog.size() == m_objectLog.capacity())
        return false;
    m_objectLog.push(object);
    return true;
}
```

`m_objectLog` is `FixedVector<void*, deallocatorLogCapacity>` (`Deallocator.h:59`),
i.e. 512 raw pointers. The `Deallocator` is a member of `Cache`, and `Cache` is
per-thread: `PerThread<PerHeapKind<Cache>>` (`Cache.h:42`, `:217-223`). So this
is a **per-thread, per-heap-kind** queue, not a per-page list and not a global
list.

A 704-byte object can take the `mightBeLarge` branch only if its address is
4 KB-aligned (`largeAlignment == 4096`; `ObjectType.h:42-45`), in which case it
goes through `deallocateSlowCase`; the destination is still the same log
(`Deallocator.cpp:79-84`).

### 3.2 Flushing the log updates a line refcount, not a free list

```cpp
// WK1400:Source/bmalloc/bmalloc/Deallocator.cpp:61-66
void Deallocator::processObjectLog(UniqueLockHolder& lock)
{
    for (Object object : m_objectLog)
        m_heap.derefSmallLine(lock, object, lineCache(lock));
    m_objectLog.clear();
}
```

```cpp
// WK1400:Source/bmalloc/bmalloc/Heap.h:165-170
inline void Heap::derefSmallLine(UniqueLockHolder& lock, Object object, LineCache& lineCache)
{
    if (!object.line()->deref(lock))
        return;
    deallocateSmallLine(lock, object, lineCache);
}
```

```cpp
// WK1400:Source/bmalloc/bmalloc/SmallLine.h:61-66
inline bool SmallLine::deref(UniqueLockHolder&)
{
    BASSERT(m_refCount);
    --m_refCount;
    return !m_refCount;
}
```

The only per-object bookkeeping is `SmallLine::m_refCount` (`SmallLine.h:47`),
stored in the chunk's `m_lines` array (`Chunk.h:57-59`), **not in the object**.
For 704-byte objects (class 66 > `smallLineSize`), allocation is by object
(`Heap.h:155-163`): each object start is recorded by ref'ing the line containing
that start (`Heap.cpp:471-483`). The line is the slot's liveness marker. When
the count reaches zero, the slot is reusable; while any other object still
starts in that line, the free is only a decrement.

### 3.3 When a line frees, the *page* goes to a per-thread page cache

```cpp
// WK1400:Source/bmalloc/bmalloc/Heap.cpp:339-351
void Heap::deallocateSmallLine(UniqueLockHolder& lock, Object object, LineCache& lineCache)
{
    BASSERT(!object.line()->refCount(lock));
    SmallPage* page = object.page();
    page->deref(lock);

    if (!page->hasFreeLines(lock)) {
        page->setHasFreeLines(lock, true);
        lineCache[page->sizeClass()].push(page);
    }

    if (page->refCount(lock))
        return;
    ...
}
```

`LineCache` is `std::array<List<SmallPage>, sizeClassCount>` (`SmallPage.h:77`).
`List::push` inserts at the tail and `popFront` removes the head
(`List.h:70-94`), so this page cache is **FIFO at page granularity**.

`SmallPage::ref` is taken once per object carved into a bump range
(`Heap.cpp:479-480`), so `page->refCount` counts live/reserved objects. If it is
non-zero, the page stays where it is. If it reaches zero, the page is unlinked
and returned to the chunk's `freePages`, the heap's `m_freePages`, and
eventually `m_chunkCache` (`Heap.cpp:353-376`). Those are **page/chunk**
free lists — not object free lists.

The per-thread page list is later drained to the per-heap page list at
scavenge:

```cpp
// WK1400:Source/bmalloc/bmalloc/Deallocator.cpp:53-59
void Deallocator::scavenge()
{
    UniqueLockHolder lock(Heap::mutex());
    processObjectLog(lock);
    m_heap.deallocateLineCache(lock, lineCache(lock));
}
```

```cpp
// WK1400:Source/bmalloc/bmalloc/Heap.cpp:207-215
void Heap::deallocateLineCache(UniqueLockHolder&, LineCache& lineCache)
{
    for (auto& list : lineCache) {
        while (!list.isEmpty()) {
            size_t sizeClass = &list - &lineCache[0];
            m_lineCache[sizeClass].push(list.popFront());
        }
    }
}
```

### 3.4 Answer to Q1

**Per-thread cache — specifically a 512-entry deferred-free log, followed by a
line-refcount update and a per-thread FIFO page cache.** The freed 704-byte
object is never linked into a per-page free list or a global free list. The
only object-level state is the line refcount; the only lists are page-level and
per-thread (or per-heap after scavenge).

---

## 4. Q2 — Which freed slot is reused

### 4.1 Allocation is a per-size-class bump allocator

```cpp
// WK1400:Source/bmalloc/bmalloc/Allocator.cpp:146-155
BNO_INLINE void* Allocator::allocateLogSizeClass(size_t size, FailureAction action)
{
    size_t sizeClass = bmalloc::sizeClass(size);
    BumpAllocator& allocator = m_bumpAllocators[sizeClass];
    if (!allocator.canAllocate())
        refillAllocator(allocator, sizeClass, action);
    ...
    return allocator.allocate();
}
```

```cpp
// WK1400:Source/bmalloc/bmalloc/BumpAllocator.h:73-81
inline void* BumpAllocator::allocate()
{
    BASSERT(m_remaining);
    --m_remaining;
    char* result = m_ptr;
    m_ptr += m_size;      // strictly ascending addresses
    return result;
}
```

Each `Allocator` owns `std::array<BumpAllocator, sizeClassCount>` and
`std::array<BumpRangeCache, sizeClassCount>` (`Allocator.h:70-71`), constructed
with `objectSize(sizeClass)` (`Allocator.cpp:46-47`). A free does **not** push
the slot back into this bump allocator; `m_ptr` never moves backwards.

### 4.2 Refill: flush the free log, then scan the page from its lowest address

```cpp
// WK1400:Source/bmalloc/bmalloc/Allocator.cpp:123-130
BNO_INLINE void Allocator::refillAllocatorSlowCase(BumpAllocator& allocator, size_t sizeClass, FailureAction action)
{
    BumpRangeCache& bumpRangeCache = m_bumpRangeCaches[sizeClass];

    UniqueLockHolder lock(Heap::mutex());
    m_deallocator.processObjectLog(lock);      // pending frees become visible here
    m_heap.allocateSmallBumpRanges(lock, sizeClass, allocator, bumpRangeCache, m_deallocator.lineCache(lock), action);
}
```

`refillAllocator` first drains the 3-entry `BumpRangeCache` without flushing
(`Allocator.cpp:132-138`); the flush above happens only when both the current
bump range and the cache are exhausted.

`allocateSmallPage` takes a page from the calling thread's cache, then the
per-heap cache, before touching free chunks (`Heap.cpp:289-293`). The by-object
path then scans from the **page's lowest address**:

```cpp
// WK1400:Source/bmalloc/bmalloc/Heap.cpp:463-486
auto findSmallBumpRange = [&](Object& it, Object& end) {
    for ( ; it + size <= end; it = it + size) {
        if (!it.line()->refCount(lock))
            return true;
    }
    return false;
};

auto allocateSmallBumpRange = [&](Object& it, Object& end) -> BumpRange {
    char* begin = it.address();
    unsigned short objectCount = 0;
    for ( ; it + size <= end; it = it + size) {
        if (it.line()->refCount(lock))
            break;
        ++objectCount;
        it.line()->ref(lock);
        it.page()->ref(lock);
    }
    return { begin, objectCount };
};

Object it(page->begin()->begin());   // lowest address in the page
Object end(it + pageSize(m_constants.pageClass(page->sizeClass())));
```

It takes the first object-aligned slot whose start line has refcount 0, then
carves a contiguous run upward (`BumpRange`). `BumpAllocator::refill` then hands
that run out in ascending order (`BumpAllocator.h:83-89`).

Two ordering subtleties:

* The **page** queue is FIFO (tail push / head pop, `List.h:70-94`), so among
  pages with free lines the oldest cached page is scanned first.
* The **bump-range cache** is a `FixedVector` whose `pop()` returns the last
  element (`FixedVector.h:96-100`), so up to three extra ranges carved from a
  fragmented page are consumed newest-first. The slot-selection rule is still
  "scan low to high; bump upward within a range"; it is not a stack of
  individual freed objects.

### 4.3 Worked example on an 8 KB class-66 page

Slots (page-relative): `0, 704, 1408, …, 7040` (11 slots).

1. Thread allocates `A` at slot 0. The bump allocator now points at 704 with
   10 slots remaining; the whole run is pre-ref'd on its start lines.
2. `fastFree(A)` appends `A` to `m_objectLog`. No page/line metadata changes
   yet unless the log is flushed.
3. The next two 704-byte allocations are class-66 bump allocations. They take
   slots **704 and 1408**. Neither is `A`.
4. After the run is consumed, the next allocation enters
   `refillAllocatorSlowCase`, which flushes the log (now `A`'s line refcount
   drops to 0), pops `A`'s page from the thread page cache, scans from offset 0,
   finds slot 0 free, and hands `A`'s slot to that allocation.

If `A` had been the *last* slot (7040), the refill would find 7040 free and reuse
it. If several lower slots were also free, the **lowest** one would win, not the
most recently freed one.

### 4.4 Answer to Q2

**Address-ordered, at page-rescan/bump-range granularity — not LIFO, not FIFO.**
The immediate next allocation after a free usually gets the next untouched slot
because the bump pointer has already moved past the freed slot. The freed slot
becomes a candidate only when the current range (and the 3-entry range cache) is
exhausted and a page is re-scanned; the scan starts at the page's lowest address
and takes the first free object-aligned slot. The page queue is FIFO, but that
is page ordering, not per-slot ordering.

---

## 5. Q3 — 704-byte double array vs 684-byte string

### 5.1 The double array

88 doubles = `88 * 8 = 704` bytes. A heap-backed `Vector<double>` buffer
allocates exactly `capacity * sizeof(double)` through `FastMalloc`
(`VectorBufferMalloc` is `FastMalloc`; `DebugHeap.h:91-92`), so the bmalloc
request is 704 → class 66.

### 5.2 The 684-byte string

`StringImpl` stores its header and characters in one allocation:
`m_refCount` (4) + `m_length` (4) + the data pointer union (8) + `m_hashAndFlags`
(4) = **20 bytes** before the character tail (`StringImpl.h:161-171`).
`allocationSize<T>(n) = tailOffset<T>() + n * sizeof(T)`
(`StringImpl.h:1298-1301`), and `tailOffset<T>()` rounds
`offsetof(m_hashAndFlags) + 4 = 20` up to `alignof(T)`
(`StringImpl.h:1310-1313`). For `LChar` (8-bit):

```
allocationSize<LChar>(684) = 20 + 684 = 704
```

so the string request is also class 66. `StringImplMalloc` is `FastMalloc` when
`ENABLE(MALLOC_HEAP_BREAKDOWN)` is off (`DebugHeap.h:91-92`), and
`FastMalloc::malloc` calls `fastMalloc` (`FastMalloc.h:217-218`), which calls
`bmalloc::api::malloc` (`FastMalloc.cpp:529-539`) on the Primary heap.

If "684-byte string" means 684 bytes *including* the header, the request is 684
and is still class 66. If the string is 16-bit (`UChar`), the request is
`20 + 684 * 2 = 1388` → class 74 (1408), and it does **not** compete with the
704 slot. If any header/padding pushes the request past 704 (e.g. 709), it is
class 67 (768), also no competition.

### 5.3 Same thread, same heap, same class

Both requests go to `bmalloc::api::malloc` on `HeapKind::Primary`
(`bmalloc.h:68-77`), which selects the calling thread's `Cache`
(`Cache.h:42`, `:217-223`). On the same thread both use the same class-66
`BumpAllocator`, `BumpRangeCache`, and `LineCache`. They therefore draw from the
same pool and **can** consume the same freed slot — but only sequentially:
whichever allocation triggers/consumes the refill that includes the slot gets
it; the other gets the next slot. There is no per-slot free-list entry that both
can pop.

If the two calls run on different threads, each uses its own `Cache`. The freed
page is queued in the *freeing* thread's line cache; the other thread cannot see
it until scavenge drains that cache into the per-heap `m_lineCache`
(`Deallocator.cpp:53-59`, `Heap.cpp:207-215`). In that case they do not compete
for the slot in the short term.

If the double array is a Gigacage-backed `ArrayBuffer` (allocated with an
auxiliary heap kind), it is a different `HeapKind`/`Cache` and does not share
the Primary class-66 pool. The analysis above assumes a plain
`fastMalloc`/`Vector` buffer, as stated in the question.

### 5.4 Answer to Q3

**Yes, both are class 66 (704 bytes) and compete at the size-class level** for
an 8-bit 684-byte string (`684 + 20 = 704`). They share the per-thread class-66
bump allocator and page cache, so the freed slot can go to either one, but only
one at a time, and usually not on the immediate next allocation (the bump
pointer is still ahead of it). They do **not** compete if the string is 16-bit
(1388 → class 74), if its total request exceeds 704 (class 67+), if the calls
are on different threads, or if one is on a different heap kind.

---

## 6. Q4 — Batched or immediate frees

`fastFree` is not immediate. The object is appended to the per-thread
`m_objectLog` (`Deallocator.h:63-74`), which holds
`deallocatorLogCapacity = 512` pointers (`Sizes.h:68`). The log is drained:

* when it is full — `deallocateSlowCase` takes the heap lock and calls
  `processObjectLog` before pushing the 513th object
  (`Deallocator.cpp:79-84`);
* on `Deallocator::scavenge()` (`Deallocator.cpp:53-59`), which is also called
  from the destructor (`Deallocator.cpp:48-51`);
* at an allocation slow-path refill — `refillAllocatorSlowCase` calls
  `processObjectLog` under the heap lock before `allocateSmallBumpRanges`
  (`Allocator.cpp:123-130`).

Consequences for a 704-byte slot:

* A free can sit in the log while up to 511 other frees accumulate. Until the
  flush, the line refcount is unchanged, so the slot is **not** reusable even if
  the bump allocator refills.
* The flush is per-thread; there is no global free batch.
* Because the allocation refill flushes the log first, a slot freed just before
  a refill is visible to that refill's page scan.

**Answer: batched, per thread, 512 entries; not immediate.**

---

## 7. Q5 — Metadata stored in freed slots

### 7.1 The small-object path writes nothing into the payload

For a 704-byte class-66 object the allocator's metadata is:

| Metadata | Location | Citation |
|---|---|---|
| line refcount | `SmallLine::m_refCount` in `Chunk::m_lines` (chunk header) | `SmallLine.h:47`, `Chunk.h:57-59` |
| line start offset / object count | `LineMetadata`, per-process `HeapConstants` table | `LineMetadata.h:34-37`, `HeapConstants.h:54-57` |
| page size class / flags / refcount | `SmallPage` in `Chunk::m_pages` (chunk header) | `SmallPage.h:64-70`, `Chunk.h:57-59` |
| pending free pointer | `Deallocator::m_objectLog` (per-thread array) | `Deallocator.h:59` |

None of these is in the 704-byte payload. `Object::line()` only computes
`&m_lines[offset / 256]` (`Chunk.h:165-168`, `:119-123`); `mightBeLarge` is an
address-alignment test, not an in-band header read (`ObjectType.h:42-45`).

The one in-band free-list cell in bmalloc is `FreeCell::scrambledNext`
(`FreeList.h:39-56`), used by the IsoHeap allocator (`IsoAllocator.h:51`), not
by the 704-byte `fastMalloc` path. It does not apply here.

Large allocations are also tracked out of band (`LargeMap` /
`m_largeAllocated`, `Heap.h:140-141`), but 704 is below `smallMax` and never
takes that path.

### 7.2 The real hazard is stale data, not allocator metadata

`fastMalloc` returns the slot without zeroing or poisoning
(`Allocator.cpp:146-155`, `BumpAllocator.h:73-81`). Therefore:

* the next 704-byte allocation receives the previous object's stale bytes
  (information-disclosure surface if the caller reads before writing);
* a use-after-free **write** goes straight into the next allocation's payload,
  with no allocator canary/metadata to detect or absorb it;
* the allocator cannot be corrupted by "metadata in the slot", because there is
  no such metadata.

A DebugHeap build is a different allocator path; the bmalloc `Deallocator`
asserts the debug heap is disabled (`Deallocator.cpp:45`).

**Answer: no in-band allocator metadata is written; the freed slot is untouched
stale user memory.**

---

## 8. Compliance findings

| ID | Finding | Consequence for the audit |
|---|---|---|
| **F1** | **684 ≠ 688.** Class 66 covers 641–704; 684 (and `684 + 20 = 704` for an LChar `StringImpl`) is the same class as 704. | Any model that assumes a 16-byte-aligned 688 slot for the string is wrong for this bmalloc. It competes with the 704 array. |
| **F2** | **No per-object free list.** Frees go to a 512-entry per-thread log, then a line refcount; the page goes to a per-thread FIFO page cache. | LIFO/FIFO free-list grooming assumptions are wrong. A freed slot is not immediately reusable and is not at the head of a stack. |
| **F3** | **Reuse is bump/address-ordered.** The next allocation advances the bump pointer; a freed slot is revisited only at a refill, and then the lowest free slot on the scanned page wins. | To reclaim a specific 704 slot, the allocator's current range and 3-entry range cache must be exhausted (or the thread cache scavenged); then the page must be selected and the target must be the lowest free slot. |
| **F4** | **Frees are batched (512).** The line refcount does not change until a flush. | Free-to-reuse timing has an extra 0–512-free delay, except that an allocation refill flushes the log first. |
| **F5** | **No in-band metadata in small slots.** Stale data persists. | A UAF write corrupts user data, not allocator metadata; there is no poisoning to detect it. |
| **F6** | **PS5 build config defaults to bmalloc, not libpas.** `ENABLE_LIBPAS=OFF` → `-DBENABLE_LIBPAS=0`; `docs/DEAD_ENDS.md:293`'s libpas claim cites only the platform default. | The bmalloc answers are runtime-relevant for the reference build. If the shipping binary enables libpas, the entire document must be re-derived against libpas. |

---

## 9. Verification

### 9.1 Size classes (compiled against the actual `Sizes.h`)

```bash
g++ -std=c++17 -I WK1400/Source/bmalloc/bmalloc cls.cpp -o cls
./cls
```

Output (trimmed):

```
request   640 -> class  65 -> objectSize   640
request   641 -> class  66 -> objectSize   704
request   684 -> class  66 -> objectSize   704
request   688 -> class  66 -> objectSize   704
request   704 -> class  66 -> objectSize   704
request   705 -> class  67 -> objectSize   768
request  1388 -> class  74 -> objectSize  1408
```

### 9.2 Page geometry for class 66 on a 4 KB VM page

`computePageSize` (`HeapConstants.cpp:112-131`) picks 8192:

```
8192 % 704 = 448 <= 8192 / 8 = 1024  -> pageSize 8192, pageClass 1
floor(8192 / 704) = 11 objects per page
```

### 9.3 Source identity

`WK1400/Source/bmalloc/bmalloc/Heap.cpp` was diffed against upstream
`WebKit/WebKit` commit `3fca1b37291f10c1bc0b672f96542994873c8f4c`; apart from
the PlayStation `releaseLargeFree` hook and two chunk-list `remove` lines, it is
byte-identical. The bmalloc
files listed in §1.1 are byte-identical between `WK1400` and `WK242`, so the
line numbers for those files are valid in either tree.

---

## 10. Citation index

Paths are relative to `WK1400` unless marked `WK242`. `WK242` has the same
content for every file listed in §1.1.

| Claim | Citation |
|---|---|
| `fastFree` → `bmalloc::api::free` | `Source/WTF/wtf/FastMalloc.cpp:564-571` |
| `api::free` → per-thread `Cache::deallocate` | `Source/bmalloc/bmalloc/bmalloc.h:141-149` |
| `Cache` is per-thread, per-heap-kind | `Source/bmalloc/bmalloc/Cache.h:42`, `:217-223` (non-MAT; MAT variant `:145-153`) |
| `Deallocator::deallocate` / fast case | `Source/bmalloc/bmalloc/Deallocator.h:76-80`, `:63-74` |
| 512-entry free log | `Source/bmalloc/bmalloc/Sizes.h:68`; `Deallocator.h:59` |
| log flush → `derefSmallLine` | `Source/bmalloc/bmalloc/Deallocator.cpp:61-66` |
| line refcount decrement | `Source/bmalloc/bmalloc/SmallLine.h:55-66`; member `:47` |
| line metadata lives in the chunk | `Source/bmalloc/bmalloc/Chunk.h:57-59`; `Chunk.h:165-168` (line mapping) |
| page queue on line-free | `Source/bmalloc/bmalloc/Heap.cpp:339-351` |
| per-thread page cache type / FIFO | `Source/bmalloc/bmalloc/SmallPage.h:77`; `List.h:70-94` |
| scavenge drains thread cache to heap | `Source/bmalloc/bmalloc/Deallocator.cpp:53-59`; `Heap.cpp:207-215` |
| page/chunk free path | `Source/bmalloc/bmalloc/Heap.cpp:353-376` |
| 704 class 66 / 684 class 66 | `Source/bmalloc/bmalloc/Sizes.h:46-57`, `:91-119`; compiled test §9.1 |
| 704 uses `allocateSlowCase`/log class | `Source/bmalloc/bmalloc/Allocator.cpp:157-172`, `:146-155` |
| bump allocator (ascending) | `Source/bmalloc/bmalloc/BumpAllocator.h:73-81`; `Allocator.h:70-71` |
| refill flushes log first | `Source/bmalloc/bmalloc/Allocator.cpp:123-130` |
| page cache priority | `Source/bmalloc/bmalloc/Heap.cpp:289-293` |
| page scan from lowest address | `Source/bmalloc/bmalloc/Heap.cpp:463-486` |
| range cache is LIFO | `Source/bmalloc/bmalloc/FixedVector.h:96-100` |
| `StringImpl` 20-byte header | `Source/WTF/wtf/text/StringImpl.h:161-171` |
| string allocation size formula | `Source/WTF/wtf/text/StringImpl.h:1298-1301`, `:1310-1313` |
| `StringImplMalloc = FastMalloc` (breakdown off) | `Source/WTF/wtf/DebugHeap.h:91-92` |
| `FastMalloc::malloc` → `fastMalloc` | `Source/WTF/wtf/FastMalloc.h:217-218`; `FastMalloc.cpp:529-539` |
| PS5 `ENABLE_LIBPAS` default OFF | `Source/cmake/OptionsPlayStation.cmake:283-287` |
| PS5 `-DBENABLE_LIBPAS=0` | `Source/cmake/OptionsPlayStation.cmake:741-742` |
| `BUSE_LIBPAS` derivation | `Source/bmalloc/bmalloc/BPlatform.h:340-358` |
| `FreeCell` is IsoHeap-only | `Source/bmalloc/bmalloc/FreeList.h:39-56`; `IsoAllocator.h:51` |
| `mightBeLarge` is alignment-only | `Source/bmalloc/bmalloc/ObjectType.h:42-45` |
| no zeroing on allocation | `Source/bmalloc/bmalloc/BumpAllocator.h:73-81`; `Allocator.cpp:146-155` |

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
