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
