# APNG hidden-default row disclosure on PS5 14.10

## Scope

This report records a read-only device result from the retail PS5 14.10 Guide
browser and the corresponding WK-1400 source path. It does not establish an
arbitrary-address read, an arbitrary write, a module base, or code execution.

## Source cause

The frozen `PNGImageDecoder::rowAvailable` handles the first animated frame as
frame zero when an APNG has a hidden default image. The frame decoder receives
the `fcTL` width, but the frame-zero pixel loop walks the IHDR canvas width.
When the first animation frame is narrower than the canvas, the decoder reads
past the libpng row and stores those bytes into in-bounds canvas pixels. A page
can recover the pixels with `getImageData`.

The relevant frozen paths are:

- `PNGImageDecoder::readChunks`: `acTL` before the first `fcTL` marks the
  default image hidden, while a narrower `fcTL` remains valid.
- `PNGImageDecoder::processingStart`: the secondary libpng decoder receives
  the `fcTL` dimensions.
- `PNGImageDecoder::rowAvailable`: frame zero uses `size().width()`, the IHDR
  canvas width, for its source walk.

WebKit fixed this shape in bug 321753, commit `56c0a88ac8c4` / `320270@main`,
landed 2026-09-01. The fix postdates the WK-1400 source drop.

## Measurement design

The probes use PNG color type 2 (RGB), with no alpha and no `tRNS`. Canvas
readback inserts opaque alpha; the measurement removes every fourth byte before
classifying the recovered stream. This avoids treating alpha premultiplication
artifacts as source bytes.

Each page load decodes paired assets three times:

- Controls: first animation frame width equals the canvas width.
- Triggers: hidden default image followed by a 16-pixel first animation frame
  whose canvas is wider.

The larger trigger exposes a bounded 510-byte source tail. It is reported in
indexed 64-byte slices. Every slice includes its offset, the total length, and a
whole-stream FNV-1a hash. Controls and triggers are processed through the same
decode, draw, and `getImageData` path.

## Device results

Probe SHA-256:
`1136ab1d1ba59e3f8f45dce5216bc1e6fd74f6bc7023a6864852e2fe20260d73`.

Two independent page loads completed. Each produced 99 beacons: one `BOOT`,
four `ASSET-LOAD`, twelve `DECODE`, twelve `DRAW`, sixty `SLICE`, eight
`RESULT`, one `FINAL`, and one `SURVIVE`. Both loads ended with
`SURVIVE poolLeft=17`. Slice indexes were complete, offsets were contiguous,
and every recomputed FNV matched.

### Controls

The controls were exact and identical across all decodes and both page loads.

| Asset | Reconstructed RGB | Expected fill | FNV-1a |
|---|---:|---|---|
| C63 | 111 bytes | repeating `10 20 30` | `6dddb047` |
| C510 | 558 bytes | repeating `10 20 30` | `8371f31d` |

### Triggers

Neither trigger matched the hidden-default fill. Every decode produced a
different stream.

| Load | Asset | Reconstructed RGB | Decode hashes |
|---|---|---:|---|
| 1 | T63 | 63 bytes | `d00c6701`, `3edf0835`, `57fd72f5` |
| 1 | T510 | 510 bytes | `53d761df`, `707cbc46`, `911a721f` |
| 2 | T63 | 63 bytes | `540f4c50`, `33b1bfa7`, `a1e02940` |
| 2 | T510 | 510 bytes | `6378749f`, `e3102d5f`, `5fef34cd` |

Sliding little-endian 64-bit classification found aligned values in the
`0x00000008xxxxxxxx` userland range. In load 1, nine values appeared at the
same tail offsets in all three T510 decodes. In load 2, the corresponding nine
values appeared in two decodes and every value moved by the same delta,
`0x375fc000`; their pairwise distances were unchanged.

| Tail offset | Load 1 | Load 2 | Delta |
|---:|---:|---:|---:|
| 72 | `0x000000083a614f58` | `0x0000000803018f58` | `0x375fc000` |
| 160 | `0x000000083a53f850` | `0x0000000802f43850` | `0x375fc000` |
| 248 | `0x000000083a544fc0` | `0x0000000802f48fc0` | `0x375fc000` |
| 256 | `0x000000083a545140` | `0x0000000802f49140` | `0x375fc000` |
| 264 | `0x000000083a5451c0` | `0x0000000802f491c0` | `0x375fc000` |
| 272 | `0x000000083a545100` | `0x0000000802f49100` | `0x375fc000` |
| 280 | `0x000000083a545160` | `0x0000000802f49160` | `0x375fc000` |
| 288 | `0x000000083a5452c0` | `0x0000000802f492c0` | `0x375fc000` |
| 336 | `0x000000083a618928` | `0x000000080301c928` | `0x375fc000` |

A separate value at tail offset 408 changed on every decode. It behaved like a
per-decode heap address rather than a stable module pointer.

## Verdict and limits

The exact controls, non-default trigger tails, complete slice hashes, aligned
userland-range values, and rigid cross-load relocation establish a
Guide-reachable process-memory disclosure on this device.

The result does not provide `read64(address)`: the page cannot choose the
source address. The leaked cluster has not been identified as a particular
structure, and none of its values is claimed to be a function pointer or
module base. This evidence also does not independently validate the older
repository statement that a probe named V674 leaked 1,651 pointers; that probe
and its raw result are not part of this report.
