# Probe Guidelines

Official rules for writing, reviewing, and deploying probes to the PS5 14.10 browser.
Every probe author (human or AI) must follow these rules. Opus 5.5 audit is mandatory before any deploy to device.

Last updated: 2026-10-23

---

## 1. Naming Convention

Probes use a V-number system. The number increments globally across all sessions and never resets.

| Range      | Era / Purpose                                           |
|------------|---------------------------------------------------------|
| V141-V162  | MetadataTable overflow probes (heap groom, sweep, extraction) |
| V170-V182  | CSSFontFace and font parser fuzz                        |
| V221-V246  | ClonedArguments butterfly UAF                           |
| V260-V270  | Font loca OOB and parser validation                     |
| V490-V529  | Canvas UAF early work (ref-pin, RAB byteLength)         |
| V530-V573  | Canvas2D alias chain (CVE-2026-43720)                   |
| V580-V600  | Info leak survey, JSC capability, state buffer           |
| V610-V643  | Cross-context UAF, IO/RO, uninit paths, Blob/WS         |
| V660-V695  | ASLR defeat chain (APNG, DAZ bypass, JSFunction)        |
| V696+      | Current: full exploitation chain probes                  |

Rules:
- Always use the next available number. Check launcher.html and PROBE_INDEX.md.
- File name: `v<NUMBER>.html` (lowercase v, no padding).
- Title inside the file: `V<NUMBER>` (uppercase V).
- One probe = one HTML file. No external JS dependencies (the PS5 loads from LAN only).

## 2. Required Structure

Every probe must contain these phases in order.

### 2.1 HTML Boilerplate

```html
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<title>V###</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a12;color:#d8d8f0;font-family:monospace;font-size:13px;padding:16px}
h1{color:#00e5d0;font-size:16px;margin-bottom:4px}
.sub{color:#5a5a80;font-size:11px;margin-bottom:12px}
#log{white-space:pre-wrap;line-height:1.6;font-size:12px}
.ok{color:#22dd66}.warn{color:#f0c840}.bad{color:#ff3344}
.info{color:#00e5d0}.hit{color:#ff3344;font-weight:bold;font-size:14px}
</style>
</head><body>
<h1>V### -- Short description</h1>
<div class="sub">CVE reference | technique summary</div>
<div id="log"></div>
<script>
'use strict';
(function() {
  // ... probe code ...
})();
</script>
</body></html>
```

The dark color scheme is mandatory. The PS5 browser renders on a TV and bright backgrounds cause readability problems. All log classes (.ok, .warn, .bad, .info, .hit) must be present.

### 2.2 Phase: Boot

First thing the probe does. Checks environment capabilities and sends a BOOT beacon.

```javascript
function phaseBoot() {
  var env = {
    bigu: typeof BigUint64Array !== 'undefined',
    dv:   typeof DataView !== 'undefined',
    f64a: typeof Float64Array !== 'undefined',
    wasm: typeof WebAssembly !== 'undefined',
    sab:  typeof SharedArrayBuffer !== 'undefined'
  };
  var s = 'bigu=' + env.bigu + '|dv=' + env.dv + '|wasm=' + env.wasm + '|sab=' + env.sab;
  B('BOOT', s);
  L('info', '[V###] BOOT ' + s);
  return env;
}
```

Add extra capability checks as needed (Workers, FontFace, WebSocket, etc.). Always beacon the results so we know the environment even if the probe crashes later.

### 2.3 Phase: Main Test

The core logic of the probe. Must be wrapped in try/catch at the top level. Each sub-phase should beacon its result before moving to the next.

### 2.4 Phase: Beacon Report

Final summary beacon with all key results encoded. Name it `DONE` or `FAIL`.

```javascript
B('DONE', 'key1=val1|key2=val2|...');
```

### 2.5 Phase: Cleanup

Release large allocations, reset canvas dimensions to 1x1, null references. The PS5 WebContent process has limited memory and the user may navigate to another probe without a full page reload.

## 3. Beacon Format

All beacons use Image() objects hitting the LAN server.

### 3.1 URL Pattern

```
/beacon/V###-PHASE?d=key=val|key=val&t=<timestamp>
```

- `V###`: probe number, uppercase V.
- `PHASE`: event name (BOOT, UAF, RECLAIM, ALIAS, DONE, FAIL, etc.).
- `d=`: URL-encoded data payload. Use pipe-delimited key=value pairs.
- `t=`: `Date.now()` timestamp for dedup and ordering.

### 3.2 Beacon Pool

Pre-allocate Image objects. The PS5 browser GCs Image objects aggressively if you create them inline.

```javascript
var _bp = [];
for (var _i = 0; _i < 1200; _i++) _bp.push(new Image());
var _bi = 0;
function B(ev, data) {
  try {
    var img = _bp[_bi % _bp.length]; _bi++;
    img.src = '/beacon/V###-' + ev + '?d=' + encodeURIComponent(
      String(data || 'ok').substring(0, 500)) + '&t=' + Date.now();
  } catch(e) {}
}
```

Rules:
- Pool size: 1200 minimum for short probes, 1500 for complex multi-phase probes.
- Always wrap B() body in try/catch. A beacon failure must never crash the probe.
- Truncate data to 500 chars max per beacon (URL length limits).
- NEVER use fetch() or XMLHttpRequest for beacons. Image.src only.

### 3.3 Data Encoding

- Pipe (`|`) separates key=value pairs.
- No spaces in values.
- Hex values: `0x` prefix, 8 or 16 hex chars. Use `h8()` helper.
- Boolean: `true` / `false` (not `1` / `0`).
- Pointers: `0x` + 16 hex chars (hi8 + lo8).

## 4. Safety Rules

### 4.1 Single UAF Rule

**NEVER trigger more than one UAF per page load.** The second free corrupts the bmalloc free list and causes an unrecoverable heap corruption crash. This is a hard rule with no exceptions.

```javascript
// WRONG: two UAF triggers
phaseUAF();  // first trigger
phaseUAF();  // CRASH - heap corruption
```

If you need to test multiple UAF parameters, use separate probe numbers.

### 4.2 Try/Catch All Native WebIDL Calls

Every call to a native Canvas2D, FontFace, or other WebIDL method on a dangling/aliased context must be wrapped in try/catch. Native calls can crash the process if the vtable is corrupted.

```javascript
// CORRECT
try {
  ctx1.lineWidth = 7777.77;
  writeOk = true;
} catch(e) {
  B('WRITE-ERR', (e.message || String(e)).substring(0, 100));
  writeOk = false;
}

// WRONG - bare native call
ctx1.lineWidth = 7777.77;  // process crash if vtable zeroed
```

### 4.3 Graceful Degradation

The probe must report partial results even if it crashes partway through. This means:

- Beacon EACH phase result immediately, before starting the next phase.
- Use the `FAIL` beacon event for unrecoverable errors.
- The BOOT beacon must fire before any dangerous operation.
- Structure phases so earlier results are useful even if later phases crash.

### 4.4 No Infinite Loops or Tight Spins

The PS5 WebContent process has a watchdog timer. Tight loops without yielding will trigger a watchdog kill. Rules:

- No `while(true)` or `for(;;)` without a bounded iteration count.
- If you need async waiting, use `setTimeout` with a reasonable interval (50ms+).
- If you need to poll, set a maximum iteration count (e.g., 10000) and bail with a beacon.
- APNG decode and Image loads are async. Use `onload`/`onerror` callbacks, not polling.

### 4.5 Memory Budget

The PS5 WebContent process OOM-kills at around 1200MB total. Stay well under that.

- **ArrayBuffer spray: maximum 800MB total.** This leaves headroom for the DOM, JS heap, and canvas backing stores.
- Prefer smaller sprays (200-300 ABs of the target size class).
- Release ABs you no longer need by setting array slots to `null` and triggering GC.
- Canvas backing stores: `width * height * 4` bytes each. Set canvas dimensions to 1x1 when done.
- APNG scan canvases: a 16384x1 canvas uses 64KB. Clean up after reading ImageData.

### 4.6 No `eval()`, No Dynamic Script Loading

All code must be inline in the HTML file. No `eval()`, no `Function()` constructor, no dynamic `<script>` element insertion. The PS5 CSP may block these, and they make auditing impossible.

### 4.7 Strict Mode

Always use `'use strict';` at the top of the IIFE. This catches accidental globals and makes offset bugs fail loudly instead of silently writing to `window`.

### 4.8 ES5 Syntax Only (with exceptions)

The PS5 WebKit engine (Safari 17.0 / Version/17.0) supports ES2022, but probes should prefer ES5 for reliability:

- Use `var`, not `let`/`const` (avoids TDZ issues in error paths).
- Use `function` declarations, not arrow functions.
- Use `for` loops, not `for...of` or `Array.prototype.forEach`.
- Exception: `BigInt` literals (`32n`), `BigUint64Array`, and `DataView` are required for pointer work and are confirmed available on PS5 14.10.

## 5. Offset Sources

All C++ object offsets must cite WK-1400 (the open-source WebKit snapshot matching PS5 14.10) with file and line number. Copy of the confirmed offset table:

### 5.1 CanvasRenderingContext2D (768B size class)

```
Offset  Field                    Source
------  -----                    ------
  0     vtable ptr               WK-1400: CanvasRenderingContext2DBase.h
  8     ScriptWrappable::m_wrapper  WK-1400: ScriptWrappable.h
 32     m_canvas (CanvasBase&)   WK-1400: CanvasRenderingContext.h
 40     CanvasPath vtable        WK-1400: CanvasPath.h (secondary vptr)
112     m_stateStack.m_buffer    WK-1400: Vector.h (WTF::Vector<State>)
120     m_stateStack.m_capacity  WK-1400: VectorBufferBase.h (u32)
124     m_stateStack.m_size      WK-1400: Vector.h (u32)
128     inline State[0]          WK-1400: Vector inline buffer start
```

### 5.2 State Struct Offsets (relative to State start)

```
Offset  Field               Source
------  -----               ------
 48     lineWidth (double)  WK-1400: CanvasRenderingContext2DBase.h
 64     miterLimit (double) WK-1400: CanvasRenderingContext2DBase.h
 96     globalAlpha (double) WK-1400: CanvasRenderingContext2DBase.h
168     lineDash.m_buffer   WK-1400: Vector<double> in State
176     lineDash.m_capacity WK-1400: VectorBufferBase.h (u32)
180     lineDash.m_size     WK-1400: Vector.h (u32)
224     FontProxy vptr      WK-1400: FontProxy.h
```

### 5.3 JSFunction / NativeExecutable

```
Offset  Field                    Source
------  -----                    ------
  0     JSCell header (8B)       WK-1400: JSCell.h
 24     m_executableOrRareData   WK-1400: JSFunction.h
        NativeExecutable+40 = m_function  WK-1400: NativeExecutable.h
```

JSFunctionType = 0x1a, Float64ArrayType = 0x2f (WK-1400 JSType.h).

### 5.4 Float64Array / TypedArray

```
Offset  Field        Source
------  -----        ------
 16     m_vector     WK-1400: JSArrayBufferView.h (raw pointer, Gigacage OFF)
 24     m_length     WK-1400: JSArrayBufferView.h
```

Total size: 48 bytes.

### 5.5 Adding New Offsets

When using an offset not listed above:
1. Find it in the WK-1400 source tree (WebKit commit matching PS5 14.10).
2. Cite the header file and line number in a comment next to the constant.
3. Add it to the project memory file for future reference.
4. If unsure, deploy a diagnostic probe to verify the offset on device before using it in an exploitation probe.

## 6. DAZ Rule

The PS5 CPU runs with MXCSR DAZ+FTZ bits set. This means all Canvas2D float64 channels (lineWidth, globalAlpha, miterLimit, lineDashOffset) flush denormal values to zero during FP arithmetic.

**NEVER transport pointers through Canvas2D float64 channels directly.** Heap pointers (e.g., 0x0000000800001000) are subnormal as IEEE 754 doubles and will be flushed to 0.0.

### 6.1 Safe Pointer Transport

Use BigUint64Array, DataView, or Float64Array with integer-path (movsd) operations:

```javascript
// CORRECT: DataView integer path preserves all bits
var ab = new ArrayBuffer(8), dv = new DataView(ab);
dv.setUint32(0, lo, true);
dv.setUint32(4, hi, true);
var val = dv.getFloat64(0, true);  // movsd, no DAZ
// ... store val via Float64Array ...
var ab2 = new ArrayBuffer(8), dv2 = new DataView(ab2);
dv2.setFloat64(0, val, true);      // movsd, no DAZ
var gotLo = dv2.getUint32(0, true); // preserved

// CORRECT: BigUint64Array (confirmed V694)
var bu = new BigUint64Array(ab);
bu[0] = (BigInt(hi) << 32n) | BigInt(lo >>> 0);

// WRONG: Canvas2D float channel
ctx.lineWidth = ptrAsFloat;  // DAZ flushes denormals to 0
var leaked = ctx.lineWidth;  // ALWAYS 0 for heap-range pointers
```

### 6.2 Reading Pointers from Aliased Context

When reading pointers via getLineDash() on an aliased context, the float64 values come through the movsd path and DO preserve bits. But you must extract them via DataView, not FP arithmetic:

```javascript
var dash = ctx.getLineDash();
var buf = new ArrayBuffer(dash.length * 8);
var f64 = new Float64Array(buf);
var rdv = new DataView(buf);
for (var i = 0; i < dash.length; i++) f64[i] = dash[i]; // movsd
// Now read raw bits via DataView
var lo = rdv.getUint32(0, true);
var hi = rdv.getUint32(4, true);
```

## 7. Size Limit

**Maximum 800 lines per probe file.** V695 is 883 lines and that is already at the upper limit. Probes over 800 lines must be split into focused sub-probes or have phases removed.

Why: large files increase parse time on the PS5 JS engine, make auditing harder, and risk exceeding the beacon pool if too many phases fire.

If a probe needs more room, factor out reusable code into a separate "library" probe that beacons nothing and is loaded first via an iframe, or split the test into V###a and V###b.

## 8. Review Requirement

**Every probe must be audited by Opus 5.5 (or equivalent senior model) before deploying to PS5.**

The audit must check:
1. Offset correctness against WK-1400 source.
2. Single-UAF rule compliance.
3. Try/catch on all native WebIDL calls.
4. Memory budget (count total AB allocation, canvas backing, spray sizes).
5. No infinite loops or tight spins.
6. DAZ rule compliance for pointer transport.
7. Beacon coverage (every phase reports before the next starts).
8. Size under 800 lines.
9. No `eval()`, no dynamic script loading.
10. Graceful degradation (does the probe report useful data even if it crashes at phase N?).

Audit findings go to the project analysis board.

## 9. Deploy Process

### 9.1 Pre-Deploy Checklist

- [ ] Opus 5.5 audit passed (or equivalent review).
- [ ] Probe tested in a desktop browser (Chrome/Firefox) for syntax errors.
- [ ] Beacon server running on LAN (`beacon-monitor.html` or equivalent).
- [ ] DEPLOY.lock checked (read it; if another agent holds it, wait or override per user rules).

### 9.2 Steps

1. **Copy probe** to `ps5-webkit-remote-loader/v###.html`.
2. **Take DEPLOY.lock**: write your agent name + timestamp to `DEPLOY.lock`. Max hold: 10 minutes.
3. **Update launcher.html**: add a link to the new probe in the deploy queue section.
4. **Set redirect**: in launcher.html's auto-redirect script, change the target to the new probe:
   ```javascript
   window.location.href = 'v###.html?cb=' + Date.now();
   ```
   The `?cb=` cache-buster forces the PS5 browser to fetch the fresh version.
5. **Release DEPLOY.lock**: delete or clear the lock file.
6. **Update PROBE_INDEX.md** in the research repo with the probe's purpose and result status.
7. **Update current.txt** with the new probe URL.

### 9.3 Cache Busting

The PS5 browser caches aggressively. Always append `?cb=<timestamp>` to the redirect URL. The `Cache-Control: no-cache,no-store,must-revalidate` meta tag helps but is not sufficient alone.

### 9.4 Rollback

If a probe causes a crash loop (PS5 WebContent restarts and immediately reloads the crashing page):
1. Change launcher.html redirect to a known-safe probe (e.g., the most recent DONE probe).
2. Wait for the PS5 to cycle through the crash and load the safe page.
3. Investigate the crash via beacon logs from the partial run.

## 10. Probe Template

Minimal working probe with boot, beacon pool, test phase, and cleanup.

```html
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<title>V###</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a12;color:#d8d8f0;font-family:monospace;font-size:13px;padding:16px}
h1{color:#00e5d0;font-size:16px;margin-bottom:4px}
.sub{color:#5a5a80;font-size:11px;margin-bottom:12px}
#log{white-space:pre-wrap;line-height:1.6;font-size:12px}
.ok{color:#22dd66}.warn{color:#f0c840}.bad{color:#ff3344}
.info{color:#00e5d0}.hit{color:#ff3344;font-weight:bold;font-size:14px}
</style>
</head><body>
<h1>V### -- Description</h1>
<div class="sub">Brief technique note</div>
<div id="log"></div>
<script>
'use strict';
(function() {
  var log = document.getElementById('log');
  function L(cls, msg) {
    var d = document.createElement('div');
    d.className = cls; d.textContent = msg;
    log.appendChild(d); log.scrollTop = log.scrollHeight;
  }

  /* ---- beacon pool ---- */
  var _bp = [];
  for (var _i = 0; _i < 1200; _i++) _bp.push(new Image());
  var _bi = 0;
  function B(ev, data) {
    try {
      var img = _bp[_bi % _bp.length]; _bi++;
      img.src = '/beacon/V###-' + ev + '?d=' + encodeURIComponent(
        String(data || 'ok').substring(0, 500)) + '&t=' + Date.now();
    } catch(e) {}
  }

  /* ---- helpers ---- */
  function h8(v) { return ('00000000' + (v >>> 0).toString(16)).slice(-8); }

  /* ============================================================
     Phase 1: Boot
     ============================================================ */
  function phaseBoot() {
    var env = {
      bigu: typeof BigUint64Array !== 'undefined',
      dv:   typeof DataView !== 'undefined'
    };
    B('BOOT', 'bigu=' + env.bigu + '|dv=' + env.dv);
    L('info', '[V###] BOOT bigu=' + env.bigu + ' dv=' + env.dv);
    return env;
  }

  /* ============================================================
     Phase 2: Main Test
     ============================================================ */
  function phaseTest() {
    L('info', '');
    L('info', '=== Phase 2: Main Test ===');

    try {
      // ... test logic ...
      B('TEST', 'result=ok');
      L('ok', '[TEST] passed');
    } catch(e) {
      B('TEST-ERR', (e.message || String(e)).substring(0, 120));
      L('bad', '[TEST] Error: ' + (e.message || e));
    }
  }

  /* ============================================================
     Phase 3: Cleanup + Final Report
     ============================================================ */
  function phaseCleanup() {
    // Release large allocations
    // Set canvas.width = 1 to free backing stores
    B('DONE', 'summary-here');
    L('ok', '[V###] DONE');
  }

  /* ============================================================
     Main
     ============================================================ */
  function run() {
    try {
      var env = phaseBoot();
      phaseTest();
      phaseCleanup();
    } catch(e) {
      B('FAIL', 'fatal|' + (e.message || String(e)).substring(0, 120));
      L('bad', '[V###] FATAL: ' + (e.message || e));
    }
  }

  run();
})();
</script>
</body></html>
```

## 11. Common Helpers

These helper functions appear in most probes. Copy them as needed.

### 11.1 Hex Formatting

```javascript
function h8(v) { return ('00000000' + (v >>> 0).toString(16)).slice(-8); }
function h2(v) { return ('0' + (v & 0xFF).toString(16)).slice(-2); }
```

### 11.2 DataView 64-bit Read/Write

```javascript
function dvW64(dv, off, hi, lo) {
  dv.setUint32(off, lo, true);
  dv.setUint32(off + 4, hi, true);
}
function dvR64(dv, off) {
  return {lo: dv.getUint32(off, true), hi: dv.getUint32(off + 4, true)};
}
function ptrHex(p) { return '0x' + h8(p.hi) + h8(p.lo); }
```

### 11.3 Float-to-Hex (DAZ-safe)

```javascript
var _cb = new ArrayBuffer(8), _cf = new Float64Array(_cb), _cu = new Uint32Array(_cb);
function f2u(v) { _cf[0] = v; return {lo: _cu[0], hi: _cu[1]}; }
function u2f(hi, lo) { _cu[0] = lo; _cu[1] = hi; return _cf[0]; }
```

## 12. Anti-Patterns (Do Not Do)

| Anti-Pattern | Why It Breaks |
|-------------|---------------|
| `let`/`const` in error-recovery paths | TDZ throws mask the real error |
| Arrow functions as callbacks | Safari 17 supports them but they obscure stack traces |
| `console.log()` as primary output | PS5 has no dev console; use L() + B() |
| `async`/`await` | Adds microtask complexity; use callbacks for APNG/Image loads |
| `new ArrayBuffer(size)` without checking total | OOM kills the whole WebContent process |
| Bare native calls on dangling refs | Process crash, no beacon, no data |
| Two UAF triggers in one page | Heap corruption, unrecoverable crash |
| Pointer values through Canvas2D float setters | DAZ flushes denormals to zero |
| `setTimeout(fn, 0)` in tight loop | Starves beacon delivery |
| `fetch()` or `XMLHttpRequest` for beacons | May be blocked; Image.src always works |

---

End of guidelines. All agents and authors building probes for the PS5 14.10 research project must follow these rules. When in doubt, check the launcher.html deploy queue and the PROBE_INDEX.md for the current state of the probe numbering.
