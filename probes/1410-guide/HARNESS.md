# Guide-browser harness (retail 14.10) — probe delivery, beacons, crash-resume

What this is: the unattended kit our V527/V527b runs (issue #11, comments
6355053043 / 6355204628) executed on. Entry vector: DNS-redirect the Guide's
`ps5.np.playstation.net` + `manuals.playstation.net` to a rig running HTTPS;
the Guide WebView loads our page with full DOM/JS in the WebProcess. This is
a LIVE WebKit entry on 14.10 (contrast README "WebKit entry NOT FOUND" —
that row refers to Relapse-era public exploits; the guide-DNS lane works
today with no jailbreak).

Components (rig side, ~150 lines total):
- `dnsmasq` hijack of the two domains + `server.py` HTTPS on :443.
- Flag-file page routing: presence of `exploit/<NAME>_ON` selects which probe
  page answers `manuals_content`; flip pages with `touch`/`rm`, no restart.
- Beacon channel: probes report via `new Image().src='beacon?m=...'`
  (GET-logged server-side; each message tripled for loss tolerance). Works
  even when later JS dies — no fetch/CORS/PNA issues in this webview.
- Crash-resume: canvas-class deaths exit the whole Guide app; a watchdog
  relaunches the Guide (chiaki-ng input lane + uinput) and the page reloads
  from the same URL, picking up where the flag file left it.
- Remote input lane for manual sessions: `ps5_key <keysym>` (Return=Cross,
  C=Circle which also reloads the page, arrows=D-pad, Esc=PS, T=touchpad).

Operational notes learned the hard way:
- Kill the Guide between flows: same-page flows accumulate memory; a
  1500-object flow followed by 192MB churn OOM-killed the second flow once.
- Beacon ordering: burst-flush after death means log order != exec order;
  timestamp client-side too.
- Webview capability baseline (14.10 guide, verified 2026-10-22 beacons):
  no OffscreenCanvas, no indexedDB (but IDBKeyRange ctor exists),
  no ReallocatableArrayBuffer (`{rab:true}` silently plain), no
  canvas.reset, no canvas.type attribute, WebGL/WASM absent.

Probe files in this PR are the V527 AB-reclaim discriminator + the lever/RAB
follow-up we ran 3 loads each; both beacon-only, no side effects.
