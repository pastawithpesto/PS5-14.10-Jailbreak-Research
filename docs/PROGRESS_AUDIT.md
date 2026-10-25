# Progress Audit

Status of the PS5 14.10 WebKit exploitation research as of October 23, 2026.

## Timeline

| Session | Date | Focus |
|---------|------|-------|
| 1-6 | Oct 15-16 | Bug discovery, stride correction, heap groom, JSString corruption |
| 7-8 | Oct 17 | Extraction attempts, RAB inversion, Relapse testing |
| 9 | Oct 17-18 | Sweep survival testing, MetadataTable declared BLOCKED/DEAD |
| 10 | Oct 18 | Pivot to new surfaces. Font/image recon. 17+ audit agents deployed |
| 11-13 | Oct 18-19 | CSSFontFace UAF (DoS-only), tee() type confusion (contained), WK-1400 audit |
| 14-16 | Oct 19-20 | IsoHeap OFF discovery, CVE-2026-43720 reopened, first reclaim attempts |
| 17-19 | Oct 20-21 | Same-type reclaim V573 CONFIRMED, full R/W via alias V562/V630 |
| 20-21 | Oct 21-22 | Crash oracle development, heap topology mapping V650-V655 |
| 22-25 | Oct 22-25 | Info leak hunting; hidden-default APNG process disclosure confirmed with V704/V705 controls |

## Exploit Chain Progress

| Stage | Status | Notes |
|-------|--------|-------|
| Bug identification | **DONE** | CVE-2026-43720 Canvas getContext() UAF |
| Source audit (WK-1400) | **DONE** | 15+ subsystems, IsoHeap OFF confirmed |
| Device fingerprinting | **DONE** | V399, V520, V521, V580, V583 |
| CVE triage (2023-2026) | **DONE** | 39+ CVEs dead, only CVE-43720 alive |
| UAF trigger | **DONE** | bitmaprenderer outer + defineProperty + 2d inner |
| Same-type reclaim | **DONE** | 500x Canvas2D spray, V573 confirmed |
| Bidirectional R/W via alias | **DONE** | All 12 Canvas2D APIs, V562/V630 |
| Crash oracle | **DONE** | Forge m_stateStack, lineWidth reads 8B at target |
| Heap topology mapping | **DONE** | V650-V655 binary subdivision, ~187KB resolution |
| DAZ bypass | **DONE** | BigUint64Array confirmed for raw pointer handling |
| Info leak / ASLR defeat | **IN PROGRESS** | V704/V705 confirm a bounded APNG process disclosure; chosen-address read and module-base identification remain open |
| Arbitrary R/W | Designed | lineDash Vector forge, needs info leak |
| Code execution | Not started | vtable hijack or Config overwrite |
| Kernel exploit | BLOCKED | Needs browser code execution first |
| Privilege escalation | Not started | |

## What We Know About the Target

- Firmware 14.10, WebKit-1400 era (Safari 17.0 / AppleWebKit 605.1.15)
- LLInt-only execution (JIT disabled)
- FreeBSD r230171, AMD Zen 2, 16KB pages
- Gigacage disabled (AB shares heap with JSC objects)
- IsoHeap OFF (WTF_MAKE_ISO_ALLOCATED = FastMalloc)
- JSC Config unfrozen (startOfStructureHeap writable)
- MADV_FREE keeps virtual mappings after free
- ~1200MB usable memory before OOM kill
- DAZ ON (denormals flush to zero in float64 channels)
- All Relapse CVEs patched
- All WSA-2026-0003/0004 CVEs dead

## Probe Count

150+ probes across 23 sessions.
