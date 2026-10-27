# Gap Analysis: Devon's Chain Map vs Actual State

**Date:** 2026-10-23 · **Ref:** Issue #18 (Devon, 14:17 UTC)

---

## 1. What Devon Is Missing

- **[7] Info leak — SUPERSEDED.** Devon is still working V667 fetch-spray.
  We already have V674/V695 APNG overread confirmed on device: 900+ heap
  ptrs, 200+ code ptrs per run, zero UAF involvement. Devon doesn't know
  [7] is solved.

- **[8] .text base — DESIGNED, Devon hasn't started.** JSFunction+24 →
  NativeExecutable+40 → m_function gives a .text pointer. Backward-walk
  by 0x4000 scanning for ELF magic (0x7f454c46) locates the base without
  per-firmware offset tables. Devon's map lists this as "NEXT" with no
  technique attached.

- **[9] Arb R/W — DESIGNED, Devon hasn't started.** Option D is fully
  specified: AB(768) reclaim → forge m_stateStack → lineWidth read
  primitive → corrupt Float64Array.m_vector+16 and m_length+24. Plus
  addrof via butterfly harvest, StructureID harvest via `{x:0.0}`, fake
  object arb R/W. Devon's map lists this as "NEXT" with no technique.

- **[10] Code exec — SUPERSEDED.** Devon assumes ROP. We confirmed
  `thr_create(430)` on external research 156c/156d: ucontext_t sets RIP, RSP, and
  all GPRs directly. ROP chain construction is unnecessary.

- **[11] Sandbox escape — NOT A SEPARATE STEP.** Devon lists this as
  "HARD (weeks-to-months)." WebContent process can make syscalls
  directly; there is no sandbox boundary to cross. Devon is planning
  work that doesn't need to happen.

- **[13] HV bypass — LIKELY UNNECESSARY.** Devon lists this as "HARD."
  ucred patch + `jitshm_create` gives exec memory without touching the
  hypervisor. Devon is budgeting months for a step we may skip entirely.

- **[12] Kernel — Devon has no technique.** We have 7 candidates ranked,
  with IPv6 multicast UAF at top and a K-R/W technique documented.
  Devon's map just says "HARD" with no specifics.

## 2. Is V667 Obsoleted?

**Yes.** V667 (fetch-spray stale-pointer reclaim) is strictly inferior to
V674/V695 APNG overread on every axis:

| | V667 fetch-spray | V674/V695 APNG overread |
|---|---|---|
| Mechanism | Reclaim freed stateStack with fetch AB, read stale ptrs | Malformed APNG triggers OOB read in decoder |
| Data per trigger | Unknown (race-dependent) | 49 KB of raw heap per trigger |
| Requires UAF race | Yes — slow endpoint + tight timing window | No — deterministic, single-shot |
| Size class match | Required (must hit exact freed slot) | Not required |
| Network dependency | Yes (needs controllable slow endpoint) | No (local PNG blob) |
| Confirmed on device | No | Yes — 1651 ptrs (900+ heap, 200+ code) |

V667 should be abandoned. No reason to carry race-window risk when a
deterministic, higher-yield alternative is confirmed.

## 3. Devon Insights Worth Adopting

- **fillStyle color-read channel.** Devon prepped a purifyNaN bypass
  using fillStyle color reads as a side channel. This is a different
  data-extraction pathway from our lineWidth oracle. Worth examining —
  if it can read bytes that DAZ/purifyNaN would destroy in float64 form,
  it gives us a complementary read primitive for pointer bytes in
  denormal range.

- **vtable hijack write primitive.** Devon's "arbitrary write via vtable
  hijack" may be a useful fallback or alternative to our Option D
  Float64Array.m_vector corruption. If the vtable hijack can be reached
  from the alias without needing arb R/W first (bootstrap problem), it
  could simplify the chain.

- **vtable derivation code.** Devon has working code to walk from a
  leaked vtable pointer to class identity. Even if we use a different
  leak source, the derivation logic is reusable.

- **Post-leak chain integration.** Devon apparently has connected code
  for steps [8]→[9]→[10]. Even though the individual techniques differ
  from ours, the integration scaffolding (error recovery, retry logic,
  timing) may be worth reviewing.

## 4. Recommended Actions for Devon

1. **Share post-leak code immediately.** Request the fillStyle color-read
   channel, vtable derivation, and vtable hijack write code. These are
   the only pieces Devon has that we might not have equivalents for.

2. **Brief Devon on [7] being solved.** Send V674/V695 results so he
   stops spending time on V667. Include the APNG blob generator and
   pointer-classification output.

3. **Brief Devon on [10] thr_create.** The ROP chain he's presumably
   designing is unnecessary. Send the external 156c/156d confirmation so
   he can redirect that effort.

4. **Brief Devon on [11]/[13] elimination.** These are the biggest
   time-savers. He's budgeting weeks-to-months for steps that are
   either unnecessary or dramatically simpler than he thinks.

5. **Redirect Devon to kernel work.** With [7]–[10] either solved or
   designed, the real gap is [12] kernel exploit implementation. Devon
   should review the IPv6 multicast UAF candidate and start prototyping
   the K-R/W primitive, or help validate the other 6 candidates.

6. **Ask Devon to validate Option D.** Fresh eyes on the
   m_stateStack → Float64Array.m_vector corruption chain. Specifically:
   whether the StructureID harvest via `{x:0.0}` is reliable across
   GC cycles, and whether the fake-object technique survives
   conservative scanning.

---

**Bottom line:** Devon's map is 4–6 steps behind actual state. The chain
is shorter than he thinks ([11] and [13] collapse), and the hard parts
he's working on ([7]) are already solved. His most valuable contribution
right now is (a) sharing the fillStyle/vtable code and (b) pivoting to
kernel exploit work.
