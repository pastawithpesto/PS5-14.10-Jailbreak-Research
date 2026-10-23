# Independent evidence review: PS5 firmware 14.10

**Review date:** 2026-10-21  
**Scope:** Review of saved research records, public source references, and firmware-free toolkit tests. No console was contacted and no exploit was run.

## Summary

This review did not independently verify kernel access, a firmware 14.10 vulnerability, or a complete jailbreak. Public and source-level leads should remain hypotheses until the relevant code is tied to the shipped build and independently reproduced in an appropriate test environment.

## Evidence assessment

- **WebKit:** The upstream advisory, fix, and regression test for CVE-2026-43715 are real. A bounded review of selected files from Sony's `WebKit_1400` source publication found older code without safeguards added by that fix. These source files are not mapped to the production 14.10 browser binary. The public report's device confirmation is still pending, so this does not establish a 14.10 vulnerability.
- **TransformStream:** The selected Sony-published source contains validation checks relevant to a public claim that those checks are absent. The exact production build remains unidentified; the claim should not be treated as confirmed from this source comparison.
- **JavaScriptCore:** An upstream hardening change and related arithmetic pattern were reviewed. Synthetic arithmetic checks are not evidence of memory corruption, and no PS5 build correspondence was established.
- **FreeBSD kernel advisories:** The upstream advisories establish defects in their named FreeBSD products and versions. No evidence in this review maps those affected code paths or configurations to the PS5 14.10 kernel.
- **Community reports:** Results attributed to public projects remain author-reported unless independently reproduced. Offsets, feature observations, or browser crashes alone do not establish kernel access.

## Tests

The local firmware-free research toolkit suite passed **51 tests** on CPython 3.12.10. These tests use synthetic fixtures and validate the toolkit; they do not exercise Sony code or PS5 firmware. No sanitizer reproduction of the upstream WebKit issue was performed in this review.

## Security boundary status

The evidence reviewed shows ordinary browser-to-bridge communication and source-level observations. It does not show a browser sandbox escape, privileged service compromise, kernel read/write, or unrestricted user-controlled execution. The status of the corresponding production 14.10 components remains unknown where no binary mapping is available.

## Practical defensive steps

- Keep the console on Sony's current supported firmware and install security updates.
- Treat browser feature observations and public exploit claims as leads, not proof of a security boundary failure.
- For vendor-side remediation, map the shipped component revisions and build configuration, then apply and regression-test the relevant upstream fixes.
- Keep any future component reproductions isolated on a PC and report their exact source revision and build settings; do not describe them as console results.

## References

- [Sony PS5 WebKit source listing](https://www.playstation.com/en-us/oss/ps5/webkit/)
- [WebKitGTK/WPE advisory WSA-2026-0004](https://webkitgtk.org/security/WSA-2026-0004.html)
- [Upstream WebKit fix and regression test](https://github.com/WebKit/WebKit/commit/5aedb82710ba578f61501106e78f6b25b7f7a558)
- [WebKit follow-up change](https://github.com/WebKit/WebKit/commit/f1fff08a99d77bac49c2500ece3fdcfac06c8f1c)
- [FreeBSD SA-24:14 UMTX advisory](https://lists.freebsd.org/archives/freebsd-security-notifications/2024-September/000049.html)
