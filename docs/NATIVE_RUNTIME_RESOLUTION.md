# Native validation and runtime license resolution

Review date: 2026-11-04. **DISTRIBUTION READINESS: FAIL.** Native functional
checks passed; redistribution clearance remains **NOT VERIFIED**. This review
supersedes the release decision in [the previous distribution review](DISTRIBUTION_VERIFICATION.md).
No public release, tag or PyPI upload occurred. Final Release Candidate Acceptance
has not started.

## Source identity and native results

- Product: `eb9714ea571cefc93acae18d6f27956dbc2c02ff`.
- CI branch: `ci/windows-system-ucrt-20261103`.
- Workflow revision: `b1894bce5d72595565551c588a8c6610e5da4ce1`; its only change
  after the product commit is the native workflow's matrix selection.
- `main` and `origin/main` remain `db23dd52fab34a15346df05f69c6b289ef4b680c`.
- [Windows-first run 41652490320](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41652490320).
- [Four-platform run 41654330827](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41654330827).
- [Quality run 41652557258](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41652557258).

The native runs explicitly checked out the product SHA. Quality checked out the
workflow revision; the source, tests and packaging code are identical between
those two commits. The uncommitted libuuid notice correction described below is
**not present in these native artifacts**.

| Platform / runner | Functional | Runtime provenance | License compliance | Result |
| --- | --- | --- | --- | --- |
| Windows x86-64 / `windows-2022` | PASS | Bundled native-file correspondence PASS; complete component clearance not established | NOT VERIFIED | FAIL |
| Linux x86-64 / `ubuntu-24.04` | PASS | PBS/wheel correspondence PASS; compiler-helper supplier NOT VERIFIED | NOT VERIFIED | FAIL |
| macOS Intel / `macos-15-intel` | PASS | PBS/wheel correspondence PASS, with Mach-O transformation limits | NOT VERIFIED | FAIL |
| macOS Apple Silicon / `macos-15` | PASS | PBS/wheel correspondence PASS, with Mach-O transformation limits | NOT VERIFIED | FAIL |

Each four-platform job passed **296 tests, 0 skipped, 0 failures, 0 errors**.
The Windows-first run also passed 296 tests. All jobs reached the fail-closed
license gate after successful builds and runtime checks; workflow failure does
not mean that the binary failed to load.

Native executable and installed-wheel smoke results cover help, benign and inert
malicious scans, partial/failed scans, JSON/SARIF exports and synthetic installed-agent
roots. Expected exit codes were 0/1/3, with usage errors returning 2. `--version`
remains unsupported and returned 2. Windows exports passed ACL checks; Unix
exports had mode `0600`. Audit records show zero blocked events and 13 self-checks
per platform. These Python audit tripwires are not an OS sandbox or a binary network trace.

**TUI boundary:** installed-wheel headless regressions passed on native runners.
The workflow does not demonstrate an interactive TUI launch from the frozen
executable or manual native-terminal visual acceptance. Those remain NOT VERIFIED.
Windows 10/11 and Server 2016+ are the selected support baseline, but this run
exercised Server 2022 only; it is not proof of every supported OS version.

## Windows system UCRT result

The before/after native inventory changed from **66 to 23 entries**, excluding
the outer PyInstaller bootloader. The removed set exactly matches the reviewed
43-file allowlist: `ucrtbase.dll`, 13 `api-ms-win-crt-*` files and 29
`api-ms-win-core-*` files. No prefix-wide Microsoft DLL exclusion was applied.

The remaining 23 entries match the previously inspected native payloads byte for
byte: 22 from the verified PBS archive and one from the locked PyYAML wheel.
`python312.dll`, `libffi-8.dll`, OpenSSL DLLs, `vcruntime140.dll` and
`vcruntime140_1.dll` remain bundled. Both VCRUNTIME files retain version
`14.44.35211.0` and their previously recorded hashes.

Isolated native CLI execution and scan/export tests succeeded without observed
missing-DLL errors. The package now relies on Windows for the removed UCRT/API
sets. No dynamic `LoadLibrary` trace or exhaustive dependency-path claim is made.

The previous four-file SDK REDIST discrepancy no longer blocks redistribution of
these candidates because none of those SDK files is shipped. **VCRUNTIME publisher
entitlement and satisfaction of redistribution conditions remain NOT VERIFIED**;
PBS byte identity and hosted-runner availability do not establish the publisher's
rights. The applicable Microsoft sources and the retained VCRUNTIME hashes remain
in [the previous rights review](DISTRIBUTION_VERIFICATION.md#applicable-microsoft-conditions).

## Unix libuuid: confirmed inclusion

The reviewed runtime is CPython **3.12.12 / PBS 20260211**. Independent inspection
matched libuuid **1.0.3** source SHA-256
`46af3275291091009ad7f1b899de3d0cea0252737550e7919d17237997db5644`
to the PBS download pin. The recipe disables shared-library construction.[3][4]

The evidence combines the source archive, `Makefile.am`, PBS build metadata,
`libuuid.a` object definitions/references, defined text symbols in the distributed
libpython, and actual calls between UUID generation and `random_get_bytes`.
It is not a symbol-name-only inference. Examples from the independent disassembly:

| Platform | `random_get_fd` | `random_get_bytes` | Example caller instruction address |
| --- | --- | --- | --- |
| Linux x86-64 | `0xb8d430` | `0xb8d500` | `0xb8d258` calls `0xb8d500` |
| macOS arm64 | `0x780360` | `0x780440` | `0x7806ac` branches to `0x780440` |
| macOS x86-64 | `0x880aa0` | `0x880b70` | `0x881228` calls `0x880b70` |

The new candidates retain the inspected libpython code: Linux matches the prior
library bytes; macOS comparisons preserve the body between load commands and
code signature, with zero excluded padding. Complete Mach-O identity is not
claimed when signing/header transformations differ.

`randutils.c` grants redistribution under the **GNU Lesser General Public
License without specifying a version**. The archive's top-level BSD notice does
not override that file-specific grant.[3] The three Unix distributions therefore
contain LGPL-covered code statically incorporated into libpython. Windows UUID
handling uses the OS `RPCRT4` path; this finding is not applied to Windows.

### Distribution obligations and unresolved compliance route

LGPL-2.1 section 13 allows choosing a published LGPL version where the library
specifies none. Lack of a version number does not itself make compliance
impossible. A distributor still needs to choose and satisfy a route.[6]

For an LGPL-2.1 route, the actual combination requires review against sections
1–4, 6 and, where applicable, section 7's combined-library conditions:[6]

- Preserve applicable copyright/license notices and provide the LGPL text and
  prominent notice of library use. Preserve the BSD notices of other libuuid files.
- Permit customer modification for their own use and reverse engineering for
  debugging those modifications under section 6.
- Section 6(a) requires the corresponding library sources, including changes,
  and the work's object/source and reproduction materials needed to modify and
  relink it. A generic upstream URL or the mere existence of `libuuid.a` is not
  evidence that the delivered material meets this requirement.
- Section 6(b)'s suitable shared-library mechanism is not established merely
  because libpython is a `.so` or `.dylib`: it already contains the libuuid code.
- A section 6(c) written offer must last at least three years and cover the
  section 6(a) materials. An offer is an alternative route, not a compulsory
  addition to a correctly fulfilled direct-material route.
- Section 6(d) permits equivalent access to the required materials from the same
  designated distribution place; section 6(e) depends on verified prior receipt.
  Section 7 also addresses the accompanying uncombined library work and notice.

**No complete corresponding-source/object/relink package, qualifying offer or
alternative route has been verified for this distribution.** This does not prove
that such material exists nowhere, or that all Dragons source must be GPL.
The review does not grant legal clearance.

The smallest supported next step is to assemble exact source, PBS patches,
configuration and necessary relinking materials for the existing runtime,
demonstrate replacement/relinking, then review the chosen distribution route.
This avoids removing working runtime components. Removing libuuid or switching
runtime suppliers would require a separate build, dependency/license review and
native regression validation; neither was attempted here.

### Applied local notice correction

`scripts/standalone_licenses.py` now preserves the authentic leading notices from
`gen_uuid.c` and `randutils.c`, plus a hash-pinned complete LGPL-2.1 text. The
`gen_uuid.c` notice includes the previously missing 1998/1999 copyright years.
The integration applies only to Unix CPython 3.12.12 / PBS 20260211.

The LGPL text comes from the GNU GCC source repository, SHA-256
`a9bdde5616ecdd1e980b44f360600ee8783b1f99b8cc83a2beb163a0a390e861`.[6]
That hosting location **does not identify the compiler runtime used by PBS**.
The collector keeps an explicit unresolved source/relink obligation even when all
notice files are available. Missing/corrupt inputs fail closed. Tests use inert
offline fixtures, not downloaded executable code.

This correction remains uncommitted for review. The current native candidates
still lack these libuuid additions, and adding them will not by itself clear LGPL
compliance.

## Linux compiler helpers

The inspected ELF contains defined `__udivti3` (267 bytes) and `__umodti3`
(297 bytes). The `.comment` section contains GCC 15.2.0, Clang 21.1.4 and Debian
GCC 4.8.4 markers. The CPython build records Clang, but these facts do not establish
which archive supplied either function. The stripped binary lacks useful STT_FILE
provenance for this purpose.

**Exact supplying archive, helper version, applicable license and exception:
NOT VERIFIED.** No GCC Runtime Library Exception or LLVM exception is assumed.
The minimum next evidence is the original link map/supplying archive, or a
validated object-member comparison tied to the exact build. macOS references to
similar helpers do not establish the same static inclusion.

## License inventory

The inventory distinguishes physical inclusion, recipe candidates and OS
libraries. The source basis is the verified PBS archives/build metadata, locked
wheels, the independent libuuid analysis above, and retained upstream notice
comparisons. `PASS (notice)` below covers the inspected text obligation only;
it does not certify complete source-level legal coverage.

### Application and packaged Python dependencies

All four candidates include these components. Sources are the exact source
commit or locked upstream wheels; the package notice files match the prior
upstream-verified collection byte for byte. Package metadata alone was not used
as proof of complete native-component coverage.

| Component | Version | License / required retained material | Current notice status |
| --- | --- | --- | --- |
| Dragons AI Agent Scanner | 0.1.0 / product SHA above | MIT copyright and permission text | PASS |
| Click | 8.5.0 | BSD-3-Clause notice/conditions/disclaimer; no endorsement | PASS |
| markdown-it-py | 4.2.0 | MIT and incorporated upstream attribution | PASS |
| mdurl | 0.1.2 | MIT notices | PASS |
| linkify-it-py | 2.2.0 | MIT notices | PASS |
| PyYAML | 6.0.3 | MIT notices; separate LibYAML accounting below | PASS |
| Pygments | 2.21.0 | BSD-2-Clause notice/conditions/disclaimer | PASS |
| platformdirs | 4.13.5 | MIT notices | PASS |
| Rich | 15.0.0 | MIT notices | PASS |
| Textual | 8.2.8 | MIT notices | PASS |
| typing_extensions | 4.16.0 | PSF/historical license collection | PASS |
| PyInstaller bootloader | 6.16.0 | GPL-2.0-or-later with bootloader exception; preserve its license/exception | PASS (text); exception does not clear application dependencies |

### Runtime components and platform differences

`U` means all three Unix candidates; `A` means all four candidates. Versions
below describe the retained earlier binary/build mapping, not versions inferred
from filenames. Original source references and byte comparisons are retained in
the evidence collection. The review does not certify uninspected source headers.

| Component | Bundled version / platform | Source basis | License and principal obligation | Status / remaining boundary |
| --- | --- | --- | --- | --- |
| CPython | 3.12.12 / A | PBS 20260211; upstream CPython | Composite PSF/historical notices and relevant change notices | Original texts PASS; embedded components need separate review |
| OpenSSL | 3.5.5 / A | PBS/native version evidence; actual Windows `-3-x64` imports | Apache-2.0 license and applicable attribution/NOTICE | License text PASS; full applicable attribution coverage not certified |
| libffi | 3.4.6 + PBS patches / U; 3.4.2 / Windows | PBS targets; Windows source-deps `16fad4855b3d8c03b5910e405ff3a04395b39a98` | MIT copyright/permission text | Reviewed version-specific supplements present and verified |
| mpdecimal | 4.0.0 / U; 2.5.1 / Windows | PBS pin; CPython vendored Windows source | BSD-2-Clause notices/conditions/disclaimer | Unix 2008–2024 supplement now present; Windows 2008–2020 notice retained |
| ncurses/panel | 6.5.20240427 / Linux | PBS static link/source | X11/MIT-style notice and no endorsement | Reviewed 2024 notice now present; macOS uses OS libraries, not bundled copies |
| bzip2 | 1.0.8 / A | PBS/native version evidence | bzip2 terms: preserve source notices, mark changes, do not misrepresent origin | Candidate text is older; not by itself a proven mandatory binary-notice violation |
| Expat | 2.6.3 / U; 2.7.3 / Windows | PBS pin; vendored Windows source/native marker | MIT notice retention | Windows vendored notice match established; no blanket all-source clearance |
| liblzma | 5.8.1 / A | PBS/XZ recipe and native evidence | 0BSD for linked library; no mandatory attribution/source offer | Do not transfer XZ tool licenses to liblzma |
| SQLite | 3.50.4 / U | Defined functions and PBS download 3500400 | Public-domain dedication | Included in Unix libpython despite no application import; not bundled on Windows |
| libedit | 20240808-3.1 / Linux | PBS static link/source | BSD-3-Clause notices and no endorsement | Reviewed top-level notice match; macOS uses OS libedit |
| zlib | 1.3.1 / Linux and Windows | PBS/native version evidence | zlib source-notice/origin/change conditions | Older candidate notice is a fidelity issue, not a mandatory binary-acknowledgment violation; macOS uses OS libz |
| libuuid BSD portions | 1.0.3 / U | Pinned archive + objects/calls | BSD-3-Clause notices/conditions/disclaimer | Native candidates miss gen_uuid.c's full copyright years; local correction not rebuilt |
| libuuid randutils.c | 1.0.3 / U | Pinned archive + objects/calls | Unversioned LGPL grant; chosen route must satisfy notice/source/relink conditions | NOT VERIFIED; native notice omission and unverified distribution route |
| HACL* / KaRaMeL | CPython 3.12.12 vendoring; HACL revision `bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0` / A | CPython headers and pinned upstream license | Source-specific MIT/Apache texts and attribution | Existing three-file correction retained; inspected notices PASS |
| LibYAML | 0.2.5 / A | Locked PyYAML native extension and upstream static-build pin | MIT copyright/permission text | Original notice PASS |
| Compiler arithmetic helpers | Exact supplier/version unknown / Linux | ELF definitions/disassembly; mixed compiler markers | License/exception cannot yet be selected | NOT VERIFIED |
| VCRUNTIME140 / 140_1 | 14.44.35211.0 / Windows | Byte match with verified PBS archive | Microsoft redistribution entitlement and conditions | Provenance PASS; publisher rights NOT VERIFIED |
| UCRT / 42 API-set files | Not bundled / Windows | Exact inventory subtraction | OS dependency; no redistribution of these 43 files by this candidate | Removal PASS; not an unresolved shipped-SDK license issue |

Candidate PBS notices for Berkeley DB, Tcl/Tk, Tix, X11/Xau/xcb, GNU readline,
OpenSSL 1.1, libffi 3.3, zlib-ng and zstd do not prove inclusion. Earlier
module/link inspections exclude these from the reviewed candidates; the current
native payload continuity does not change that conclusion. Candidate source
versions must not be reported as installed versions. OS-provided macOS libedit,
ncurses/panel and libz ABI filenames likewise do not establish exact upstream
source versions. OS dependencies are outside the bundled-file inventory.

### Notice and integrity verification

The current sidecars contain 42 files on Linux, 41 on each macOS platform and
40 on Windows. On each platform, 38 retained upstream notice files match the
previously reviewed collection; generated inventory text is separate. The new
libffi/mpdecimal/ncurses supplements match the pinned source and reviewed notice
bytes. SHA-256 verification passed for every sidecar file, binary and manifest,
including all 44/43/43/42 entries in the respective checksum lists.

| Executable suffix (prefix `dragonscan-0.1.0-`) | Four-platform run SHA-256 |
| --- | --- |
| `linux-x86_64` | `43e63dffaec4932ebbadb5ef3fd75d5c5bbac32acae9b0ca90ced1d213f11de3` |
| `macos-arm64` | `505cbb763fba1cc3f6f43a2b4f1cd40f34151bfb52e29a107d756ae9120fb8cb` |
| `macos-x86_64` | `b0f3084a0ae695fadb925e807284d13ae03b661edec955b2c09e965be88708d1` |
| `windows-x86_64.exe` | `96d377bd7a1d4a3f4385065c89a68cbde1f0691516a8d6572b24e2d10b58bbb4` |

The Windows-first executable is also retained, SHA-256
`177a686b3d9183060330c4d0fcef76b03bb5a32212609a2d65e9461ce55c9394`.
Separate builds have separate hashes; source identity is not a reproducible-build claim.

## Quality, repository and retention

- Hosted full suite: **1941 passed, 1 skipped** at the workflow revision. That
  skipped test is not counted as passed. Hosted Ruff and mypy gates passed.
- Local notice/packaging regression selection after the final code correction:
  **78 passed, 2 deselected**. The two omitted tests are the subprocess-based
  sdist/installed-wheel tests; this selection is not a full-suite claim.
- Local Ruff format check: **377 files already formatted**; Ruff lint passed;
  mypy checked **71 source/script files**; `git diff --check` passed.
- Registry remains **48 finding IDs**. Frozen Phase 2 v2 remeasurement is
  **8 TP / 0 FP / 0 FN**. Phase 6 v2 is **21 TP / 0 FP / 3 FN**; its occurrence
  correctness check still fails for those three known misses. Ground truth and
  detection logic were not changed.
- Only the authorized packaging commit and workflow-only correction were pushed
  to the CI branch. New notice/test/report changes remain uncommitted. Unrelated
  user edits, private semantic results and unfinished experiments were preserved.
  Private results and user agent configurations were not read.

Local retained evidence is outside Git and automatically pruned scratch storage:
`~/Dragons-validation-evidence/eb9714e/`. It includes both native runs' binaries,
checksums, sidecars, summaries, JUnit and command/audit logs, plus independent
UUID/disassembly, integrity, byte-continuity and benchmark evidence. The copied
native evidence files were hash-checked. Hosted artifacts have seven-day retention.

## Remaining release blockers and smallest next actions

1. **Unix libuuid notices:** review/commit the scoped local correction, then
   rebuild and inspect new sidecars. Do not mark the existing candidates fixed.
2. **Unix LGPL distribution route:** assemble exact source/patch/relink material,
   demonstrate the route, and review its legal conditions before distribution.
3. **Linux compiler helpers:** obtain the exact link map/archive or validated
   supplying object evidence; apply its real license and exception only then.
4. **Windows VCRUNTIME:** establish publisher entitlement and compliance with the
   applicable Microsoft distribution conditions. Do not remove required DLLs.
5. **Complete runtime clearance:** finish the remaining source-level attribution
   and component mapping; conservative candidate notices are not approval.
6. **Acceptance coverage:** frozen-executable interactive TUI and manual terminal
   acceptance remain unverified; the other supported Windows releases were not
   exercised. Record these as future acceptance work, not as passed checks here.

**DISTRIBUTION READINESS: FAIL.** Functional/integrity evidence is positive;
unresolved redistribution obligations prevent release. No release authorization
or next-milestone execution follows from this report.

## Sources

[3] https://sourceforge.net/projects/libuuid/files/libuuid-1.0.3.tar.gz
[4] https://github.com/astral-sh/python-build-standalone/blob/20260211/cpython-unix/build-uuid.sh
[6] https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-15.2.0/COPYING.LIB
