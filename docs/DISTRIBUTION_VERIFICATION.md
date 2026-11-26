# Standalone distribution verification — 2026-11-03

Historical review of the `db23dd5` candidates. The
[native runtime resolution](NATIVE_RUNTIME_RESOLUTION.md) supersedes its current
release decision with the `eb9714e` system-UCRT candidates, confirmed Unix
libuuid/LGPL inclusion, and the remaining redistribution blockers. Statements
below describe the earlier review, not clearance of the newer artifacts.

**DISTRIBUTION COMPLIANCE: NOT VERIFIED.** No artifact is cleared for public
release by this review. The native workflow's release gate is **FAIL**, not a
build or runtime-test failure. No release, tag, PyPI upload, commit or push was
performed for this verification.

## Exact source and native evidence

Source: `db23dd52fab34a15346df05f69c6b289ef4b680c` (`main` and `origin/main`).
Existing working-tree changes were excluded from builds and preserved.

- [Native no-publish run 41639930696](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41639930696): all four jobs failed at the license gate after successful builds, installed-wheel tests and native smoke checks.
- [Quality run 41633596439](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41633596439): **1928 passed, 1 skipped**, same source commit.
- Each native artifact includes `summary.json`, `tests.xml`, `audit.json`,
  `commands.json`, command logs, `SHA256SUMS`, the executable and its adjacent
  `.licenses/manifest.json`. Workflow artifacts have seven-day retention; the
  identifiers and binary hashes below identify the reviewed candidates, not a
  permanent download service.

| Platform / native runner | Build | Runtime | Licenses | Integrity | Result |
| --- | --- | --- | --- | --- | --- |
| Linux x86-64 / `ubuntu-24.04` | PASS | PASS | NOT VERIFIED | PASS | NOT VERIFIED |
| Windows x86-64 / `windows-2022` | PASS | PASS | NOT VERIFIED | PASS | NOT VERIFIED |
| macOS Intel / `macos-15-intel` | PASS | PASS | NOT VERIFIED | PASS | NOT VERIFIED |
| macOS Apple Silicon / `macos-15` | PASS | PASS | NOT VERIFIED | PASS | NOT VERIFIED |

Each runner passed **283 tests, 0 skipped, 0 failed, 0 errors**. Native checks
covered `--help`, inert clean/finding/partial/failed scans, usage errors, JSON and
SARIF exports, and synthetic installed-agent roots. The unsupported `--version`
option correctly returned usage exit code 2; it is not a supported version API.
Expected scan exit codes were 0/1/3 and usage exit code 2. Export permission
checks passed on each platform. Synthetic roots were used, not user installations.
Python audit tripwires recorded no blocked events; these are not an OS sandbox
or a native-code network trace. Manual terminal visual acceptance is not claimed.

Architecture headers matched their platforms. Independent checksum verification
covered each listed artifact and notice file, with binary hashes also matching
both summary and license manifest. Packaging and inventory privacy checks passed
within their implemented scope; they are not an exhaustive secret-content proof.

| Executable suffix (prefix `dragonscan-0.1.0-`) | SHA-256 |
| --- | --- |
| `linux-x86_64` | `3388bb46e85cfb43e2af45818480b0836b4da4a5212ca729c0da7d5fa2e798cd` |
| `windows-x86_64.exe` | `70b2219f46d1bcb9528a2ff3fe379c44257c4ae040f14f6752877f5215d9245a` |
| `macos-x86_64` | `6203aad2fd220d2f2aeb6bb8a92bcb32d05a6cc3f7da58fb6a5857234a392a0a` |
| `macos-arm64` | `a8d315fe003de08f04862f8466358b27858bb5f22e5e9926c05d62757c52152a` |

## Windows runtime: provenance versus permission

CPython is **3.12.12**, from **Python Build Standalone 20260211**. The executable
contains **66 native archive entries**; this count excludes its outer PyInstaller
bootloader. Every entry has a source-byte match:

- **22** entries match the digest-verified PBS Windows
  `install_only_stripped` archive, including `python312.dll`, selected CPython
  extensions, `libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `libffi-8.dll` and both
  VCRUNTIME DLLs. PBS archive SHA-256:
  `93bf8e8c05ede0077b197a29c99ebdaf253497f27190097494265150b4e70ba8`.
- **43** entries (`ucrtbase.dll` and 42 API-set DLLs) match the x64 UCRT files
  in the official [Microsoft.Windows.SDK.CPP 10.0.26100.1742 package](https://www.nuget.org/packages/Microsoft.Windows.SDK.CPP/10.0.26100.1742),
  under `c/Redist/10.0.26100.0/ucrt/DLLs/x64/`.
  [Exact package](https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.26100.1742/microsoft.windows.sdk.cpp.10.0.26100.1742.nupkg)
  SHA-256: `cea18bcdb33096a94e441a8fdf2db138e356b020a1b5f27d6ddfea1bcec48eb2`.
  This establishes a trustworthy source correspondence, not the runner's exact
  copy history, a reproducible source build, or a redistribution grant.
- **1** PyYAML extension matches the exact locked PyYAML 6.0.3 Windows wheel.

| Bundled component | Observed version | SHA-256 |
| --- | --- | --- |
| `VCRUNTIME140.dll` | `14.44.35211.0` | `d5e4d9a3e835fa679450145d6a7d94e36573a509317111904d9b3712c30d9066` |
| `VCRUNTIME140_1.dll` | `14.44.35211.0` | `1f2d41c4aa5db0bc33ebf7b66d72943a817d7ce6cbe880502a9403823633093f` |
| `ucrtbase.dll` | `10.0.26100.1742` | `2e5fb14b7bf8540278f3614a12f0226e56a7cc9e64b81cbd976c6fcf2f71cbfb` |

OpenSSL DLLs report file version `3.5.5.0`; libcrypto contains
`OpenSSL 3.5.5 27 Jan 2026`. The PBS metadata's stale `1_1` DLL names do not
identify these final bytes. `libffi-8.dll` has no PE file-version result in this
inspection; its ABI filename alone is not a verified upstream version.

Normal PE imports not bundled in the archive are `ADVAPI32`, `CRYPT32`,
`IPHLPAPI`, `KERNEL32`, `OLEAUT32`, `PROPSYS`, `RPCRT4`, `USER32`, `VERSION`,
`WS2_32`, `bcrypt`, `ole32` and `api-ms-win-core-path-l1-1-0` DLLs. These are
external Windows dependencies, not additional files distributed by Dragons.
The import inspection does not cover delay imports, forwarders or dynamic
`LoadLibrary` resolution. Although Windows 10+ supplies UCRT, this artifact also
ships a UCRT copy; OS availability does not erase its redistribution obligations.

### Applicable Microsoft conditions

Official sources accessed 2026-11-03:

1. [Visual C++ redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)
   limits distribution of the runtime package, merge modules and individual
   binaries to licensed Visual Studio users, subject to the applicable terms.
   The [Visual Studio 2022 REDIST list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution)
   lists VCRUNTIME files conditionally on a valid software license. A PBS hash
   match or the hosted runner's installed tools does not establish the publisher's
   own entitlement. **Publisher entitlement: NOT VERIFIED.**
2. The exact SDK NuGet metadata links to [Windows SDK license terms](https://aka.ms/WinSDKLicenseURL),
   resolving to [Microsoft's SDK license document](https://download.microsoft.com/download/0/F/F/0FF2B061-47DD-4F55-89B6-FD1D8C44F14D/sdk_license.rtf).
   Section 3 permits distribution of listed object code subject to its conditions,
   including significant primary functionality, downstream protections,
   indemnification, retention of notices, and platform/other restrictions.
   A license-text copy alone does not demonstrate satisfaction of those conditions.
3. The SDK's linked [REDIST list](https://learn.microsoft.com/en-us/legal/windows-sdk/redist)
   expressly lists `ucrtbase.dll` and many API-set DLLs, but does not name four
   files found in this SDK package and the actual executable:
   `api-ms-win-core-fibers-l1-1-0.dll`, `api-ms-win-core-fibers-l1-1-1.dll`,
   `api-ms-win-core-kernel32-legacy-l1-1-1.dll`, and
   `api-ms-win-core-sysinfo-l1-2-0.dll`. This is an unresolved coverage discrepancy,
   not proof that redistribution is prohibited. Their presence in a `Redist`
   directory is not substituted for the legal grant.
4. [Universal CRT deployment guidance](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment?view=msvc-170)
   documents system UCRT availability and restricted local deployment. It is not
   an unconditional replacement for the SDK license or its REDIST list.

**VCRUNTIME/UCRT redistribution clearance: NOT VERIFIED.** No verified Microsoft
rights are inferred from binary identity, MIT licensing of Dragons, or PBS's
ability to publish its own runtime. No invented Microsoft notice was added.

## Notices and other platforms

Each artifact contains 36 component records and 39 notice/license files.
Integrity checks passed. Original source comparisons additionally confirmed:

- Dragons' MIT text against the exact source commit (Windows has CRLF rather
  than LF, with identical normalized text), and CPython's original license
  against each platform's PBS archive.
- **13 package/bootloader notice files per platform** against the exact locked
  wheel sources: PyYAML 6.0.3, Pygments 2.21.0, Click 8.5.0, linkify-it-py 2.2.0,
  markdown-it-py 4.2.0, mdurl 0.1.2, platformdirs 4.13.5, Rich 15.0.0,
  Textual 8.2.8, typing_extensions 4.16.0 and PyInstaller 6.16.0.
- **23 additional runtime/vendor notice files per platform** against pinned
  sources, including CPython additional notices, HACL* MIT, KaRaMeL attribution
  and Apache 2.0 text, PBS candidate library notices and LibYAML 0.2.5.
  Source URLs and hashes for the embedded cryptography notices are in
  [the runtime review](RUNTIME_LICENSE_REVIEW.md#embedded-cryptography-notices).
- The remaining manifest text is generated inventory information, not another
  independent upstream license. File counts are not a legal completeness proof.

The HACL*/KaRaMeL omission in the older `abe40c5` candidates is **resolved in
these newly built artifacts**. No additional definite missing or mismatched
upstream notice was established in the inspected collection. This is not a claim
that all statically linked code has been mapped to its obligations.

Linux's `libpython3.12.so.1.0` is byte-identical to the verified PBS stripped
archive. Both macOS libpython bodies match between load commands and code
signature, with zero excluded padding and signature/header-related changes;
complete Mach-O file hashes are not equal. PyYAML matches the locked wheels
exactly on Linux and Windows, and by the same body/signature comparison on both
macOS architectures. The matching libraries contain OpenSSL 3.5.5 evidence.

CPython's [license collection](https://docs.python.org/3.12/license.html) and the
[versioned PBS distribution specification](https://raw.githubusercontent.com/astral-sh/python-build-standalone/20260211/docs/distributions.rst)
do not grant blanket rights to every bundled third party. PyInstaller's
[bootloader exception](https://pyinstaller.org/en/stable/license.html) permits
shipping a generated application under its own license, subject to the
application's dependencies; the pinned 6.16.0 license files were checked, rather
than substituting current documentation for the shipped texts.

The sidecars still label 17 vendor-license records as candidate libraries with
unconfirmed inclusion. Their presence does not prove that Berkeley DB, Tcl/Tk,
X11 or every other candidate is actually bundled. Exact per-build static-component
versions, inclusion and obligation mapping are not fully closed by this review.
Do not assert a source/relinking violation merely because a candidate license is
present. **Complete runtime license coverage on all four platforms: NOT VERIFIED.**

## Quality and changes

The isolated exact-source verification passed **938 safe-static tests**, including
**37 packaging/license tests**, with zero blocked audit events. This is a scoped
selection, not another full-suite result. Ruff formatting/lint passed; mypy
checked source and scripts separately. The full-suite claim above belongs only
to the recorded GitHub quality run.

The deterministic finding registry remains **48 IDs**. Frozen Phase 2 v2 results
remain **8 TP / 0 FP / 0 FN**; Phase 6 v2 remains **21 TP / 0 FP / 3 FN**. Ground
truth was not changed and the three existing false negatives are not resolved.

Only this verification record and the historical runtime review were changed
for this task, left uncommitted. No packaging correction was justified by a
newly confirmed missing notice; runtime collection and fail-closed license gates
were left unchanged. Existing user changes and private results were preserved;
private agent configurations and semantic results were not read.

## Remaining blockers and decision

1. Establish the publisher's applicable Microsoft entitlement and satisfaction
   of distribution conditions; resolve the four-file SDK REDIST discrepancy.
2. Finish exact bundled/static component-to-version-to-notice/obligation mapping
   rather than treating the conservative PBS candidate collection as clearance.

**DISTRIBUTION COMPLIANCE: NOT VERIFIED.** Runtime and integrity evidence is
positive, but it does not establish complete redistribution rights. Public
release remains blocked. Final Cross-Platform Acceptance & First Public Release
Preparation was not started.
