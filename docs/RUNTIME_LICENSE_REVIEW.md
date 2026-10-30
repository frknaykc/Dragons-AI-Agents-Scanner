# Standalone runtime license review

This is a release-gate record, not a redistribution grant. Dragons' application
license remains MIT. A successful notice checksum check is not license clearance.

## Observed runtime and sources

The four-platform validation of `79651f67edbecef3356537b3dc053ef86d000a41`
used CPython 3.12.12; the interpreter's `BUILD` marker identifies PBS 20260211.
The [native validation run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41034072700)
passed 266 installed-wheel tests on each platform. Its license gate failed.
The marker identifies the claimed build, not a cryptographic match between the
installed interpreter, its transformed bundled library and an upstream archive.

Explicit provisioning downloads these original sources, without executing them:

| Source | SHA-256 |
| --- | --- |
| [CPython 3.12.12 additional notices](https://raw.githubusercontent.com/python/cpython/v3.12.12/Doc/license.rst) | `341832873fd316a37927e79385093fbbfd40a467428480835fe435a80cadf4e5` |
| [PBS 20260211 source archive](https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/refs/tags/20260211) | `a70d814140fb061d5724c477aeecfdf263e890d3a3515546763adc727f929628` |

Packaging copies CPython's installed `LICENSE.txt`, additional notices and the
PBS recipe's original license files byte-for-byte into the adjacent notice
directory. The recipe is parsed as data, never imported. Recipe versions describe
candidate components, not proof that every candidate is linked into the binary.
Missing sources, unreviewed cached URLs and changed bytes are not silently accepted.

## Independent upstream archive inspection

Four full archives from the [PBS 20260211 release](https://github.com/astral-sh/python-build-standalone/releases/tag/20260211)
were downloaded and matched against the release API's SHA-256 digests. Only
`python/PYTHON.json` and license metadata were read; no archived code was executed.
All use CPython version `3.12.12`, PBS release `20260211` and the filename pattern
`cpython-<version>+<release>-<variant>-full.tar.zst`:

| Variant | SHA-256 |
| --- | --- |
| `aarch64-apple-darwin-pgo+lto` | `bf70a8ba4d44eb243af9dc3485656e0ce3757588eefe27e1801b36ff9773805a` |
| `x86_64-apple-darwin-pgo+lto` | `14fe4f2213f9b89d5649b2c50636be20393ec0092960d1acd11f7c84a4e1b2e9` |
| `x86_64-unknown-linux-gnu-pgo+lto` | `75428635145d4eb8de86cff5d00a823009a21fe8c173c7899959d0f41f73ad4a` |
| `x86_64-pc-windows-msvc-pgo` | `6644ab07ff671724b4e71e4a70a8ae1719ed761fe5bed44b96785f2e653b9499` |

[The versioned PBS archive specification](https://github.com/astral-sh/python-build-standalone/blob/20260211/docs/distributions.rst)
describes `build_info`, linking requirements and extension license metadata.
The inspected metadata cannot be used as an exact final-binary component map:

- Unix `_ssl` metadata lists both OpenSSL 1.1 and OpenSSL 3 notice paths and license
  alternatives. The recipe's `openssl-3.5` version is 3.5.5; a recipe entry alone
  does not prove which code is present in a transformed PyInstaller library.
- Windows `_ssl` metadata refers to `libcrypto-1_1-x64.dll` and
  `libssl-1_1-x64.dll`, whereas the actual Dragons archive contains
  `libcrypto-3-x64.dll` and `libssl-3-x64.dll`. Do not silently rewrite that
  discrepancy into a verified mapping.
- The actual Windows archive also contains `VCRUNTIME140.dll`,
  `VCRUNTIME140_1.dll`, `ucrtbase.dll` and API-set DLLs. CPython's license is not
  a redistribution license for these Microsoft files.

## Remaining release blockers

1. Establish byte-level interpreter provenance and an exact linked-component /
   notice mapping, accounting for stripping, relocation and code signing. Resolve
   the upstream metadata discrepancies above and any component-specific attribution,
   source or relinking requirements. This review has not established an actual
   license violation; it has not established complete clearance either.
2. Record the exact Windows runtime DLL versions and origin, applicable Microsoft
   terms and the distributor's entitlement. [Microsoft's redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)
   limits distribution to licensed Visual Studio users under the relevant terms;
   the [2022 redistributable list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution)
   is conditional on a valid license. A hosted runner or a copied DLL filename
   does not establish that entitlement for Dragons' publisher.

Until these are resolved, retain `unresolved_obligations` and report release
acceptance **FAIL**. Do not substitute a generic license text, remove a failing
gate, or treat the candidate notice collection as complete runtime compliance.
Manual native-terminal visual acceptance remains separate from headless tests.
