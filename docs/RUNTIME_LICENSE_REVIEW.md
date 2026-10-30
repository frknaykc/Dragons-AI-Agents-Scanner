# Standalone runtime license review

This is a release-gate record, not a redistribution grant. Dragons' application
license remains MIT. A successful notice checksum check is not license clearance.

## Observed runtime and sources

The four-platform validation of `abe40c5c8e972e22417dd25614772e9efb32ae18`
used CPython 3.12.12; the interpreter's `BUILD` marker identifies PBS 20260211.
The [native validation run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41054686275)
passed 276 installed-wheel tests on each platform. Its license gate failed.
The marker identifies the claimed build, not a cryptographic match between the
installed interpreter, its transformed bundled library and an upstream archive.

Explicit provisioning downloads these original sources, without executing them:

| Source | SHA-256 |
| --- | --- |
| [CPython 3.12.12 additional notices](https://raw.githubusercontent.com/python/cpython/v3.12.12/Doc/license.rst) | `341832873fd316a37927e79385093fbbfd40a467428480835fe435a80cadf4e5` |
| [PBS 20260211 source archive](https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/refs/tags/20260211) | `a70d814140fb061d5724c477aeecfdf263e890d3a3515546763adc727f929628` |
| [CPython HACL* header](https://raw.githubusercontent.com/python/cpython/v3.12.12/Modules/_hacl/Hacl_Hash_SHA2.h) | `093d7693084af0999d2a13d207311d74b5bdfdc9c08447ed4a979e3f7505ae6b` |
| [CPython KaRaMeL header](https://raw.githubusercontent.com/python/cpython/v3.12.12/Modules/_hacl/include/krml/internal/target.h) | `d16a59f37a1d4982626870e370889eb9d332a9ad035661b8062f549fc734d061` |
| [Vendored upstream Apache 2.0 license](https://raw.githubusercontent.com/hacl-star/hacl-star/bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0/LICENSE) | `c5accbbd8546e94c34aed24afe689a617627d18eed5a6c48277e48db57c23851` |

Packaging copies CPython's installed `LICENSE.txt`, additional notices and the
PBS recipe's original license files byte-for-byte into the adjacent notice
directory. The recipe is parsed as data, never imported. Recipe versions describe
candidate components, not proof that every candidate is linked into the binary.
Missing sources, unreviewed cached URLs and changed bytes are not silently accepted.

### Embedded cryptography notices

The inspected `abe40c5` sidecars omitted HACL*'s MIT copyright/grant and KaRaMeL's
Apache attribution. `Doc/license.rst` alone does not supply these notices.
Packaging now retains the two original leading C comments byte-for-byte, without
shipping or executing header code, together with the complete upstream Apache
license. The upstream revision is recorded in CPython's
[vendoring script](https://github.com/python/cpython/blob/v3.12.12/Modules/_hacl/refresh.sh),
which was inspected as text, never run. All 13 vendored HACL* implementation and
interface headers inspected share the same MIT notice; the support headers carry
the INRIA/Microsoft Apache attribution. One copy of each notice is sufficient
for this collection; these are not new runtime dependencies.

This mapping is reviewed only for CPython 3.12.12. Other interpreter versions and
missing cache entries remain explicitly unresolved; corrupt sources or malformed
reviewed headers fail closed. Provisioning is explicitly online during build
setup; notice generation and scanning remain offline. The historical candidate
above predates this correction and is not retroactively considered compliant.

## Independent upstream archive inspection

Four full archives from the [PBS 20260211 release](https://github.com/astral-sh/python-build-standalone/releases/tag/20260211)
were downloaded and matched against the release API's SHA-256 digests. Metadata,
license texts and native bytes were read as data; no archived code was executed.
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

### Final-binary byte comparison

The same candidate's runtime bytes were compared with the release's
`install_only_stripped.tar.gz` archives, each checked against its published digest:

| Target | Archive SHA-256 | Observed correspondence |
| --- | --- | --- |
| `aarch64-apple-darwin` | `22625deaf5757e7c266cf1a096c9151a06b598b1e14632a2ec9993d58ec5fe84` | `libpython3.12.dylib` body identical; signature-related changes |
| `x86_64-apple-darwin` | `a84ac7a36d465bc6eb68db84540fdb5da04333900e2c3cb34b5d454f2022048c` | `libpython3.12.dylib` body identical; added signature |
| `x86_64-unknown-linux-gnu` | `1dbaa624a09e15afe7efbdac08d42993135a68db8d34f986ef6977a6d77bdc3c` | `libpython3.12.so.1.0` byte-identical |
| `x86_64-pc-windows-msvc` | `93bf8e8c05ede0077b197a29c99ebdaf253497f27190097494265150b4e70ba8` | 22 matched native entries byte-identical, including both VCRUNTIME DLLs, not UCRT |

For both Mach-O libraries, every byte after the load-command region and before
the signature matched; excluded header padding was zero. Differences were confined
to `__LINKEDIT` size/signature commands and signature bytes (plus the Intel header's
command count/size). No load-path difference was observed. This is a transformed
binary correspondence, not a claim that the complete dylib hashes are identical.

The Unix libraries contain `OpenSSL 3.5.5 27 Jan 2026`; Windows `libcrypto-3-x64.dll`
and `libssl-3-x64.dll` report PE file version `3.5.5.0`, with the same version string
in libcrypto. This resolves the observed version ambiguity for these bytes, not
every static-link/notice obligation in the broader runtime inventory. The stale
1.1 metadata names are not used as final-binary identities.

Static PE resource inspection identified both VCRUNTIME DLLs as `14.44.35211.0`
and `ucrtbase.dll` as `10.0.26100.1742`. Both VCRUNTIME DLLs match PBS's stripped
Windows archive; `ucrtbase.dll` has no matching entry in the inspected PBS archives,
so its origin remains unverified. PBS provenance is not Microsoft's redistribution grant.

## Remaining release blockers

1. Complete the linked-component / notice mapping and component-specific attribution,
   source or relinking review. Verify corrected HACL*/KaRaMeL notices in newly built
   artifacts; the historical candidates above do not contain them. Runtime byte
   correspondence narrows this blocker but does not certify complete clearance.
2. Establish UCRT provenance, applicable Microsoft terms and the distributor's
   entitlement for the identified Windows files. [Microsoft's redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)
   limits distribution to licensed Visual Studio users under the relevant terms;
   the [2022 redistributable list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution)
   is conditional on a valid license. A hosted runner or a copied DLL filename
   does not establish that entitlement for Dragons' publisher.

Until these are resolved, retain `unresolved_obligations` and report release
acceptance **FAIL**. Do not substitute a generic license text, remove a failing
gate, or treat the candidate notice collection as complete runtime compliance.
Manual native-terminal visual acceptance remains separate from headless tests.
