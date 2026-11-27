# Package identity and intelligence

A vulnerability, a malicious-package advisory, and a missing registry entry answer different questions. None establishes that a package was installed or that its code ran. Scans do not resolve, download, import or install a dependency to establish its origin.

## Package evidence

The static matcher compares ecosystem (PyPI or npm), package name, exact supported version and public registry origin. PyPI names use lowercase and collapse `-`, `_` and `.`; npm scopes are part of the name. Known private registries, ambiguous index options, direct URLs and unsupported version expressions do not match a public advisory. Current support covers a conservative subset of exact versions; it is not a package-manager resolver. Manifest, lock and MCP origins are declarations, not observations of downloaded bytes.

`DRAGON-SC-010` requires a fresh authenticated malicious-package advisory, explicit public origin evidence, and an active runtime declaration. A passive declaration is not a malicious-package finding. A legacy public-default match without explicit origin is advisory only. Withdrawn records are not matched. Opt-in OSV enrichment is separate: a withdrawn advisory, a `MAL-` record, or an advisory with a `MAL-` alias is not reported as a vulnerability. OSV's batch result supplies the exact-version match for records using version ranges; the scanner does not resolve those ranges independently.

### Review a saved registry response

```sh
python -m dragonscan.intel_commands registry-check response.json \
  --ecosystem npm --name sample --version 1.0.0 --registry https://registry.npmjs.org
```

This command reads a local JSON snapshot (up to 8192 bytes). It does not contact a registry. The operator supplies the capture; it is not an authenticated denial. Example shape (use the actual observation time):

```json
{
  "identity": {"ecosystem":"npm","name":"sample","version":"1.0.0","registry":"https://registry.npmjs.org"},
  "observed_at":"2026-01-01T00:00:00Z",
  "method":"GET", "url":"https://registry.npmjs.org/sample", "http_status":200,
  "body":{"name":"sample","versions":{"1.0.0":{}}}
}
```

For npm use the public package URL (encode a scope's `/` as `%2F`); for PyPI use `https://pypi.org/pypi/NAME/json` with `info.name` and the `releases` mapping. Use the original version-key set, not a filtered list. A `404` must be from the package-level GET, not a version URL. A current matching capture can report `version_present`, `version_missing`, or `package_missing`. Only the last produces review ID `DRAGON-SC-008`. An outage, a private registry, a mismatched URL, an unusable capture, or an observation older than 24 hours returns `unknown`.

Pass `--intended intended.json --resolved resolved.json` to compare independently known intent and reviewed lock provenance. Each file uses the four-field `identity` object above, without the wrapper. `DRAGON-SC-009` flags a near-name substitution within the same scope or the same name from a different registry only when the observed public version matches the supplied resolved identity. Similar names alone are not a finding. These review IDs are not scan-policy triggers.

## Offline signed releases

Keep the signer policy and intelligence store outside the scan target. Obtain the public key independently of the candidate feed. The policy is local configuration, not a file discovered in a target:

```json
{"keys":{"release-key":"ssh-ed25519 BASE64_PUBLIC_KEY"},"feeds":{"example":["release-key"]},"revoked":[]}
```

Use the public key's algorithm and base64 fields without a comment. Policy IDs are ASCII letters/digits, `_` or `-` and begin with a letter or digit. The feed is schema 1 JSON with a numeric dotted `feed_version` and required `expires` in `YYYY-MM-DDTHH:MM:SSZ` format. A record can contain a `withdrawn` date or UTC timestamp. A package `registry`, if present, must be the supported public origin for its ecosystem. The producer signs the **original file bytes**, using an Ed25519 OpenSSH detached signature under namespace `dragonscan-feed-v1`. Whitespace and BOM changes are not interchangeable bytes.

```sh
python -m dragonscan.intel_commands install-signed --feed feed.json \
  --signature feed.json.sig --signer release-key --trust trusted.json --store ./intel-store
python -m dragonscan.intel_commands verify ./intel-store/intel.json --trust trusted.json
```

Installation checks feed ID authorization, signer revocation, signature, expiry and the store's numeric version floor before atomic replacement. A changed payload at the same version, a downgrade or an unsuccessful validation leaves the previous release intact. Installation and legacy updates serialize on the same store lock. A digest-pinned legacy update cannot replace an installed signed release. Revocation takes effect at the next verification: add the old key ID to `revoked` and authorize a replacement key for this feed. Do not reuse revoked keys under new IDs. The store and policy must not be writable by untrusted users. Rollback protection covers updates to this store; it does not survive deletion, backup restoration or compromise of the operator account.

Authentication uses the system `/usr/bin/ssh-keygen` verifier; no target executables, dependencies, shell, remote key servers or custom cryptography are used. Updates fail closed on Windows until ACL validation is supported. A successful verification returns the SHA-256 of the feed bytes, not the envelope. A signed envelope requires an explicit trust policy at load time (`load_feeds(paths, trust_path=policy_path)`); without it the scanner reports incomplete intelligence, not an unsigned fallback. A legacy feed's `trust` or `provenance` label is not authentication. Its matches, like unsigned user signature-pack matches, remain visible but cannot alone trigger a severity policy or a malicious-digest launch veto. Incomplete requested analysis remains a separate fail-closed condition.
