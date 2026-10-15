# CI integration

[Overview](../README.md) · [Policy and exit codes](CLI_GUIDE.md#exit-status-and-policy) · [Report fields](FINDINGS_AND_REPORTS.md)

## Choose an integration

The repository includes a [local composite Action](../action.yml) and a [workflow example](../examples/dragons-action.yml) for **trusted checkouts of Dragons itself**. The example's `uses: ./` resolves to the repository it checks out; copying that workflow unchanged to another repository would run that repository's root Action, not Dragons. There is no published Action tag or immutable revision to reference from an external repository. For your own pipeline, install Dragons from an explicitly trusted source and invoke its CLI as shown below. Do not present Dragons's development quality workflow as a user-facing scanner integration.

## Composite Action in a trusted checkout

When a trusted checkout contains the Dragons Action at its root, review the example's triggers and policy before enabling it. Its checkout disables persisted Git credentials; the job grants only `contents: read`. It calls `uses: ./` **after checkout**. The Action itself does not checkout code and does not enable remote targets, semantic providers, OSV, installed-agent discovery or MCP execution.

**Trust boundary:** `uses: ./` installs and executes Action setup code from that same checkout. Do **not** run this form against an untrusted pull-request checkout. For untrusted PR targets, use a separately trusted Action source pinned to an immutable commit and isolate other build steps. No published Action tag, Marketplace listing or trusted immutable revision is provided here. This is not a sandbox. The Action setup can fetch its own pinned Python/uv dependencies; the static scan does not fetch target links or install target dependencies.

The Action's inputs are `target` (relative path in `GITHUB_WORKSPACE`, default `.`), `fail-on` (optional, e.g. `high`) and `fail-on-incomplete` (`true`/`false`, default `false`). Paths outside the workspace, traversals, symlink escapes and remote URLs are rejected. It outputs `exit-code` and `sarif-path` when a report is available; SARIF is written to `$RUNNER_TEMP/dragons.sarif`. No secret or scanner-controlled finding text is emitted through Action outputs. Only Ubuntu is in scope for the composite Action. Local metadata/CLI tests have passed; **GitHub-hosted Action execution has not been validated**.

## CLI-only policy in a CI job

Once the repo is checked out and Dragons is installed from trusted source, a local CI step may invoke:

```sh
uv run dragonscan scan ./agent-directory --format sarif --output scan.sarif --fail-on high --fail-on-incomplete
```

`./agent-directory` is a placeholder, not bundled content. A completed scan with no threshold violation exits **0** (even when other findings exist); a completed scan meeting `--fail-on high` exits **1**; invalid usage exits **2**; partial/failed scans exit **3**. An operational error wins over threshold failure. The Action preserves the scanner's exit status rather than masking it with `continue-on-error`; a setup failure occurs before there is a scanner code. The report can exist when the scan exits 1 or 3, but inspect it for completeness and sensitive data before exporting it.

## SARIF artifacts and Code Scanning

The Action generates SARIF; it does **not** upload it. A separate workflow could upload a reviewed SARIF artifact to GitHub Code Scanning with appropriate `security-events: write` permissions and an explicitly trusted upload step, after considering failure handling and fork-PR permissions. No hosted upload, Code Scanning acceptance or cross-platform Action behavior is claimed as verified. Repository-relative locations may link to code; archive and external URIs may not. The [SARIF reference](REFERENCE.md#sarif-output) documents this mapping. Keep private target paths and potential report excerpts out of public artifacts unless reviewed.
