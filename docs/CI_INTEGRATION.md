# CI integration

[Overview](../README.md) · [Policy and exit codes](CLI_GUIDE.md#exit-status-and-policy) · [Report fields](FINDINGS_AND_REPORTS.md)

## Choose an integration

The repository includes a [local composite Action](../action.yml) and a [workflow example](../examples/dragons-action.yml) for **trusted checkouts of Dragons itself**. The example's `uses: ./` resolves to the repository it checks out; copying that workflow unchanged to another repository would run that repository's root Action, not Dragons. For your own pipeline, install Dragons from an explicitly trusted source and invoke its CLI as shown below. No published Action tag or Marketplace listing is provided; use of the Action from a different repository has not been hosted-tested. Do not present Dragons's development quality workflow as a user-facing scanner integration.

## Composite Action in a trusted checkout

When a trusted checkout contains the Dragons Action at its root, review the example's triggers and policy before enabling it. Its checkout disables persisted Git credentials; the job grants only `contents: read`. It calls `uses: ./` **after checkout**. The Action itself does not checkout code and does not enable remote targets, semantic providers, OSV, installed-agent discovery or MCP execution.

**Trust boundary:** `uses: ./` installs and executes Action setup code from that same checkout. Do **not** run this form against an untrusted pull-request checkout. For untrusted PR targets, use a separately trusted Action source pinned to an immutable commit and isolate other build steps. This is not a sandbox. The Action setup can fetch its own pinned Python/uv dependencies; the static scan does not fetch target links or install target dependencies.

The Action's inputs are `target` (relative path in `GITHUB_WORKSPACE`, default `.`), `fail-on` (optional, e.g. `high`) and `fail-on-incomplete` (`true`/`false`, default `false`). Paths outside the workspace, traversals, symlink escapes and remote URLs are rejected. It outputs `exit-code` and `sarif-path` when a report is available; SARIF is written to `$RUNNER_TEMP/dragons.sarif`. No secret or scanner-controlled finding text is emitted through Action outputs. The local Action has been tested on a GitHub-hosted Ubuntu 24.04 runner with trusted fixtures; other runners and third-party repositories have not been tested.

## CLI-only policy in a CI job

Once the repo is checked out and Dragons is installed from trusted source, a local CI step may invoke:

```sh
uv run dragonscan scan ./agent-directory --format sarif --output scan.sarif --fail-on high --fail-on-incomplete
```

`./agent-directory` is a placeholder, not bundled content. A completed scan with no threshold violation exits **0** (even when other findings exist); a completed scan meeting `--fail-on high` exits **1**; invalid usage exits **2**; partial/failed scans exit **3**. An operational error wins over threshold failure. The Action preserves the scanner's exit status rather than masking it with `continue-on-error`; a setup failure occurs before there is a scanner code. The report can exist when the scan exits 1 or 3, but inspect it for completeness and sensitive data before exporting it.

## SARIF artifacts and Code Scanning

The Action generates SARIF; it does **not** upload it. The [hosted validation workflow](../.github/workflows/hosted-action-sarif.yml) uploads a verified report using `github/codeql-action/upload-sarif`, a stable `dragons-hosted-validation` category and job-scoped `contents: read` / `security-events: write` permissions. It is manually triggered on a trusted revision, checks a clean scan (exit 0), a synthetic policy failure (exit 1), an invalid target (exit 3), and a finding scan (exit 0 with no policy threshold). Expected failures use `continue-on-error` only alongside assertions of both the underlying step outcome and scanner exit code; a failed assertion fails the job. A successful upload does not change the scanner's policy result.

The GitHub-hosted validation [run 38900274145](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/38900274145) on commit `b41d0e2bd7af0f82a4cd9e9fcf878aaa24071029` completed successfully. GitHub Code Scanning accepted one analysis (category `dragons-hosted-validation`) and displayed `DRAGON-PI-002` at `benchmarks/corpus/quality-instruction-safety-bypass/SKILL.md:3` with SARIF level `error`. The validated fixture contained one result and no unexpected findings. This confirms ingestion and visibility for that trusted, manually dispatched workflow—not uploads from forks, untrusted PRs or external repositories.

For your own workflow, scan only targets you are authorized to report to GitHub. Pass a workspace-relative `target`, keep credentials out of the scan environment, verify the SARIF and then upload it with `security-events: write` in a trusted job. The upload action must receive the SARIF path and may use a distinct `category` for each analysis stream; avoid repeated uploads of the same category/ref/commit. Repository-relative locations may link to code; archive and external URIs may not. The [SARIF reference](REFERENCE.md#sarif-output) documents this mapping. Keep private target paths and potential report excerpts out of public artifacts unless reviewed. Fork PR tokens are commonly read-only and cannot be assumed to upload SARIF; never use `pull_request_target` to run untrusted checkout code with a write-capable token.

GitHub references: [composite Action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax), [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [SARIF upload and permissions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file), [supported SARIF data](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), and [workflow token security](https://docs.github.com/en/actions/reference/security/secure-use).
