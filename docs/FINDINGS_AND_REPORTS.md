# Findings and reports

[Overview](../README.md) · [CLI examples](CLI_GUIDE.md) · [Technical format reference](REFERENCE.md#sarif-output)

## Read a finding

Each finding has a stable **detection ID** (for example, `DRAGON-PI-001`), category/title, affected **artifact**, optional line, explanation, bounded **evidence** and remediation. The **severity** (`critical`, `high`, `medium`, `low`, `info`) reflects potential impact; **confidence** (`high`, `medium`, `low`) reflects strength of the evidence. **Classification** (`malicious`, `exploitable`, `risky`, `suspicious`, `informational`) is the detector's label, not a determination that an attack succeeded. Overall risk is the highest finding severity, not a probability score.

Where evidence supports it, `source` and `sink` describe the input and destination, `flow` describes structured transfer context and `path` contains supported attack-graph steps. Missing fields mean the relationship was **not established**, not that the artifact is safe. Location may be file-only for some formats. Diagnostics describe unreadable/malformed/omitted analysis, **not** security findings. A diagnostic can make a scan partial even when findings also exist.

The terminal summary starts with the target and counts of scanned artifact types, followed by `Artifacts`, `Status` (`COMPLETE`, `PARTIAL`, `FAILED`), risk, severity counts, `Policy` (`PASS`, `POLICY_VIOLATION`, `INCOMPLETE`, `SCAN_ERROR`) and reason. With `--installed-agents`, it also lists distinct discovered agent names (location evidence, not proof of installation) and the saved JSON report path before the result counts. A boxed **Findings** section contains a separate card for each security finding. Each card shows severity, title, rule ID, confidence, file/line, evidence, reason, **Check** (what to inspect), **False positive** (what could change the interpretation), and **Fix** (the rule's remediation). `MEDIUM` is orange when terminal color is enabled; `Check`, `False positive` and `Fix` labels have distinct colors. Piped output, `NO_COLOR` and report files contain no ANSI color codes. The review prompts are guidance, not extra findings or evidence that an action occurred. They do not change JSON/SARIF fields.

**Scan coverage & diagnostics** follows the findings with counts of errors, limited analyses, warnings and partial agent roots; it shows the first fatal cause, but not individual warning or coverage messages. Limits, unreadable files and skipped regions are not included in the finding count. A `PARTIAL` scan is not a clean bill of health, even when no findings appear. The default terminal `--installed-agents` scan saves full JSON to a newly created private directory under the user's home (`~/dragonscan-*/scan.json`, permission-restricted on POSIX systems). Its `Report` line gives the exact path. This file may contain local paths and bounded excerpts: review it before sharing or retaining it. The report is not uploaded; each run creates a new directory. Explicit `--format json` or `--output` continues to behave as requested, without an extra copy. JSON includes the per-artifact diagnostics and full installed-agent inventory, including unlocated roots; absence from the terminal agent list does not establish that a program is uninstalled. These [real terminal screenshots](../assets/screenshots/dragons-clean-scan.png) and [gated-finding capture](../assets/screenshots/dragons-severity-policy.png), along with the [missing-target text capture](assets/cli/diagnostic.txt), document earlier output; the [screenshot log](../assets/screenshots/README.md) records their commands and dates.

A synthetic security finding's selected fields, with the absolute local artifact path intentionally **omitted** (not a verbatim terminal capture):

```text
Status      COMPLETE
Risk        HIGH
Policy      POLICY_VIOLATION
╔═ Findings (1) ...
┌─ HIGH ...
│ Prior instruction override
│ Rule:           DRAGON-PI-001
│ Confidence:     HIGH
│ Evidence:       'instruction directs the agent to disregard prior instructions'
│ Reason:         An actionable instruction attempts to replace prior guidance;
│                 intent is not execution.
│ Check:          Inspect the cited artifact and surrounding context; verify ...
│ False positive: Quoted, prohibited or benign authorized behavior can change ...
│ Fix:            Remove the override and verify the artifact's author and trust boundary.
```

Command: `uv run dragonscan scan benchmarks/corpus/pi-override/SKILL.md --fail-on high` (exit **1**). This fixture is inert; Dragons did not run its contents.

## Static relationship details

CLI finding cards and the existing TUI detail pane show category, source, sink and
supported static path steps, including edge, artifact/line, origin and confidence.
Available flow types, trust boundaries, capabilities and transformations are shown
without inventing missing relationships. `not established` means no supporting
relationship was supplied by the detector; it does not mean safe. A supported
static path is **not runtime verification** or evidence of a successful attack.
Severity describes potential impact; confidence describes evidence strength.
The TUI keeps the scan coverage banner visible and long details scroll within the
existing pane, including at narrow terminal widths.

JSON retains its existing field shapes and omission rules. SARIF result properties
add `category` and, when present, `source`, `sink`, `path` and `flow`; these are
static context, not SARIF execution traces. Existing `relatedLocations` remain.
Relationship strings in all four formats use the same redaction boundary before
display/export, with unsafe or oversized values suppressed rather than truncated
before redaction. Local paths remain potentially identifying: review reports
before sharing. No rule, severity threshold or policy exit code changes.

## JSON

Failed scans without findings display **Risk: NOT ASSESSED** in the terminal and TUI, including when zero artifacts could be analyzed. Completed scans without findings retain **Risk: NONE**; existing findings retain their severity even if another artifact fails. Neither label is a guarantee of safety.

JSON keeps its nullable severity contract: `risk: null` means there is no finding severity, not that analysis succeeded. Check `scan_status`, `policy.status`, errors and diagnostics: a failed scan has `scan_status: failed`, `policy.status: scan_error` and exit code **3**. SARIF keeps operational errors out of `results` and reports them through `invocations[0].executionSuccessful: false` and the existing policy properties. A successfully executed but partial scan still requires checking the policy; `executionSuccessful: true` alone is not a pass.

```sh
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md --format json --output scan.json
```

The verified benign report has `"findings": []`, `"errors": []`, `"diagnostics": []`, `"scan_status": "complete"` and `"policy": {"status": "pass", ...}`. The exact JSON also contains an **absolute local artifact path**; this guide does not reproduce that path. For the synthetic high finding, the verified JSON has `detection_id: DRAGON-PI-001`, `severity: high`, `confidence: high`, `classification: suspicious`, `line: 1`, and policy `triggering_findings: ["DRAGON-PI-001"]`. These are selected observed fields, **not a complete JSON document**. JSON provides full per-artifact diagnostics; do not share unreviewed reports from private directories.

## SARIF

```sh
uv run dragonscan scan benchmarks/corpus/pi-override/SKILL.md --format sarif --output scan.sarif --fail-on high
```

The verified SARIF 2.1.0 output for that synthetic fixture includes the following **selected fields** (not a complete SARIF document):

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "DRAGON-PI-001",
          "level": "error",
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": "benchmarks/corpus/pi-override/SKILL.md"},
              "region": {"startLine": 1}
            }
          }]
        }
      ],
      "properties": {"policy": {"status": "policy_violation"}}
    }
  ]
}
```

SARIF includes `tool.driver.rules` and only actual security findings in `results`; operational diagnostics do **not** appear as fake SARIF results. Severity maps to SARIF `error` for critical/high, `warning` for medium, `note` for low/info. A relative URI for repository files may enable Code Scanning linkage, but archive members and files outside the workspace may not map to source lines. Generating SARIF does **not** upload it to GitHub; hosted acceptance was not validated. Read [CI integration](CI_INTEGRATION.md) before uploading any artifact.

## Exit status matters

Reports and exit codes share one policy decision: **0** completed/pass (even with findings when no threshold is selected), **1** requested severity policy violation, **2** invalid CLI invocation, **3** incomplete analysis or scan failure. Operational errors take precedence over policy findings. `--output` writes atomically and suppresses stdout; always inspect the exit status separately. [Full policy rules](REFERENCE.md#current-scope).
