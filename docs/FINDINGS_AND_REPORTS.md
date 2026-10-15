# Findings and reports

[Overview](../README.md) · [CLI examples](CLI_GUIDE.md) · [Technical format reference](REFERENCE.md#sarif-output)

## Read a finding

Each finding has a stable **detection ID** (for example, `DRAGON-PI-001`), category/title, affected **artifact**, optional line, explanation, bounded **evidence** and remediation. The **severity** (`critical`, `high`, `medium`, `low`, `info`) reflects potential impact; **confidence** (`high`, `medium`, `low`) reflects strength of the evidence. **Classification** (`malicious`, `exploitable`, `risky`, `suspicious`, `informational`) is the detector's label, not a determination that an attack succeeded. Overall risk is the highest finding severity, not a probability score.

Where evidence supports it, `source` and `sink` describe the input and destination, `flow` describes structured transfer context and `path` contains supported attack-graph steps. Missing fields mean the relationship was **not established**, not that the artifact is safe. Location may be file-only for some formats. Diagnostics describe unreadable/malformed/omitted analysis, **not** security findings. A diagnostic can make a scan partial even when findings also exist.

The terminal summary presents `Status` (`COMPLETE`, `PARTIAL`, `FAILED`), risk, severity counts, `Policy` (`PASS`, `POLICY_VIOLATION`, `INCOMPLETE`, `SCAN_ERROR`) and reason. It groups `ERROR`, `WARNING` and `COVERAGE` separately. [Real clean-scan screenshot](../assets/screenshots/dragons-clean-scan.png) · [real gated-finding screenshot](../assets/screenshots/dragons-severity-policy.png) · [missing-target text capture](assets/cli/diagnostic.txt). The [screenshot log](../assets/screenshots/README.md) records commands, fixtures and exit codes.

A verified synthetic security finding, with the absolute local artifact path intentionally **omitted** (this is a summary, not a verbatim terminal capture):

```text
Status      COMPLETE
Risk        HIGH
Findings    1
Policy      POLICY_VIOLATION
HIGH  DRAGON-PI-001  (high confidence)
  Prior instruction override
  Evidence  'instruction directs the agent to disregard prior instructions'
```

Command: `uv run dragonscan scan benchmarks/corpus/pi-override/SKILL.md --fail-on high` (exit **1**). This fixture is inert; Dragons did not run its contents.

## JSON

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
