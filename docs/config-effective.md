# Codex effective configuration

`dragonscan config-effective` answers one question: given two explicit configuration files, which `features.computer_use` declaration would win in a measured Codex CLI 0.146.0 case? It does not report whether computer use is available, permitted or active in a running session.

```sh
dragonscan config-effective \
  --codex-version 0.146.0 \
  --user-config /review/home/.codex/config.toml \
  --project /review/project
```

The version and project root are supplied by the operator. The project file is `/review/project/.codex/config.toml`. For example, with these inputs:

```toml
# /review/home/.codex/config.toml
[projects."/review/project"]
trust_level = "untrusted"
[features]
computer_use = false
```

```toml
# /review/project/.codex/config.toml
[features]
computer_use = true
```

The JSON result is:

```json
{"key":"features.computer_use","effective":false,"source":"user","reason":"untrusted"}
```

With `trust_level = "trusted"` instead, the project value wins. The same precedence was observed with the two booleans reversed. These four observations are the entire compatibility matrix. The result describes the supplied pair only. No Codex installation, home directory, environment, parent directory, managed configuration or runtime policy is searched for additional layers. If another layer, profile, environment or command-line override might apply, pass `--overrides-present`; the result is `unknown`.

## Reading `unknown`

`effective` is a JSON boolean for a measured case and the string `"unknown"` otherwise. `source` is `user`, `project` or `unknown`; `reason` identifies the trust decision or limitation without quoting input. An unknown result exits successfully: it is not `false` and does not establish a safe configuration.

Only the two layouts above, with the exact project trust entry and opposing boolean declarations, are modeled. Other versions, missing or additional keys (including unused profiles), implicit trust, same-valued declarations and non-boolean values are not inferred. Each UTF-8 TOML input is limited to 16 KiB. Missing files, malformed TOML, links in any path component, nonregular files and `..` paths yield `unknown`. Platforms without descriptor-relative, no-follow opening also return `unknown` rather than weakening the boundary.

## Evidence and scan modes

The [golden fixture](../tests/fixtures/config-effective/codex-0.146.0.json) records the `computer_use` row from `codex features list`, once per trust setting and polarity. The [maintainer capture script](../scripts/capture_codex_precedence.py) requires an already installed, trusted `codex-cli 0.146.0`. It invokes only `--version` and `features list` with generated configs, a temporary repository root and a synthetic home; it does not start an agent session. The scanner and normal tests do not invoke this script or Codex.

`dragonscan scan` remains a declaration scan. Direct-file, project-directory and synthetic installed-home scans can report the same artifact and findings without assuming that the file was loaded by Codex. Use `config-effective` separately when both layers and the exact version are known.
