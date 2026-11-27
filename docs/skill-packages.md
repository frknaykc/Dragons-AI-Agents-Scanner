# Scanning a skill package

Pass the directory containing `SKILL.md` to scan a package. Passing an individual file scans that file only. Installed scans also recognize packages below the selected client's documented skill locations. Neither mode imports package code, follows remote links, installs dependencies, or expands archives.

Inside a selected package the scanner inventories supporting Markdown, common script and text/configuration formats, and recognized manifests. Markdown body evidence retains its original file and line. YAML frontmatter fields `name`, `description`, `compatibility`, `metadata`, and `allowed-tools` are typed metadata, not instructions or evidence of effective permissions. Duplicate keys, malformed YAML, and unsupported field types make coverage partial. A closing delimiter lets the scanner continue with the body even when the header is invalid.

An ordinary link records a reference, not an instruction to run its target. Local references resolve against the referring file inside the package; the scanner does not substitute a file with the same name. Missing, ambiguous or escaping references, symlinks and reference cycles are reported as coverage gaps. Private state such as `.env` files and key stores is outside package discovery.

`DRAGON-PATH-002` requires an explicit directive and original evidence connecting its exact target to an interpreter input. For example, the report can link `SKILL.md` to a procedure, the procedure to a named shell script, and a literal pipeline in that script to the Python interpreter. The source may be remote content or literal decoded input. A standalone link, an unreferenced helper, and a decoded text preview are not proof of that chain. Even a complete path is static evidence: nothing ran.

`DRAGON-EXEC-005` traces a different path: a package instruction names a script to run, and input in that script reaches an interpreter or selects the process to launch. The report identifies the instruction, script, input and call by file and line. An argument passed to a fixed executable is not by itself evidence that the argument selects that executable.

| Script | What the adapter follows |
|---|---|
| Python | Module-level assignments from `input()` or a positive literal `sys.argv` index to `eval`, `exec`, `os.system` or supported `subprocess` calls. Imports are inspected as syntax, never resolved. Analysis stops at the first unsupported statement and keeps earlier evidence. |
| Shell | Positional arguments `$1`–`$9` used to select a command or as input to `eval`, `sh -c` or `bash -c`. The separate literal-pipeline check for `DRAGON-PATH-002` still applies. |
| PowerShell | `$args[0]`–`$args[9]` used by the call operator or `Invoke-Expression`. |
| JavaScript | `process.argv[2]`–`process.argv[9]` used by `eval` in `.js`, `.cjs` or `.mjs` files. |

The three text adapters accept a whole file of simple scalar bindings and at most one terminal use. Unsupported syntax anywhere in that file yields partial coverage rather than a guessed relationship. All four adapters are limited to 64 KiB; token, nesting and statement limits restrict the supported subset further. Other script formats and unparsed data files are inventory only. Unsupported executable binaries and archives are not opened. A report without a finding is not a safety verdict; check its coverage diagnostics.
