# Scanning a skill package

Pass the directory containing `SKILL.md` to scan a package. Passing an individual file scans that file only. Installed scans also recognize packages below the selected client's documented skill locations. Neither mode imports package code, follows remote links, installs dependencies, or expands archives.

Inside a selected package the scanner inventories supporting Markdown, common script and text/configuration formats, and recognized manifests. Markdown body evidence retains its original file and line. YAML frontmatter fields `name`, `description`, `compatibility`, `metadata`, and `allowed-tools` are typed metadata, not instructions or evidence of effective permissions. Duplicate keys, malformed YAML, and unsupported field types make coverage partial. A closing delimiter lets the scanner continue with the body even when the header is invalid.

An ordinary link records a reference, not an instruction to run its target. Local references resolve against the referring file inside the package; the scanner does not substitute a file with the same name. Missing, ambiguous or escaping references, symlinks and reference cycles are reported as coverage gaps. Private state such as `.env` files and key stores is outside package discovery.

`DRAGON-PATH-002` requires an explicit directive and original evidence connecting its exact target to an interpreter input. For example, the report can link `SKILL.md` to a procedure, the procedure to a named shell script, and a literal pipeline in that script to the Python interpreter. The source may be remote content or literal decoded input. A standalone link, an unreferenced helper, and a decoded text preview are not proof of that chain. Even a complete path is static evidence: nothing ran.

Script analysis currently recognizes a single top-level shell pipeline plus blank or comment lines. Other programs and unparsed data files are inventory only, with incomplete semantic coverage. Unsupported executable binaries and archives are not opened. File, byte, depth and graph limits can also stop analysis; inspect scan diagnostics before drawing conclusions.
