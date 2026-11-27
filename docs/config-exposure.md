# Credential exposure and persistence

A static finding describes what a configuration declares or what an instruction requests. It does not mean a credential works, a file was read, a service was installed, or data left the machine.

| Rule | What triggers it |
| --- | --- |
| `DRAGON-SECRET-001` | A sensitive environment or header field in a supported MCP server declaration contains a complete recognized GitHub or GitLab token format, optionally preceded by `Bearer`. Evidence identifies the field location and credential family, not the value. |
| `DRAGON-CRED-001` | An actionable instruction requests access to a protected source. Recognized paths include SSH private keys, AWS credentials, Kubernetes config, Google application-default credentials, Docker client config, the Chrome default-profile login database on Linux, and the Bitcoin Core wallet file. |
| `DRAGON-EXFIL-001` | The instruction links sensitive data to an external transfer. Reading a protected source and separately uploading build logs is not evidence of credential transfer. |
| `DRAGON-PERSIST-001` | A directive targets an agent instruction, configuration or hook file and indicates persistent influence. Examples of recognized targets are `MEMORY.md`, `.claude/settings.json`, and `.codex/config.toml`. |
| `DRAGON-PERSIST-002` | A directive requests writing a recognized systemd service, user launch agent or cron schedule to run a task without operator approval. A scheduled backup or a service filename alone is not sufficient. |

The literal rule does not resolve environment references or validate tokens. An unused profile is not an active MCP server declaration. Public SSH keys and sample filenames such as `.kube/config.example` do not match the corresponding protected file. An edit expressly conditioned on user approval is not treated as an unapproved change simply because the target is persistent.

Ordinary scans inspect only the supplied artifacts; a path named in an instruction is evidence, not permission for the scanner to open it. These rules neither determine the effective settings of an installed agent nor establish runtime behavior.
