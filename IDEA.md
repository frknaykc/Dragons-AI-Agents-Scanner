Dragons AI Agent Scanner

Idea

Dragons AI Agent Scanner is an open-source security scanner designed for the AI agent ecosystem.

AI agents increasingly rely on external artifacts such as skills, MCP servers, plugins, instruction files, memory files, hooks, and configuration files. These artifacts can influence agent behavior, access sensitive resources, execute tools or commands, communicate with external systems, and persist instructions across sessions.

This creates a new security surface where malicious or compromised content may lead to prompt injection, credential theft, data exfiltration, unsafe command execution, persistence, tool poisoning, supply-chain attacks, or other unintended agent behavior.

Dragons AI Agent Scanner aims to detect these risks before an artifact is trusted or executed.

What It Scans

The scanner should support common agent artifacts and ecosystems, including:

* SKILL.md and agent skills
* AGENTS.md
* SOUL.md
* MEMORY.md
* CLAUDE.md and similar instruction files
* MCP configurations and servers
* Plugins and extensions
* Agent hooks and scripts
* Agent configuration files
* Installed or downloaded AI agent projects

The architecture should allow additional agent ecosystems and artifact formats to be added over time.

Detection Goals

The scanner should identify behaviors and patterns such as:

* Direct and indirect prompt injection
* Malicious or suspicious instructions
* Tool poisoning and tool shadowing
* Credential and secret access
* Data exfiltration
* Dangerous command execution
* Remote code execution patterns
* Untrusted remote instructions
* Memory or instruction poisoning
* Agent persistence and self-modification
* Hidden or obfuscated instructions
* Suspicious network communication
* Excessive permissions or capabilities
* Dependency and supply-chain risks
* Mismatch between declared and actual behavior

Detection should not rely on simple keyword matching alone.

The project should combine deterministic security rules, structured parsing, behavioral analysis, data-flow/taint analysis, known threat indicators, and optional semantic analysis where appropriate.

Findings

Every security finding should be explainable.

A finding should include, when applicable:

* Severity
* Confidence
* Detection category
* Affected artifact
* File and location
* Evidence
* Reason for detection
* Relevant source and sink
* Recommended action

Severity levels should follow a simple model:

Critical, High, Medium, Low, and Info.

The scanner should distinguish between:

* Confirmed malicious behavior
* Exploitable security risks
* Suspicious behavior
* Security weaknesses
* Informational findings

Core Principles

Local First

Core scanning should be capable of running locally without requiring source files, prompts, credentials, or agent configuration to be uploaded to an external service.

Safe by Default

Scanning an artifact must not unnecessarily execute or trust the artifact being analyzed.

Dynamic inspection, when required, should use appropriate isolation and explicit user control.

Evidence Over Scores

The scanner should explain why something is dangerous rather than only producing an arbitrary risk score.

Context Matters

A single behavior may be harmless in isolation but dangerous when combined with another capability.

For example:

Sensitive Data Access → External Network Communication

may represent a potential exfiltration path even when neither capability is independently malicious.

The scanner should eventually be capable of correlating behavior across multiple agent artifacts.

Extensible Detection

Security rules and detections should be designed so the open-source community can contribute new detection logic, attack patterns, indicators, and test cases as the agentic security landscape evolves.

Usage Vision

The project should eventually support workflows such as:

dragonscan scan SKILL.md
dragonscan scan ./agent
dragonscan scan ./repository
dragonscan scan <git-repository>
dragonscan scan --system

It should be useful both before installing third-party agent components and for auditing existing AI agent environments.

Machine-readable output such as JSON and SARIF should allow integration with CI/CD and security workflows.

Project Goal

Dragons AI Agent Scanner should become a practical open-source security layer for the agentic ecosystem.

The goal is not simply to determine whether a file contains suspicious words.

The goal is to answer:

What can this agent artifact cause an AI agent to do, what does it trust or access, and could that behavior create a security risk?
