"""CLI adapter; scan and reporting remain usable without Click."""

import os
from pathlib import Path

import click

from dragonscan.discovery import DiscoveryError
from dragonscan.dynamic_mcp import DynamicPolicy
from dragonscan.models import ScanReport, Severity, Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.risk import meets_threshold
from dragonscan.scanner import Scanner
from dragonscan.scanner import scan as scan_target
from dragonscan.semantic_provider import OpenAICompatibleProvider


@click.group()
def main() -> None:
    """Scan local AI agent artifacts; execution requires separate MCP consent."""


@main.command()
@click.argument("path", required=False, type=click.Path(path_type=Path))
@click.option(
    "--installed-agents", is_flag=True, help="Scan bounded known local agent environments"
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--fail-on",
    type=click.Choice([level.value for level in Severity]),
    default="high",
    show_default=True,
    help="Exit 1 on findings at or above this severity.",
)
@click.option(
    "--signature-pack",
    type=click.Path(path_type=Path),
    default=None,
    help="Load static JSON signatures from an explicit local directory.",
)
@click.option(
    "--vuln-check",
    is_flag=True,
    help="Query OSV over HTTPS; sends normalized package names and exact versions to OSV.",
)
@click.option(
    "--semantic",
    is_flag=True,
    help=(
        "Opt in; sends excerpts to a model. Redaction is best-effort; "
        "review target privacy before remote use."
    ),
)
@click.option("--semantic-url", help="Trusted OpenAI-compatible /v1/chat/completions URL.")
@click.option("--semantic-model", help="Trusted semantic model name.")
@click.option("--dynamic-mcp", is_flag=True, help="Request local stdio MCP metadata inspection.")
@click.option(
    "--allow-uncontained-mcp",
    is_flag=True,
    help="Separately consent to running untrusted code WITHOUT network or filesystem sandboxing.",
)
@click.option("--dynamic-mcp-server", help="Exact declared server name (must be unique).")
@click.option(
    "--dynamic-mcp-executable",
    type=click.Path(path_type=Path),
    help="Exact absolute executable path in the MCP config.",
)
def scan(
    path: Path | None,
    installed_agents: bool,
    output_format: str,
    fail_on: str,
    signature_pack: Path | None,
    vuln_check: bool,
    semantic: bool,
    semantic_url: str | None,
    semantic_model: str | None,
    dynamic_mcp: bool,
    allow_uncontained_mcp: bool,
    dynamic_mcp_server: str | None,
    dynamic_mcp_executable: Path | None,
) -> None:
    """Scan a local file or directory (recognized artifact names/context only)."""
    if path is None and not installed_agents:
        raise click.UsageError("PATH is required unless --installed-agents is set")
    if installed_agents and dynamic_mcp:
        raise click.UsageError("--dynamic-mcp cannot be combined with --installed-agents")
    provider = None
    if not dynamic_mcp and (allow_uncontained_mcp or dynamic_mcp_server or dynamic_mcp_executable):
        raise click.UsageError("--dynamic-mcp is required for dynamic execution options")
    dynamic_policy = DynamicPolicy(
        dynamic_mcp, allow_uncontained_mcp, dynamic_mcp_server, dynamic_mcp_executable
    )
    if semantic:
        if not semantic_url or not semantic_model:
            raise click.UsageError("semantic provider URL and model are required")
        try:
            provider = OpenAICompatibleProvider(
                semantic_url, semantic_model, os.environ.get("DRAGONSCAN_SEMANTIC_API_KEY")
            )
        except ValueError:
            raise click.UsageError("invalid semantic provider configuration") from None
    try:
        if vuln_check:
            from dragonscan.osv import OSVProvider

            scanner = Scanner(
                signature_pack=signature_pack,
                vulnerability_provider=OSVProvider(),
                semantic_provider=provider,
                dynamic_policy=dynamic_policy,
            )
        elif signature_pack is None and provider is None and not dynamic_mcp:
            scanner = Scanner()
        else:
            scanner = Scanner(
                signature_pack=signature_pack,
                semantic_provider=provider,
                dynamic_policy=dynamic_policy,
            )
        if installed_agents:
            report = scanner.scan_installed(Target(path) if path is not None else None)
        else:
            assert path is not None
            report = (
                scan_target(Target(path))
                if signature_pack is None
                and provider is None
                and not dynamic_mcp
                and not vuln_check
                else scanner.scan(Target(path))
            )
    except DiscoveryError as exc:
        report = ScanReport(path or Path.home(), (), (), (str(exc),))
    click.echo(json_report(report) if output_format == "json" else terminal_report(report))
    if (
        report.errors
        or any(item.status == "diagnostic" for item in report.installed_environments)
        or report.vulnerability_status == "partial"
        or report.semantic_status == "partial"
        or report.dynamic_status in {"blocked", "partial", "failed"}
    ):
        raise SystemExit(2)
    if meets_threshold(report.risk, Severity(fail_on)):
        raise SystemExit(1)
