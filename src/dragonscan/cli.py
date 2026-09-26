"""CLI adapter; scan and reporting remain usable without Click."""

import os
from pathlib import Path

import click

from dragonscan.discovery import DiscoveryError
from dragonscan.models import ScanReport, Severity, Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.risk import meets_threshold
from dragonscan.scanner import Scanner
from dragonscan.scanner import scan as scan_target
from dragonscan.semantic_provider import OpenAICompatibleProvider


@click.group()
def main() -> None:
    """Scan local AI agent artifacts without executing them."""


@main.command()
@click.argument("path", type=click.Path(path_type=Path))
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
def scan(
    path: Path,
    output_format: str,
    fail_on: str,
    signature_pack: Path | None,
    vuln_check: bool,
    semantic: bool,
    semantic_url: str | None,
    semantic_model: str | None,
) -> None:
    """Scan a local file or directory (recognized artifact names/context only)."""
    provider = None
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

            report = Scanner(
                signature_pack=signature_pack,
                vulnerability_provider=OSVProvider(),
                semantic_provider=provider,
            ).scan(Target(path))
        elif signature_pack is None and provider is None:
            report = scan_target(Target(path))
        else:
            report = Scanner(signature_pack=signature_pack, semantic_provider=provider).scan(
                Target(path)
            )
    except DiscoveryError as exc:
        report = ScanReport(path, (), (), (str(exc),))
    click.echo(json_report(report) if output_format == "json" else terminal_report(report))
    if (
        report.errors
        or report.vulnerability_status == "partial"
        or report.semantic_status == "partial"
    ):
        raise SystemExit(2)
    if meets_threshold(report.risk, Severity(fail_on)):
        raise SystemExit(1)
