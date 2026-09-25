"""CLI adapter; scan and reporting remain usable without Click."""

from pathlib import Path

import click

from dragonscan.discovery import DiscoveryError
from dragonscan.models import ScanReport, Severity, Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.risk import meets_threshold
from dragonscan.scanner import Scanner
from dragonscan.scanner import scan as scan_target


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
def scan(path: Path, output_format: str, fail_on: str, signature_pack: Path | None) -> None:
    """Scan a local file or directory (recognized artifact names/context only)."""
    try:
        report = (
            scan_target(Target(path))
            if signature_pack is None
            else Scanner(signature_pack=signature_pack).scan(Target(path))
        )
    except DiscoveryError as exc:
        report = ScanReport(path, (), (), (str(exc),))
    click.echo(json_report(report) if output_format == "json" else terminal_report(report))
    if report.errors:
        raise SystemExit(2)
    if meets_threshold(report.risk, Severity(fail_on)):
        raise SystemExit(1)
