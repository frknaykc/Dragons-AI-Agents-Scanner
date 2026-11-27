"""Explicit local web inspection and separately consented registration evidence."""

import json
from pathlib import Path

import click

from dragonscan.domain_evidence import EvidenceError, inspect_domain
from dragonscan.loading import LoadError
from dragonscan.web_ingestion import inspect_web

_LOCAL = click.Path(path_type=Path, dir_okay=False)


@click.command("scan-web")
@click.argument("path", type=_LOCAL)
def scan_web(path: Path) -> None:
    """Inspect local HTML, README or recorded search JSON. Never follows links."""
    try:
        report = inspect_web(path)
    except (EvidenceError, LoadError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(json.dumps(report, indent=2, ensure_ascii=True))


@click.command("domain-evidence")
@click.argument("domain")
@click.option(
    "--rdap", is_flag=True, help="Send the registrable domain to its supported registry over HTTPS."
)
@click.option(
    "--dns-record", type=_LOCAL, help="Local recorded DNS observation for the exact host."
)
@click.option("--history", type=_LOCAL, help="Trusted local prior registration observation.")
@click.option("--psl", type=_LOCAL, help="Local Public Suffix List snapshot (ICANN section).")
def domain_evidence(
    domain: str, rdap: bool, dns_record: Path | None, history: Path | None, psl: Path | None
) -> None:
    """Inspect one operator-named domain; offline unless --rdap is explicitly supplied."""
    try:
        report = inspect_domain(
            domain, consent=rdap, dns_record=dns_record, history=history, psl=psl
        )
    except (EvidenceError, LoadError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(json.dumps(report, indent=2, ensure_ascii=True))
