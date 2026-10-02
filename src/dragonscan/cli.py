"""CLI adapter; scan and reporting remain usable without Click."""

import os
import tempfile
from dataclasses import replace
from pathlib import Path

import click

from dragonscan.discovery import DiscoveryError
from dragonscan.dynamic_mcp import DynamicPolicy
from dragonscan.models import ScanReport, Severity, Target
from dragonscan.policy import evaluate
from dragonscan.reporting import json_report, sarif_report, terminal_report
from dragonscan.scanner import Scanner
from dragonscan.scanner import scan as scan_target
from dragonscan.semantic_provider import OpenAICompatibleProvider
from dragonscan.target_acquisition import AcquisitionCleanupError, acquire
from dragonscan.threat_intel import FeedError, update_feed


@click.group()
def main() -> None:
    """Scan local AI agent artifacts; execution requires separate MCP consent."""


@main.group()
def intel() -> None:
    """Manage optional intelligence; scans never update feeds."""


@intel.command("update")
@click.option("--url", required=True, help="Explicit public HTTPS feed URL.")
@click.option(
    "--sha256",
    required=True,
    help="Operator-supplied expected SHA-256 digest (not publisher authentication).",
)
@click.option("--store", type=click.Path(path_type=Path), required=True)
def intel_update(url: str, sha256: str, store: Path) -> None:
    """Verify and atomically install a feed without submitting scan data."""
    try:
        feed = update_feed(url, sha256, store)
    except FeedError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(f"Installed feed {feed.id} version {feed.version} ({len(feed.records)} records)")


@main.command()
@click.argument("path", required=False)
@click.option(
    "--remote", is_flag=True, help="Explicitly download one public HTTPS artifact; network access."
)
@click.option(
    "--git",
    "git_target",
    is_flag=True,
    help="Scan a local Git working tree; remote Git is unavailable.",
)
@click.option(
    "--installed-agents", is_flag=True, help="Scan bounded known local agent environments"
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--fail-on",
    type=click.Choice([level.value for level in Severity]),
    default=None,
    help="Opt in to exit 1 on findings at or above this severity.",
)
@click.option(
    "--fail-on-incomplete",
    is_flag=True,
    help="Also fail on partial installed-agent resolution and semantic candidate coverage.",
)
@click.option(
    "--output", type=click.Path(path_type=Path), help="Atomically write the report to a file."
)
@click.option(
    "--signature-pack",
    type=click.Path(path_type=Path),
    default=None,
    help="Load static JSON signatures from an explicit local directory.",
)
@click.option(
    "--intel",
    "intel_feeds",
    multiple=True,
    type=click.Path(path_type=Path),
    help="Explicit local intelligence JSON (repeatable).",
)
@click.option(
    "--intel-store",
    type=click.Path(path_type=Path),
    help="Use an explicitly selected offline intelligence store.",
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
@click.option(
    "--dynamic-mcp",
    is_flag=True,
    help="Request local stdio MCP metadata inspection (blocked without required isolation).",
)
@click.option(
    "--allow-uncontained-mcp",
    is_flag=True,
    help=(
        "Legacy uncontained execution: consent to running code WITHOUT network "
        "or filesystem sandboxing."
    ),
)
@click.option("--dynamic-mcp-server", help="Exact declared server name (must be unique).")
@click.option(
    "--dynamic-mcp-executable",
    type=click.Path(path_type=Path),
    help="Exact absolute executable path in the MCP config.",
)
def scan(
    path: str | None,
    remote: bool,
    git_target: bool,
    installed_agents: bool,
    output_format: str,
    fail_on: str | None,
    fail_on_incomplete: bool,
    output: Path | None,
    signature_pack: Path | None,
    intel_feeds: tuple[Path, ...],
    intel_store: Path | None,
    vuln_check: bool,
    semantic: bool,
    semantic_url: str | None,
    semantic_model: str | None,
    dynamic_mcp: bool,
    allow_uncontained_mcp: bool,
    dynamic_mcp_server: str | None,
    dynamic_mcp_executable: Path | None,
) -> None:
    """Scan a local file, directory, or archive; remote access requires --remote."""
    if path is None and not installed_agents:
        raise click.UsageError("PATH is required unless --installed-agents is set")
    if installed_agents and dynamic_mcp:
        raise click.UsageError("--dynamic-mcp cannot be combined with --installed-agents")
    if installed_agents and (vuln_check or semantic):
        raise click.UsageError("network enrichment cannot be combined with --installed-agents")
    if remote and (installed_agents or dynamic_mcp):
        raise click.UsageError(
            "--remote cannot be combined with --installed-agents or --dynamic-mcp"
        )
    if git_target and (installed_agents or dynamic_mcp):
        raise click.UsageError("--git cannot be combined with --installed-agents or --dynamic-mcp")
    if remote and path is None:
        raise click.UsageError("--remote requires a target URL")
    if path is not None and "://" in path and not remote:
        raise click.UsageError("network targets require --remote")
    if remote and path is not None and not path.startswith("https://"):
        raise click.UsageError("--remote supports HTTPS targets only")
    local_path = Path(path) if path is not None else None
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
    report: ScanReport | None = None
    try:
        if vuln_check:
            from dragonscan.osv import OSVProvider

            scanner = Scanner(
                signature_pack=signature_pack,
                vulnerability_provider=OSVProvider(),
                semantic_provider=provider,
                dynamic_policy=dynamic_policy,
                intel_feeds=intel_feeds,
                intel_store=intel_store,
            )
        elif (
            signature_pack is None
            and provider is None
            and not dynamic_mcp
            and not intel_feeds
            and intel_store is None
        ):
            scanner = Scanner()
        else:
            scanner = Scanner(
                signature_pack=signature_pack,
                semantic_provider=provider,
                dynamic_policy=dynamic_policy,
                intel_feeds=intel_feeds,
                intel_store=intel_store,
            )
        if installed_agents:
            report = scanner.scan_installed(Target(local_path) if local_path is not None else None)
        else:
            assert path is not None
            assert local_path is not None
            if (
                remote
                or git_target
                or (
                    path.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz"))
                    and not local_path.is_dir()
                )
            ):
                with acquire(path, remote=remote, git=git_target) as acquired:
                    report = scanner.scan_acquired(acquired)
            else:
                report = (
                    scan_target(Target(local_path))
                    if signature_pack is None
                    and provider is None
                    and not dynamic_mcp
                    and not vuln_check
                    and not intel_feeds
                    and intel_store is None
                    else scanner.scan(Target(local_path))
                )
    except AcquisitionCleanupError:
        if report is None:
            report = ScanReport(
                local_path or Path.home(),
                (),
                (),
                acquisition_status="failed",
                acquisition_diagnostics=("acquisition workspace cleanup failed",),
            )
        else:
            report = replace(
                report,
                acquisition_status="partial",
                acquisition_diagnostics=report.acquisition_diagnostics
                + ("acquisition workspace cleanup failed",),
            )
    except DiscoveryError as exc:
        report = ScanReport(local_path or Path.home(), (), (), (str(exc),))
    except Exception:
        # A scanner/provider bug must not look like a finding-policy failure or clean scan.
        # Do not serialize exception text: provider errors may contain secrets.
        report = ScanReport(local_path or Path.home(), (), (), ("Scanner execution failed",))
    policy = evaluate(
        report,
        Severity(fail_on) if fail_on is not None else None,
        fail_on_incomplete=fail_on_incomplete,
    )
    text = (
        json_report(report, policy)
        if output_format == "json"
        else sarif_report(report, policy)
        if output_format == "sarif"
        else terminal_report(report, policy)
    )
    if output is None:
        click.echo(text)
    else:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=output.parent, prefix=".dragonscan-", delete=False
            ) as handle:
                temporary = Path(handle.name)
                handle.write(text + "\n")
            os.replace(temporary, output)
        except OSError:
            click.echo("Report output failed", err=True)
            raise SystemExit(3) from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    if policy.exit_code:
        raise SystemExit(policy.exit_code)
