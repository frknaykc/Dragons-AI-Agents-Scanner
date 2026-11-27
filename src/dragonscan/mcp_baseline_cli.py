"""Explicit MCP snapshot workflows, separate from static scan and process consent."""

import json
from pathlib import Path

import click

from dragonscan.mcp_baseline import BaselineError, baseline


@click.group("mcp-baseline")
def mcp_baseline() -> None:
    """Review, approve, or compare local JSON MCP declarations without launching anything."""


def _emit(action: str, config: Path, digest: str = "") -> None:
    try:
        result = baseline(action, config, digest)
    except BaselineError as exc:
        result = {"status": "partial", "reason": str(exc)}
    except FileNotFoundError:
        result = {"status": "partial", "reason": "source or approved snapshot missing"}
    except OSError:
        result = {"status": "partial", "reason": "protected local file unavailable"}
    click.echo(json.dumps(result, sort_keys=True, ensure_ascii=True))
    raise click.exceptions.Exit({"partial": 3, "changed": 1}.get(result["status"], 0))


@mcp_baseline.command()
@click.argument("config", type=click.Path(path_type=Path))
def review(config: Path) -> None:
    """Print the source-qualified candidate and digest; do not approve it."""
    _emit("review", config)


@mcp_baseline.command()
@click.argument("config", type=click.Path(path_type=Path))
@click.option("--digest", required=True, help="Exact digest of the reviewed candidate.")
def approve(config: Path, digest: str) -> None:
    """Save this exact candidate as the operator-approved snapshot."""
    _emit("approve", config, digest)


@mcp_baseline.command()
@click.argument("config", type=click.Path(path_type=Path))
def compare(config: Path) -> None:
    """Compare without writing. Exit 1 for drift, 3 for missing coverage."""
    _emit("compare", config)
