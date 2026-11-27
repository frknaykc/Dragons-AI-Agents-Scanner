"""Offline intelligence commands. Also usable as python -m dragonscan.intel_commands."""

import json
from dataclasses import asdict
from pathlib import Path

import click

from dragonscan.intel_store import FeedError, read_bounded
from dragonscan.package_identity import PackageIdentity
from dragonscan.registry_evidence import _identity, inspect_registry
from dragonscan.signed_intel import _object, install_signed, read_release

_PATH = click.Path(path_type=Path)


@click.group()
def tools() -> None:
    """Manage explicit local intelligence and review saved registry observations."""


@tools.command("install-signed")
@click.option("--feed", type=_PATH, required=True)
@click.option("--signature", type=_PATH, required=True)
@click.option("--signer", required=True)
@click.option("--trust", type=_PATH, required=True)
@click.option("--store", type=_PATH, required=True)
def install(feed: Path, signature: Path, signer: str, trust: Path, store: Path) -> None:
    """Verify and atomically install a local signed release."""
    try:
        loaded = install_signed(feed, signature, signer, trust, store)
    except FeedError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"Installed {loaded.id} {loaded.version}; signer={loaded.signer} sha256={loaded.sha256}"
    )


@tools.command("verify")
@click.argument("release", type=_PATH)
@click.option("--trust", type=_PATH, required=True)
def verify(release: Path, trust: Path) -> None:
    """Recheck a stored signed release against the current policy and clock."""
    try:
        feed = read_release(release, trust)
        if not feed.signer:
            raise FeedError("unsigned release")
    except FeedError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Verified {feed.id} {feed.version}; signer={feed.signer} sha256={feed.sha256}")


@tools.command("registry-check")
@click.argument("snapshot", type=_PATH)
@click.option("--ecosystem", type=click.Choice(["PyPI", "npm"]), required=True)
@click.option("--name", required=True)
@click.option("--version", required=True)
@click.option("--registry", required=True)
@click.option("--intended", type=_PATH, help="Independent intended package identity (local JSON).")
@click.option("--resolved", type=_PATH, help="Identity from reviewed lock provenance (local JSON).")
def registry_check(
    snapshot: Path,
    ecosystem: str,
    name: str,
    version: str,
    registry: str,
    intended: Path | None,
    resolved: Path | None,
) -> None:
    """Compare one exact identity to an explicit, saved registry observation."""

    def identity(path: Path | None) -> PackageIdentity | None:
        if path is None:
            return None
        data = _identity(_object(read_bounded(path, 8192)))
        if data is None:
            raise FeedError("invalid package identity")
        return data

    try:
        query = PackageIdentity(ecosystem, name, version, registry)
        try:
            observation = _object(read_bounded(snapshot, 8192))
        except FeedError:
            observation = {}  # unavailable/malformed is unknown, never registry absence
        result = inspect_registry(
            query, observation, intended=identity(intended), resolved=identity(resolved)
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(result), sort_keys=True))


if __name__ == "__main__":
    tools()
