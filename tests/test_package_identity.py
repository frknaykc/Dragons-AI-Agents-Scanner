"""Registry provenance and package-advisory separation; all records synthetic."""

import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest
from click.testing import CliRunner

from dragonscan.intel_commands import tools
from dragonscan.models import Target
from dragonscan.osv import OSVClient, OSVProvider
from dragonscan.package_identity import PackageIdentity
from dragonscan.registry_evidence import inspect_registry
from dragonscan.scanner import Scanner
from dragonscan.vulnerability import Query


def test_private_registry_not_a_public_intelligence_match(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "sample==1.0\n--index-url https://private.invalid/simple\n"
    )
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "feed_id": "lab",
                "feed_version": "1",
                "records": [
                    {
                        "id": "sample",
                        "source": "Test",
                        "indicator_type": "package",
                        "ecosystem": "PyPI",
                        "version": "1.0",
                        "value": "sample",
                        "classification": "malicious",
                    }
                ],
            }
        )
    )
    report = Scanner(intel_feeds=(feed,)).scan(Target(tmp_path))
    assert not any(f.intelligence for f in report.findings)


@pytest.mark.parametrize(
    "identifier,extra",
    [
        ("MAL-0000-1", {}),
        ("GHSA-example", {"withdrawn": "2026-01-01T00:00:00Z"}),
        ("OSV-EXAMPLE", {"aliases": ["MAL-example"]}),
        (
            "OSV-OTHER",
            {
                "affected": [
                    {"package": {"ecosystem": "npm", "name": "sample"}, "versions": ["1.0.1"]}
                ]
            },
        ),
    ],
)
def test_malicious_or_withdrawn_osv_records_are_not_vulnerabilities(identifier, extra):
    query = Query("npm", "sample", "1.0.0")

    def transport(path, body):
        return json.dumps(
            {"results": [{"vulns": [{"id": identifier}]}]}
            if body
            else {
                "id": identifier,
                "affected": [
                    {"package": {"ecosystem": "npm", "name": "sample"}, "versions": ["1.0.0"]}
                ],
                **extra,
            }
        ).encode()

    result = OSVProvider(OSVClient(transport)).query((query,))
    assert result.matches[query] == ()


def test_registry_presence_absence_and_confusion_are_not_malicious_advisories(tmp_path):
    pkg = PackageIdentity("npm", "fixture", "1.0.0", "https://registry.npmjs.org")
    now = datetime.now(UTC)
    record = {
        "identity": asdict(pkg),
        "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "GET",
        "url": "https://registry.npmjs.org/fixture",
        "http_status": 200,
        "body": {"name": "fixture", "versions": {"1.0.0": {}}},
    }
    assert inspect_registry(pkg, record).status == "version_present"
    assert inspect_registry(pkg, {**record, "http_status": 404}).review_id == "DRAGON-SC-008"
    assert (
        inspect_registry(pkg, {**record, "body": {"name": "fixture", "versions": {}}}).review_id
        is None
    )
    assert inspect_registry(pkg, {**record, "http_status": 503}).status == "unknown"
    assert inspect_registry(pkg, record, now=now + timedelta(days=2)).status == "unknown"
    assert inspect_registry(replace(pkg, version="1.0.1"), record).status == "unknown"
    private = replace(pkg, registry="https://private.invalid")
    assert inspect_registry(private, {**record, "identity": asdict(private)}).status == "unknown"
    for intended in (private, replace(pkg, name="fixtuer")):
        assert inspect_registry(pkg, record, intended=intended).review_id is None
        assert (
            inspect_registry(pkg, record, resolved=pkg, intended=intended).review_id
            == "DRAGON-SC-009"
        )
    assert (
        inspect_registry(
            pkg, record, resolved=pkg, intended=replace(pkg, name="@other/fixture")
        ).review_id
        is None
    )
    path = tmp_path / "snapshot.json"
    args = [
        "registry-check",
        str(path),
        "--ecosystem",
        "npm",
        "--name",
        pkg.name,
        "--version",
        pkg.version,
        "--registry",
        pkg.registry,
    ]
    assert json.loads(CliRunner().invoke(tools, args).output)["status"] == "unknown"
    path.write_text(json.dumps(record))
    assert json.loads(CliRunner().invoke(tools, args).output)["status"] == "version_present"


@pytest.mark.parametrize(
    "what",
    ["requirements-port", "requirements-path", "unavailable", "uv", "npm-lock", "yarn", "mcp"],
)
def test_private_sources_never_reach_public_provider_or_match_feed(tmp_path, what):
    eco = (
        "PyPI" if what in {"requirements-port", "requirements-path", "unavailable", "uv"} else "npm"
    )
    if what in {"requirements-port", "requirements-path", "unavailable"}:
        url = {
            "requirements-port": "https://pypi.org:8844/simple",
            "requirements-path": "https://pypi.org/private",
            "unavailable": "not-a-registry",
        }[what]
        (tmp_path / "requirements.txt").write_text(f"sample==1.0.0\n--index-url={url}\n")
    elif what == "uv":
        (tmp_path / "uv.lock").write_text(
            'version=1\n[[package]]\nname="sample"\nversion="1.0.0"\nsource={registry="https://private.invalid/simple"}\n'
        )
    elif what == "npm-lock":
        (tmp_path / "package.json").write_text('{"dependencies":{"sample":"1.0.0"}}')
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/sample": {
                            "version": "1.0.0",
                            "resolved": "https://private.invalid/sample/-/sample-1.0.0.tgz",
                        }
                    },
                }
            )
        )
    elif what == "yarn":
        (tmp_path / "yarn.lock").write_text(
            '"sample@^1.0.0":\n  version "1.0.0"\n  resolved "https://private.invalid/sample/-/sample-1.0.0.tgz"\n'
        )
    else:
        (tmp_path / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "sample": {
                            "command": "npx",
                            "args": ["sample@1.0.0"],
                            "env": {"NPM_CONFIG_REGISTRY": "https://private.invalid"},
                        }
                    }
                }
            )
        )
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "feed_id": "lab",
                "feed_version": "1",
                "records": [
                    {
                        "id": "sample",
                        "indicator_type": "package",
                        "source": "Synthetic",
                        "classification": "malicious",
                        "value": "sample",
                        "ecosystem": eco,
                        "version": "1.0.0",
                    }
                ],
            }
        )
    )
    calls = []

    def transport(path, body):
        calls.append(path)
        return b'{"results":[]}'

    report = Scanner(
        vulnerability_provider=OSVProvider(OSVClient(transport)), intel_feeds=(feed,)
    ).scan(Target(tmp_path))
    assert not calls
    assert not any(f.intelligence or f.vulnerability for f in report.findings)


def test_npm_major_or_minor_selectors_are_not_exact_versions():
    for version in ("1", "1.2", "01.2.3"):
        with pytest.raises(ValueError):
            PackageIdentity("npm", "sample", version, "https://registry.npmjs.org")


def test_public_uv_lock_and_private_tarball_version_identity(tmp_path):
    from dragonscan.package_identity import registry_label

    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="Sam_ple"\nversion="1.2.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    payloads = []

    def transport(path, body):
        payloads.append(json.loads(body))
        return b'{"results":[{}]}'

    Scanner(vulnerability_provider=OSVProvider(OSVClient(transport))).scan(Target(tmp_path))
    assert payloads == [
        {"queries": [{"package": {"name": "sam-ple", "ecosystem": "PyPI"}, "version": "1.2.0"}]}
    ]
    url = "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz"
    assert (
        registry_label(url, "npm", tarball="sample", version="1.0.0")
        == "https://registry.npmjs.org"
    )
    assert registry_label(url, "npm", tarball="sample", version="1.0.1") == "unknown-registry"
