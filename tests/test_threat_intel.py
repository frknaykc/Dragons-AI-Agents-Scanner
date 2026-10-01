"""Untrusted, optional intelligence stays data, never scan or network authority."""

import hashlib
import json
import socket
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from dragonscan.cli import main
from dragonscan.models import Target
from dragonscan.reporting import json_report, terminal_report
from dragonscan.sarif import sarif_report
from dragonscan.scanner import Scanner
from dragonscan.threat_intel import FeedError, parse_feed, update_feed


def feed(*records: dict[str, object], feed_id: str = "synthetic") -> bytes:
    return json.dumps(
        {"schema_version": 1, "feed_id": feed_id, "feed_version": "1.0", "records": records}
    ).encode()


def record(kind: str, value: str, **extra: object) -> dict[str, object]:
    return {
        "id": "test-1",
        "indicator_type": kind,
        "value": value,
        "classification": "malicious",
        "source": "Synthetic Test",
        **extra,
    }


def test_feed_validation():
    valid = parse_feed(feed(record("domain", "MALICIOUS.EXAMPLE.TEST")))
    assert valid.records[0].value == "malicious.example.test"
    failures = [
        b"{broken",
        feed(record("domain", "malicious.example.test")).replace(
            b'"schema_version": 1', b'"schema_version": 2'
        ),
        feed(record("domain", "not a host")),
        feed(record("unknown", "x")),
        feed(record("domain", "malicious.example.test", classification="unknown")),
        feed(record("domain", "malicious.example.test", source="\x1b[31m")),
        feed(record("domain", "malicious.example.test", description="x" * 300)),
        feed(record("package", "bad", ecosystem="npm")),
        feed(record("sha256", "a" * 63)),
        feed(record("sha1", "a" * 40)),
        feed(record("ipv6", "not-an-address")),
        feed(record("domain", "malicious.example.test", update_url="https://example.test")),
        feed(record("domain", "malicious.example.test"), record("domain", "other.example.test")),
        feed(
            record("domain", "malicious.example.test"),
            {**record("domain", "malicious.example.test"), "id": "test-2"},
        ),
        feed(record("domain", "malicious.example.test"), feed_id="../escape"),
        feed(record("domain", "malicious.example.test"), feed_id="AKIAABCDEFGHIJKLMNOP"),
        feed(record("domain", "malicious.example.test", id="ghp_abcdefghijklmnopqrst")),
        b"{" + b" " * 1_048_576,
    ]
    for raw in failures:
        with pytest.raises(FeedError):
            parse_feed(raw)
    many = feed(
        *(
            {**record("domain", f"host-{index}.example.test"), "id": f"item-{index}"}
            for index in range(513)
        )
    )
    with pytest.raises(FeedError, match="record count"):
        parse_feed(many)


def test_exact_matches_provenance_and_no_flow(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Contact https://malicious.example.test/path and 8.8.8.8\n")
    digest = hashlib.sha256(skill.read_text().encode()).hexdigest()
    items = [
        record("domain", "malicious.example.test"),
        {**record("url", "https://malicious.example.test/path"), "id": "test-2"},
        {**record("ipv4", "8.8.8.8"), "id": "test-3"},
        {**record("sha256", digest, artifact_kind="skill"), "id": "test-4"},
        {**record("domain", "not-malicious.example.test"), "id": "test-5"},
    ]
    local = tmp_path / "local.json"
    local.write_bytes(feed(*items))
    second = tmp_path / "second.json"
    second.write_bytes(
        feed({**items[0], "id": "other-1", "classification": "suspicious"}, feed_id="second")
    )
    report = Scanner(intel_feeds=(second, local)).scan(Target(skill))
    reversed_report = Scanner(intel_feeds=(local, second)).scan(Target(skill))
    ti = [finding for finding in report.findings if finding.detection_id == "DRAGON-TI-001"]
    assert [(item.evidence, item.intelligence) for item in ti] == [
        (item.evidence, item.intelligence)
        for item in reversed_report.findings
        if item.detection_id == "DRAGON-TI-001"
    ]
    assert {item.intelligence.indicator_type for item in ti if item.intelligence} == {
        "domain",
        "url",
        "ipv4",
        "sha256",
    }
    domain = next(
        item for item in ti if item.intelligence and item.intelligence.indicator_type == "domain"
    )
    assert len(domain.intelligence.sources) == 2
    assert domain.severity == next(
        item.severity
        for item in reversed_report.findings
        if item.intelligence and item.intelligence.indicator_type == "domain"
    )
    assert all(not item.path and not item.taint and not item.flow for item in ti)
    assert not any("not-malicious" in item.evidence for item in ti)


def test_intelligence_candidate_limit_is_reported_as_partial(tmp_path: Path, monkeypatch):
    from dragonscan import signature_ioc

    skill = tmp_path / "SKILL.md"
    skill.write_text("Contact malicious.example.test for details.\n")
    local = tmp_path / "local.json"
    local.write_bytes(feed(record("domain", "malicious.example.test")))
    original = signature_ioc.collect_candidates

    def limited(kind, text):
        values, _ = original(kind, text)
        return values, True

    monkeypatch.setattr("dragonscan.threat_intel.collect_candidates", limited)
    report = Scanner(intel_feeds=(local,)).scan(Target(skill))
    assert report.intelligence_status == "partial"
    assert "intelligence IOC candidate limit reached" in report.intelligence_diagnostics


def test_intelligence_hit_limit_is_reported_as_partial(tmp_path: Path, monkeypatch):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Contact first.example.test and second.example.test.\n")
    local = tmp_path / "local.json"
    local.write_bytes(
        feed(
            record("domain", "first.example.test"),
            {**record("domain", "second.example.test"), "id": "test-2"},
        )
    )
    monkeypatch.setattr("dragonscan.threat_intel.MAX_MATCHES", 1)
    report = Scanner(intel_feeds=(local,)).scan(Target(skill))
    assert report.intelligence_status == "partial"
    assert "intelligence hit limit reached" in report.intelligence_diagnostics


def test_package_identity_exact_ecosystem_and_version(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"name":"example", "dependencies":{"bad-example":"1.2.3"}}')
    records = [
        record("package", "bad-example", ecosystem="npm", version="1.2.3"),
        {**record("package", "bad-example", ecosystem="PyPI", version="1.2.3"), "id": "test-2"},
        {**record("package", "bad-example", ecosystem="npm", version="1.2.4"), "id": "test-3"},
    ]
    local = tmp_path / "intel.json"
    local.write_bytes(feed(*records))
    report = Scanner(intel_feeds=(local,)).scan(Target(manifest))
    ti = [item for item in report.findings if item.detection_id == "DRAGON-TI-001"]
    assert len(ti) == 1
    assert ti[0].intelligence and ti[0].intelligence.sources[0].record_id == "test-1"


def test_mcp_version_and_display_name_are_not_execution_authority(tmp_path: Path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bad-example": {"command": "npx", "args": ["bad-example@1.2.3"]},
                    "different": {"command": "npx", "args": ["bad-example@1.2.4"]},
                    "unversioned": {"command": "npx", "args": ["bad-example"]},
                }
            }
        )
    )
    local = tmp_path / "feed.json"
    local.write_bytes(feed(record("package", "bad-example", ecosystem="npm", version="1.2.3")))
    with patch("dragonscan.dynamic_mcp.inspect", side_effect=AssertionError("execution")):
        report = Scanner(intel_feeds=(local,)).scan(Target(config))
    matches = [item for item in report.findings if item.intelligence]
    assert len(matches) == 1
    assert matches[0].intelligence.context == "mcp_package"
    assert not matches[0].flow and not matches[0].taint


def test_ipv6_hostname_and_no_substring_or_url_prefix(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "Connect [2001:db8::1], api.example.test and https://other.example.test/path/child"
    )
    local = tmp_path / "feed.json"
    local.write_bytes(
        feed(
            record("ipv6", "2001:0db8::1"),
            {**record("hostname", "api.example.test"), "id": "test-2"},
            {**record("hostname", "example.test"), "id": "test-3"},
            {**record("url", "https://example.test/path"), "id": "test-4"},
        )
    )
    results = [
        item.intelligence
        for item in Scanner(intel_feeds=(local,)).scan(Target(skill)).findings
        if item.intelligence
    ]
    assert {(item.indicator_type, item.indicator) for item in results} == {
        ("ipv6", "2001:db8::1"),
        ("hostname", "api.example.test"),
    }


def test_hash_matches_raw_bytes_including_bom(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"\xef\xbb\xbfhello")
    local = tmp_path / "feed.json"
    local.write_bytes(
        feed(
            record("sha256", hashlib.sha256(skill.read_bytes()).hexdigest(), artifact_kind="skill")
        )
    )
    assert any(
        item.intelligence for item in Scanner(intel_feeds=(local,)).scan(Target(skill)).findings
    )


def test_hash_and_skill_filename_are_not_text_or_name_only_matches(tmp_path: Path):
    digest = "a" * 64
    skill = tmp_path / "SKILL.md"
    skill.write_text(f"Hash {digest} and {digest[:16]} in the prose; not the file digest")
    local = tmp_path / "feed.json"
    local.write_bytes(feed(record("sha256", digest, artifact_kind="skill")))
    assert not any(
        item.intelligence for item in Scanner(intel_feeds=(local,)).scan(Target(skill)).findings
    )


def test_update_atomic_and_offline_scan(tmp_path: Path):
    store = tmp_path / "store"
    old = feed(record("domain", "old.example.test"))
    new = feed(record("domain", "malicious.example.test"))
    store.mkdir()
    (store / "intel.json").write_bytes(old)
    sha = hashlib.sha256(new).hexdigest()

    def download(_url: str, dest: Path, *, max_bytes: int) -> str:
        assert max_bytes <= 1_048_576
        dest.write_bytes(new)
        return "https://public.example.test/feed.json"

    with patch("dragonscan.threat_intel._download", side_effect=download):
        with pytest.raises(FeedError):
            update_feed("https://public.example.test/feed.json", "0" * 64, store)
        assert (store / "intel.json").read_bytes() == old
        update_feed("https://public.example.test/feed.json", sha, store)
    assert (store / "intel.json").read_bytes() == new
    skill = tmp_path / "SKILL.md"
    skill.write_text("Connect to malicious.example.test")
    with patch("dragonscan.threat_intel._download", side_effect=AssertionError("network")):
        assert any(
            item.intelligence for item in Scanner(intel_store=store).scan(Target(skill)).findings
        )
        assert not any(item.intelligence for item in Scanner().scan(Target(skill)).findings)
    (store / "intel.json").write_bytes(b"invalid")
    report = Scanner(intel_store=store).scan(Target(skill))
    assert report.intelligence_status == "partial" and report.artifacts
    assert not any(item.intelligence for item in report.findings)
    result = CliRunner().invoke(
        main, ["scan", str(skill), "--intel-store", str(store), "--fail-on", "low"]
    )
    assert result.exit_code == 3


def test_update_rejects_private_url_without_network(tmp_path: Path):
    with patch("socket.create_connection", side_effect=AssertionError("network")):
        with pytest.raises(FeedError):
            update_feed("https://127.0.0.1/intel.json", "a" * 64, tmp_path / "store")


def test_update_redirect_private_and_size_bound_preserve_old_feed(tmp_path: Path):
    store = tmp_path / "store"
    store.mkdir()
    old = feed(record("domain", "old.example.test"))
    (store / "intel.json").write_bytes(old)
    response = Mock(status=302)
    response.getheader.return_value = "https://127.0.0.1/private"
    connection = Mock()
    connection.getresponse.return_value = response
    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    with patch("dragonscan.target_acquisition.socket.getaddrinfo", return_value=public):
        with patch("dragonscan.target_acquisition._PinnedHTTPS", return_value=connection) as pinned:
            with pytest.raises(FeedError):
                update_feed("https://public.example.test/feed", "a" * 64, store)
    assert pinned.call_count == 1
    response.status = 200
    response.getheader.return_value = "1048577"
    with patch("dragonscan.target_acquisition.socket.getaddrinfo", return_value=public):
        with patch("dragonscan.target_acquisition._PinnedHTTPS", return_value=connection):
            with pytest.raises(FeedError):
                update_feed("https://public.example.test/feed", "a" * 64, store)
    assert (store / "intel.json").read_bytes() == old


@pytest.mark.parametrize("mode", ["no_length", "false_small", "truncated", "oversized", "failure"])
def test_streamed_update_is_bounded_and_cleans_partial_candidates(tmp_path: Path, mode: str):
    store = tmp_path / "store"
    store.mkdir()
    old = feed(record("domain", "old.example.test"))
    fresh = feed(record("domain", "new.example.test"))
    (store / "intel.json").write_bytes(old)
    response = Mock(status=200)
    size = {"no_length": None, "false_small": "1", "truncated": str(len(fresh) + 1)}
    response.getheader.side_effect = lambda name: (
        size.get(mode) if name == "Content-Length" else None
    )
    response.read1.side_effect = [b"x" * 1_048_577, b""] if mode == "oversized" else [fresh, b""]
    connection = Mock()
    connection.getresponse.side_effect = OSError("synthetic failure") if mode == "failure" else None
    connection.getresponse.return_value = response
    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    with patch("dragonscan.target_acquisition.socket.getaddrinfo", return_value=public):
        with patch("dragonscan.target_acquisition._PinnedHTTPS", return_value=connection):
            if mode == "no_length":
                update_feed(
                    "https://public.example.test/feed", hashlib.sha256(fresh).hexdigest(), store
                )
            else:
                with pytest.raises(FeedError):
                    update_feed(
                        "https://public.example.test/feed", hashlib.sha256(fresh).hexdigest(), store
                    )
    assert (store / "intel.json").read_bytes() == (fresh if mode == "no_length" else old)
    assert sorted(item.name for item in store.iterdir()) == ["intel.json"]


def test_update_downgrade_and_permissions(tmp_path: Path):
    store = tmp_path / "store"
    store.mkdir()
    installed = feed(record("domain", "old.example.test"))
    (store / "intel.json").write_bytes(
        installed.replace(b'"feed_version": "1.0"', b'"feed_version": "2.0"')
    )
    fresh = feed(record("domain", "new.example.test"))
    with patch(
        "dragonscan.threat_intel._download",
        side_effect=lambda _url, dest, **_: dest.write_bytes(fresh),
    ):
        with pytest.raises(FeedError, match="downgrade"):
            update_feed(
                "https://public.example.test/intel.json", hashlib.sha256(fresh).hexdigest(), store
            )
    assert b"old.example.test" in (store / "intel.json").read_bytes()


def test_update_rejects_symlink_store_and_invalid_feed(tmp_path: Path):
    store = tmp_path / "store"
    store.mkdir()
    old = feed(record("domain", "old.example.test"))
    (store / "intel.json").write_bytes(old)

    def download(_url: str, dest: Path, *, max_bytes: int) -> str:
        dest.write_bytes(b"not json")
        return "https://public.example.test/feed.json"

    with patch("dragonscan.threat_intel._download", side_effect=download):
        with pytest.raises(FeedError):
            update_feed(
                "https://public.example.test/feed.json",
                hashlib.sha256(b"not json").hexdigest(),
                store,
            )
    assert (store / "intel.json").read_bytes() == old
    link = tmp_path / "link"
    link.symlink_to(store, target_is_directory=True)
    with pytest.raises(FeedError):
        update_feed("https://public.example.test/feed.json", "a" * 64, link)


def test_cli_opt_in_reporting_and_gate(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Connect to malicious.example.test")
    local = tmp_path / "feed.json"
    local.write_bytes(feed(record("domain", "malicious.example.test")))
    runner = CliRunner()
    base = runner.invoke(main, ["scan", str(skill), "--format", "json"])
    assert base.exit_code == 0 and "threat_intelligence" not in base.output
    result = runner.invoke(
        main, ["scan", str(skill), "--intel", str(local), "--format", "json", "--fail-on", "low"]
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["threat_intelligence"]["matches"] == 1
    sarif = runner.invoke(main, ["scan", str(skill), "--intel", str(local), "--format", "sarif"])
    assert any(
        item["ruleId"] == "DRAGON-TI-001" for item in json.loads(sarif.output)["runs"][0]["results"]
    )


def test_one_fact_per_indicator_and_line_with_sarif_provenance(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Fetch https://malicious.example.test/path\n")
    local = tmp_path / "feed.json"
    local.write_bytes(feed(record("domain", "malicious.example.test")))
    report = Scanner(intel_feeds=(local,)).scan(Target(skill))
    hits = [finding for finding in report.findings if finding.intelligence]
    assert len(hits) == 1
    assert hits[0].intelligence and hits[0].intelligence.context == "remote_endpoint"
    sarif = CliRunner().invoke(
        main, ["scan", str(skill), "--intel", str(local), "--format", "sarif"]
    )
    results = json.loads(sarif.output)["runs"][0]["results"]
    intelligence = next(item for item in results if item["ruleId"] == "DRAGON-TI-001")
    provenance = intelligence["properties"]["threatIntelligence"]["sources"][0]
    assert provenance["source"] == "Synthetic Test"


def test_reused_scanner_reloads_installed_feed_without_ghost_matches(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Contact old.example.test or new.example.test")
    store = tmp_path / "store"
    store.mkdir()
    installed = store / "intel.json"
    installed.write_bytes(feed(record("domain", "old.example.test")))
    scanner = Scanner(intel_store=store)

    def matched() -> list[str]:
        return [
            f.intelligence.indicator
            for f in scanner.scan(Target(skill)).findings
            if f.intelligence is not None
        ]

    assert matched() == ["old.example.test"]
    installed.write_bytes(feed(record("domain", "new.example.test")))
    assert matched() == ["new.example.test"]
    installed.unlink()
    missing = scanner.scan(Target(skill))
    assert missing.intelligence_status == "partial"
    assert not any(f.intelligence for f in missing.findings)
    installed.write_bytes(b"invalid")
    corrupt = scanner.scan(Target(skill))
    assert corrupt.intelligence_status == "partial"
    assert not any(f.intelligence for f in corrupt.findings)


@pytest.mark.parametrize(
    "source, secret",
    [
        ("https://user:password@example.test/report?token=SECRET", "SECRET"),
        ("https://example.test/report?key=PRIVATE", "PRIVATE"),
        ("Bearer example-private-token", "example-private-token"),
        ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("Source AKIAABCDEFGHIJKLMNOP. review", "AKIAABCDEFGHIJKLMNOP"),
    ],
)
def test_untrusted_source_metadata_does_not_leak_to_reports(
    tmp_path: Path, source: str, secret: str
):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Contact malicious.example.test")
    local = tmp_path / "feed.json"
    local.write_bytes(feed(record("domain", "malicious.example.test", source=source)))
    report = Scanner(intel_feeds=(local,)).scan(Target(skill))
    assert any(f.intelligence for f in report.findings)
    for output in (terminal_report(report), json_report(report), sarif_report(report)):
        assert secret not in output


def test_feed_match_does_not_change_base_graph_semantic_or_sarif_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Connect to malicious.example.test\n\nContact malicious.example.test again\n")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(feed(record("domain", "malicious.example.test"), feed_id="first"))
    second.write_bytes(
        feed(
            record("domain", "malicious.example.test", classification="suspicious"),
            feed_id="second",
        )
    )
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: pytest.fail("network"))
    monkeypatch.setattr(
        "dragonscan.threat_intel._download", lambda *_args, **_kwargs: pytest.fail("update")
    )
    base_scanner = Scanner()
    base = base_scanner.scan(Target(skill))
    enabled_scanner = Scanner(intel_feeds=(second, first))
    enabled = enabled_scanner.scan(Target(skill))
    assert enabled.findings[: len(base.findings)] == base.findings
    assert base_scanner.graph == enabled_scanner.graph
    assert enabled.semantic_status == base.semantic_status == "disabled"
    assert enabled.dynamic_status == base.dynamic_status == "not_requested"
    hits = [finding for finding in enabled.findings if finding.intelligence]
    assert len(hits) == 2
    assert {hit.line for hit in hits} == {1, 3}
    assert all(len(hit.intelligence.sources) == 2 for hit in hits if hit.intelligence)
    assert all(hit.severity == hits[0].severity for hit in hits)
    assert all(not hit.taint and not hit.flow and not hit.path for hit in hits)
    other = Scanner(intel_feeds=(first, second)).scan(Target(skill))
    assert sarif_report(enabled) == sarif_report(other)
    ti_rule = next(
        rule
        for rule in json.loads(sarif_report(enabled))["runs"][0]["tool"]["driver"]["rules"]
        if rule["id"] == "DRAGON-TI-001"
    )
    assert "first" not in json.dumps(ti_rule) and "second" not in json.dumps(ti_rule)
