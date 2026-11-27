"""Local-only authenticated release and advisory authority regressions."""

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan.dynamic_mcp import _prelaunch_denial
from dragonscan.intel_commands import tools
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    Dependency,
    Document,
    Severity,
    SourceFormat,
    SourceRef,
    Target,
)
from dragonscan.policy import evaluate
from dragonscan.scanner import Scanner
from dragonscan.signed_intel import NAMESPACE, install_signed, read_release
from dragonscan.threat_intel import FeedError, Matcher, load_feeds, update_feed


def release(version="1", **fields):
    return json.dumps(
        {"schema_version": 1, "feed_id": "lab", "feed_version": version, "records": [], **fields}
    ).encode()


def test_legacy_same_version_changed_bytes_preserves_existing(tmp_path, monkeypatch):
    store = tmp_path / "store"
    store.mkdir()
    original = release()
    (store / "intel.json").write_bytes(original)
    changed = original + b"\n"
    monkeypatch.setattr(
        "dragonscan.threat_intel._download", lambda url, dest, **kw: dest.write_bytes(changed)
    )
    with pytest.raises(FeedError, match="same version"):
        update_feed("https://feed.invalid", hashlib.sha256(changed).hexdigest(), store)
    assert (store / "intel.json").read_bytes() == original


def test_raw_feed_cannot_assert_reviewed_authority(tmp_path: Path):
    artifact = tmp_path / "SKILL.md"
    artifact.write_text("Sample documentation.")
    record = {
        "id": "sample",
        "source": "Test",
        "indicator_type": "sha256",
        "value": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "classification": "malicious",
        "trust": "operator_reviewed",
    }
    local = tmp_path / "feed.json"
    local.write_bytes(release(records=[record]))
    report = Scanner(intel_feeds=(local,)).scan(Target(artifact))
    hits = [f for f in report.findings if f.intelligence]
    assert len(hits) == 1
    assert hits[0].intelligence is not None
    assert hits[0].intelligence.sources[0].trust == "unverified"


@pytest.fixture
def signing_lab(tmp_path):
    ssh = Path("/usr/bin/ssh-keygen")
    if os.name != "posix" or not ssh.is_file():
        pytest.skip("requires POSIX OpenSSH for synthetic signature integration")
    key = tmp_path / "fixture-key"

    def run(*args):
        subprocess.run(
            [str(ssh), *args],
            check=True,
            cwd=tmp_path,
            env={"LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

    run("-q", "-t", "ed25519", "-C", "fixture", "-N", "", "-f", str(key))
    pub = " ".join(key.with_suffix(".pub").read_text().split()[:2])
    policy = {"keys": {"issuer": pub}, "feeds": {"lab": ["issuer"]}, "revoked": []}
    trust = tmp_path / "policy.json"
    trust.write_text(json.dumps(policy))
    candidate = tmp_path / "candidate.json"
    sig = candidate.with_suffix(".json.sig")
    expires = (datetime.now(UTC) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(version="2", **fields):
        candidate.write_bytes(release(version, **{"expires": expires, **fields}))
        sig.unlink(missing_ok=True)
        run("-Y", "sign", "-n", NAMESPACE, "-f", str(key), str(candidate))

    sign()
    return candidate, sig, trust, sign


@pytest.mark.parametrize(
    "change",
    [
        "tampered",
        "revoked",
        "wrong_feed",
        "missing_expiry",
        "expired",
        "rollback",
        "changed",
        "legacy",
    ],
)
def test_signed_invalid_updates_preserve_last_release(tmp_path, monkeypatch, signing_lab, change):
    candidate, sig, trust, sign = signing_lab
    store = tmp_path / "installed"
    old = install_signed(candidate, sig, "issuer", trust, store)
    dest = store / "intel.json"
    previous = dest.read_bytes()
    assert old.sha256 == hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert read_release(dest, trust) == old
    assert install_signed(candidate, sig, "issuer", trust, store) == old
    if change == "tampered":
        candidate.write_bytes(candidate.read_bytes() + b"\n")
    elif change == "revoked":
        policy = json.loads(trust.read_bytes())
        policy["revoked"] = ["issuer"]
        trust.write_text(json.dumps(policy))
        with pytest.raises(FeedError):
            read_release(dest, trust)
    elif change == "wrong_feed":
        sign("3", feed_id="other")
    elif change == "missing_expiry":
        sign("3", expires=None)
    elif change == "expired":
        sign("3", expires="2000-01-01T00:00:00Z")
    elif change == "rollback":
        sign("1")
    elif change == "changed":
        sign("2.0")  # identical numeric version; raw bytes differ
    elif change == "legacy":
        raw = release("3")
        monkeypatch.setattr(
            "dragonscan.threat_intel._download", lambda url, dest, **kw: dest.write_bytes(raw)
        )
        with pytest.raises(FeedError):
            update_feed("https://feed.invalid", hashlib.sha256(raw).hexdigest(), store)
        assert dest.read_bytes() == previous
        return
    with pytest.raises(FeedError):
        install_signed(candidate, sig, "issuer", trust, store)
    assert dest.read_bytes() == previous


def test_signed_command_verified_bytes_freshness_and_authority(tmp_path, signing_lab, monkeypatch):
    candidate, sig, trust, sign = signing_lab
    store = tmp_path / "store"
    record = {
        "id": "d",
        "source": "Synthetic",
        "indicator_type": "sha256",
        "value": "a" * 64,
        "classification": "malicious",
        "trust": "operator_reviewed",
    }
    sign(records=[record])
    runner = CliRunner()
    result = runner.invoke(
        tools,
        [
            "install-signed",
            "--feed",
            str(candidate),
            "--signature",
            str(sig),
            "--signer",
            "issuer",
            "--trust",
            str(trust),
            "--store",
            str(store),
        ],
    )
    assert result.exit_code == 0, result.output
    dest = store / "intel.json"
    assert runner.invoke(tools, ["verify", str(dest), "--trust", str(trust)]).exit_code == 0
    assert runner.invoke(tools, ["verify", str(candidate), "--trust", str(trust)]).exit_code != 0
    assert load_feeds((dest,))[1]  # trust cannot be read from a sibling file
    feeds, errors = load_feeds((dest,), trust_path=trust)
    assert not errors
    document = Document(Artifact(tmp_path / "SKILL.md", ArtifactKind.SKILL, SourceFormat.MARKDOWN))
    (hit,) = Matcher(feeds).detect(document, "a" * 64)
    assert hit.intelligence is not None
    assert hit.intelligence.sources[0].trust == "authenticated_reviewed"
    target = tmp_path / "SKILL.md"
    target.write_text("# Synthetic\n")
    report = replace(Scanner().scan(Target(target)), findings=(hit,))
    assert evaluate(report, Severity.HIGH).exit_code == 1
    assert _prelaunch_denial(report) == "reviewed malicious artifact digest; MCP launch skipped"
    passive = replace(hit, intelligence=replace(hit.intelligence, context="documentation"))
    assert evaluate(replace(report, findings=(passive,)), Severity.LOW).exit_code == 0
    assert _prelaunch_denial(replace(report, findings=(passive,))) is None

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(UTC) + timedelta(days=4)

    monkeypatch.setattr("dragonscan.signed_intel.datetime", Future)
    until, notes = load_feeds((dest,), trust_path=trust)
    assert not until and any("expired" in n for n in notes)


def test_windows_fails_closed_before_access(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr("dragonscan.intel_store.os", SimpleNamespace(name="nt"))
    store = tmp_path / "never-created"
    with pytest.raises(FeedError, match="Windows ACLs"):
        install_signed(
            tmp_path / "missing", tmp_path / "missing", "issuer", tmp_path / "policy", store
        )
    assert not store.exists()


def test_signed_malicious_package_requires_active_exact_observed_public_origin(
    tmp_path, signing_lab
):
    candidate, sig, trust, sign = signing_lab
    store = tmp_path / "store"
    record = {
        "id": "fixture",
        "indicator_type": "package",
        "value": "fixture",
        "source": "Synthetic",
        "ecosystem": "npm",
        "registry": "https://registry.npmjs.org",
        "version": "1.0.0",
        "classification": "malicious",
    }
    sign(records=[record])
    install_signed(candidate, sig, "issuer", trust, store)
    loaded = read_release(store / "intel.json", trust)
    artifact = Artifact(tmp_path / "SKILL.md", ArtifactKind.SKILL, SourceFormat.MARKDOWN)
    dep = Dependency(
        "node",
        "fixture",
        "1.0.0",
        "1.0.0",
        "exact",
        "registry",
        "npx",
        "runtime-execution",
        "instruction",
        SourceRef(artifact.path, artifact.source_format, 1),
        registry="https://registry.npmjs.org",
    )

    def detect(item, feed=loaded):
        return Matcher((feed,)).detect(Document(artifact, dependencies=(item,)), "a" * 64)

    (hit,) = detect(dep)
    assert hit.detection_id == "DRAGON-SC-010" and not hit.vulnerability
    assert "npm:fixture@1.0.0" in hit.evidence
    assert detect(replace(dep, mechanism="declaration"))[0].detection_id == "DRAGON-TI-001"
    for other in (
        replace(dep, registry=None),
        replace(dep, registry="https://private.invalid"),
        replace(dep, exact_version="2.0.0"),
        replace(dep, ecosystem="python"),
    ):
        assert not detect(other)
    sign("3", records=[{**record, "withdrawn": "2020-01-01"}])
    retired = install_signed(candidate, sig, "issuer", trust, store)
    assert not detect(dep, retired)


def test_rejected_store_permissions_and_atomic_replace_failure(tmp_path, signing_lab, monkeypatch):
    candidate, sig, trust, sign = signing_lab
    store = tmp_path / "store"
    install_signed(candidate, sig, "issuer", trust, store)
    previous = (store / "intel.json").read_bytes()
    sign("3")
    trust.chmod(0o666)
    with pytest.raises(FeedError, match="permissions"):
        install_signed(candidate, sig, "issuer", trust, store)
    trust.chmod(0o600)
    store.chmod(0o777)
    with pytest.raises(FeedError, match="writable"):
        install_signed(candidate, sig, "issuer", trust, store)
    store.chmod(0o700)

    def unavailable(staged, destination):
        raise OSError("synthetic write failure")

    monkeypatch.setattr("dragonscan.intel_store.os.replace", unavailable)
    with pytest.raises(FeedError):
        install_signed(candidate, sig, "issuer", trust, store)
    assert (store / "intel.json").read_bytes() == previous
