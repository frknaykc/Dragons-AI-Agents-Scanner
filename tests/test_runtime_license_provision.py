"""Pinned upstream provisioning with inert responses; never contact a service."""

import io
from pathlib import Path

import pytest

from scripts import provision_runtime_licenses as provisioner
from scripts import standalone_licenses as licenses


@pytest.fixture
def source(monkeypatch):
    url = "https://example.invalid/version/LICENSE"
    data = b"Original copyright\r\nUnmodified grant\r\n"
    pins = {url: licenses.digest(data)}
    monkeypatch.setattr(provisioner, "SOURCE_DIGESTS", pins)
    monkeypatch.setattr(licenses, "SOURCE_DIGESTS", pins)
    return url, data


def test_provision_preserves_bytes_and_reuses_verified_cache(tmp_path, monkeypatch, source):
    url, data = source
    calls = []

    def open_source(request, timeout):
        calls.append((request, timeout))
        return io.BytesIO(data)

    monkeypatch.setattr(provisioner.urllib.request, "urlopen", open_source)
    provisioner.provision(tmp_path)
    assert licenses.cached_source(url, tmp_path) == data
    provisioner.provision(tmp_path)
    assert calls == [(url, 60)]


@pytest.mark.parametrize("response", [b"wrong text", b"", b"x" * 33])
def test_provision_rejects_changed_or_oversized_sources(tmp_path, monkeypatch, source, response):
    monkeypatch.setattr(provisioner, "MAX_SOURCE_BYTES", 32)
    monkeypatch.setattr(
        provisioner.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(response)
    )
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        provisioner.provision(tmp_path)
    assert not list(tmp_path.iterdir())


def test_corrupt_cache_fails_offline_without_overwrite(tmp_path, monkeypatch, source):
    url, _ = source
    target = tmp_path / licenses.digest(url.encode())
    target.write_bytes(b"changed")

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network access")

    monkeypatch.setattr(provisioner.urllib.request, "urlopen", forbidden)
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        licenses.cached_source(url, tmp_path)
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        provisioner.provision(tmp_path)
    assert target.read_bytes() == b"changed"


def test_directory_cache_fails_offline_without_overwrite(tmp_path, monkeypatch, source):
    url, _ = source
    target = tmp_path / licenses.digest(url.encode())
    target.mkdir()

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network access")

    monkeypatch.setattr(provisioner.urllib.request, "urlopen", forbidden)
    with pytest.raises(licenses.LicenseError, match="not a regular file"):
        licenses.cached_source(url, tmp_path)
    with pytest.raises(licenses.LicenseError, match="not a regular file"):
        provisioner.provision(tmp_path)
    assert target.is_dir()
    assert not list(target.iterdir())


def test_missing_cache_is_offline_and_unknown_cached_sources_fail(tmp_path, monkeypatch):
    url = "https://example.invalid/unreviewed"
    assert licenses.cached_source(url, tmp_path) is None
    (tmp_path / licenses.digest(url.encode())).write_bytes(b"unreviewed")
    with pytest.raises(licenses.LicenseError, match="not pinned"):
        licenses.cached_source(url, tmp_path)


def test_reviewed_sources_are_immutable_and_version_specific():
    cpython = "https://raw.githubusercontent.com/python/cpython/v3.12.12/Doc/license.rst"
    pbs = "https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/refs/tags/20260211"
    assert licenses.SOURCE_DIGESTS == {
        cpython: "341832873fd316a37927e79385093fbbfd40a467428480835fe435a80cadf4e5",
        pbs: "a70d814140fb061d5724c477aeecfdf263e890d3a3515546763adc727f929628",
    }


def test_symlinked_cache_is_rejected(tmp_path: Path, monkeypatch, source):
    url, data = source
    actual = tmp_path / "original"
    actual.write_bytes(data)
    target = tmp_path / licenses.digest(url.encode())
    # Simulate the filesystem boundary without requiring Windows symlink privileges.
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == target)
    with pytest.raises(licenses.LicenseError, match="symlinked"):
        provisioner.provision(tmp_path)
    with pytest.raises(licenses.LicenseError, match="symlinked"):
        licenses.cached_source(url, tmp_path)
