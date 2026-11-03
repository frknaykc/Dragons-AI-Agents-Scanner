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
        licenses.HACL_NOTICE_URL: (
            "093d7693084af0999d2a13d207311d74b5bdfdc9c08447ed4a979e3f7505ae6b"
        ),
        licenses.KARAMEL_NOTICE_URL: (
            "d16a59f37a1d4982626870e370889eb9d332a9ad035661b8062f549fc734d061"
        ),
        licenses.KARAMEL_LICENSE_URL: (
            "c5accbbd8546e94c34aed24afe689a617627d18eed5a6c48277e48db57c23851"
        ),
        licenses.LIBFFI_UNIX_URL: (
            "67894089811f93fca47a76f85e017da6f8582d4ba0905963c6e0f1ad6df7a195"
        ),
        licenses.LIBFFI_WINDOWS_URL: (
            "a61d06e8f7be57928e71e800eb9273b05cb8868c484108afe41e4305bb320dde"
        ),
        licenses.MPDECIMAL_URL: (
            "942445c3245b22730fd41a67a7c5c231d11cb1b9936b9c0f76334fb7d0b4468c"
        ),
        licenses.NCURSES_URL: ("136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6"),
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
