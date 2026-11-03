"""Inert, offline tests of platform-specific authentic notice preservation."""

import importlib
import io
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
licenses = importlib.import_module("scripts.standalone_licenses")


@pytest.fixture
def sources(tmp_path, monkeypatch):
    import socket
    import urllib.request

    def forbidden(*args, **kwargs):
        raise AssertionError("notice assembly must stay offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    expected = {}
    pins = {}
    for name, version, url, member, _ in licenses.RUNTIME_SUPPLEMENTS:
        content = f"Original {name} {version} notice\r\n".encode()
        data = content
        if member:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                item = tarfile.TarInfo(member)
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            data = buffer.getvalue()
        expected[url] = content
        pins[url] = licenses.digest(data)
        (tmp_path / licenses.digest(url.encode())).write_bytes(data)
    monkeypatch.setattr(licenses, "SOURCE_DIGESTS", pins)
    return tmp_path, expected


@pytest.mark.parametrize(
    ("platform", "versions"),
    [
        ("win32", {("libffi", "3.4.2")}),
        ("darwin", {("libffi", "3.4.6"), ("mpdecimal", "4.0.0")}),
        ("linux", {("libffi", "3.4.6"), ("mpdecimal", "4.0.0"), ("ncurses", "6.5")}),
    ],
)
def test_exact_original_bytes_and_platform_versions(sources, monkeypatch, platform, versions):
    cache, expected = sources
    monkeypatch.setattr(licenses.sys, "platform", platform)
    components, unresolved = licenses.runtime_supplements(cache)
    assert not unresolved
    assert {
        (c["name"].removeprefix("reviewed runtime "), c["version"]) for c in components
    } == versions
    for component in components:
        assert list(component["files"].values()) == [expected[component["source"]]]
        assert component["source_sha256"] == licenses.SOURCE_DIGESTS[component["source"]]


def test_missing_supplement_retains_blocker(sources, monkeypatch):
    cache, _ = sources
    monkeypatch.setattr(licenses.sys, "platform", "win32")
    url = licenses.LIBFFI_WINDOWS_URL
    (cache / licenses.digest(url.encode())).unlink()
    components, unresolved = licenses.runtime_supplements(cache)
    assert not components
    assert unresolved == ["Missing reviewed runtime supplement: " + url]


def test_altered_source_fails_closed(sources, monkeypatch):
    cache, _ = sources
    monkeypatch.setattr(licenses.sys, "platform", "win32")
    (cache / licenses.digest(licenses.LIBFFI_WINDOWS_URL.encode())).write_bytes(b"altered")
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        licenses.runtime_supplements(cache)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.DIRTYPE])
def test_nonregular_archive_notice_fails_closed(sources, monkeypatch, kind):
    cache, _ = sources
    monkeypatch.setattr(licenses.sys, "platform", "linux")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        item = tarfile.TarInfo("ncurses-6.5/COPYING")
        item.type = kind
        item.linkname = "outside"
        archive.addfile(item)
    data = buffer.getvalue()
    url = licenses.NCURSES_URL
    monkeypatch.setitem(licenses.SOURCE_DIGESTS, url, licenses.digest(data))
    (cache / licenses.digest(url.encode())).write_bytes(data)
    with pytest.raises(licenses.LicenseError, match="invalid runtime supplement member"):
        licenses.runtime_supplements(cache)


@pytest.mark.parametrize(("version", "tag"), [("3.12.13", "20260211"), ("3.12.12", "20260101")])
def test_other_runtime_does_not_reuse_supplements(tmp_path, monkeypatch, version, tag):
    monkeypatch.setattr(licenses.platform, "python_version", lambda: version)
    monkeypatch.setattr(licenses.sys, "base_prefix", str(tmp_path))
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(tmp_path))
    (tmp_path / "LICENSE.txt").write_bytes(b"Runtime license fixture")
    (tmp_path / "BUILD").write_text(tag)
    components, _ = licenses.runtime_notices(tmp_path / "absent")
    assert not any(c["name"].startswith("reviewed runtime ") for c in components)
