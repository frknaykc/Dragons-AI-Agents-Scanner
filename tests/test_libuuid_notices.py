"""Offline regression coverage for incorporated libuuid notices, not legal clearance."""

import importlib
import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
licenses = importlib.import_module("scripts.standalone_licenses")
UUID_URL = "https://sourceforge.net/projects/libuuid/files/libuuid-1.0.3.tar.gz"
LGPL_URL = "https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-15.2.0/COPYING.LIB"
HEADERS = {
    "gen_uuid.c": b"/* Original BSD copyright 1996, 1997, 1998, 1999. */",
    "randutils.c": b"/* Original GNU Lesser General Public License notice. */",
}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    import socket
    import urllib.request

    def forbidden(*args, **kwargs):
        raise AssertionError("notice collection must remain offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(licenses.sys, "platform", "linux")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, header in HEADERS.items():
            content = header + b"\r\nDO_NOT_SHIP_OR_EXECUTE_SOURCE_CODE\r\n"
            item = tarfile.TarInfo("libuuid-1.0.3/" + name)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
    sources = {UUID_URL: buffer.getvalue(), LGPL_URL: b"Original complete LGPL fixture\r\n"}
    monkeypatch.setattr(licenses, "SOURCE_DIGESTS", {})
    for url, content in sources.items():
        licenses.SOURCE_DIGESTS[url] = licenses.digest(content)
        (tmp_path / licenses.digest(url.encode())).write_bytes(content)
    return tmp_path


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_uuid_exact_notices_never_clear_source_relink_gate(cache, monkeypatch, platform):
    monkeypatch.setattr(licenses.sys, "platform", platform)
    components, unresolved = licenses.libuuid_notices(cache)
    files = {name: data for c in components for name, data in c["files"].items()}
    assert files == {
        "gen_uuid-NOTICE.txt": HEADERS["gen_uuid.c"],
        "randutils-NOTICE.txt": HEADERS["randutils.c"],
        "LGPL-2.1.txt": b"Original complete LGPL fixture\r\n",
    }
    assert any("source" in item and "relink" in item for item in unresolved)
    assert all(b"DO_NOT_SHIP" not in data for data in files.values())


def test_windows_does_not_claim_libuuid_inclusion(cache, monkeypatch):
    monkeypatch.setattr(licenses.sys, "platform", "win32")
    assert licenses.libuuid_notices(cache) == ([], [])


@pytest.mark.parametrize(
    "version,tag,expected",
    [("3.12.12", "20260211", True), ("3.12.12", "20250101", False), ("3.12.13", "20260211", False)],
)
def test_runtime_integration_is_scoped_to_reviewed_build(
    cache, monkeypatch, version, tag, expected
):
    monkeypatch.setattr(licenses.platform, "python_version", lambda: version)
    monkeypatch.setattr(licenses.sys, "base_prefix", str(cache))
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(cache))
    (cache / "LICENSE.txt").write_bytes(b"CPython license fixture")
    (cache / "BUILD").write_text(tag)
    components, unresolved = licenses.runtime_notices(cache)
    assert any(c["name"].startswith("incorporated libuuid") for c in components) is expected
    assert any("libuuid 1.0.3" in item and "relink" in item for item in unresolved) is expected


@pytest.mark.parametrize("url", [UUID_URL, LGPL_URL])
def test_missing_source_keeps_explicit_blocker(cache, url):
    (cache / licenses.digest(url.encode())).unlink()
    _, unresolved = licenses.libuuid_notices(cache)
    assert any(url in item for item in unresolved)
    assert any("relink" in item for item in unresolved)


@pytest.mark.parametrize("url", [UUID_URL, LGPL_URL])
def test_corrupt_source_fails_closed(cache, url):
    (cache / licenses.digest(url.encode())).write_bytes(b"altered")
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        licenses.libuuid_notices(cache)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.DIRTYPE, tarfile.REGTYPE])
def test_invalid_header_or_member_fails_closed(cache, monkeypatch, kind):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        item = tarfile.TarInfo("libuuid-1.0.3/gen_uuid.c")
        item.type = kind
        item.linkname = "outside"
        content = b"no leading comment"
        item.size = len(content) if kind == tarfile.REGTYPE else 0
        archive.addfile(item, io.BytesIO(content) if item.size else None)
    data = buffer.getvalue()
    monkeypatch.setitem(licenses.SOURCE_DIGESTS, UUID_URL, licenses.digest(data))
    (cache / licenses.digest(UUID_URL.encode())).write_bytes(data)
    with pytest.raises(licenses.LicenseError, match="invalid libuuid"):
        licenses.libuuid_notices(cache)
