"""Offline, inert regressions for CPython's vendored cryptography notices."""

import pytest

from scripts import standalone_licenses as licenses

HACL_URL = (
    "https://raw.githubusercontent.com/python/cpython/v3.12.12/Modules/_hacl/Hacl_Hash_SHA2.h"
)
KARAMEL_URL = (
    "https://raw.githubusercontent.com/python/cpython/v3.12.12/"
    "Modules/_hacl/include/krml/internal/target.h"
)
APACHE_URL = (
    "https://raw.githubusercontent.com/hacl-star/hacl-star/"
    "bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0/LICENSE"
)
SOURCES = {
    HACL_URL: b"/* MIT License\r\n * Original copyright and grant fixture\r\n */\r\nINERT",
    KARAMEL_URL: b"/* Original attribution fixture; Apache 2.0 License. */\nINERT",
    APACHE_URL: b"Original Apache license fixture\r\n",
}


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    import socket
    import urllib.request

    def forbidden(*args, **kwargs):
        raise AssertionError("notice generation must remain offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(licenses.platform, "python_version", lambda: "3.12.12")
    monkeypatch.setattr(licenses.sys, "base_prefix", str(tmp_path))
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(tmp_path))
    (tmp_path / "LICENSE.txt").write_bytes(b"Runtime license fixture\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(
        licenses, "SOURCE_DIGESTS", {u: licenses.digest(d) for u, d in SOURCES.items()}
    )
    for url, data in SOURCES.items():
        (cache / licenses.digest(url.encode())).write_bytes(data)
    return cache


def test_runtime_preserves_embedded_notices_without_copying_source_code(runtime):
    components, _ = licenses.runtime_notices(runtime)
    embedded = {c["source"]: c for c in components if c["name"].startswith("CPython embedded ")}
    assert set(embedded) == set(SOURCES)
    for url, original in SOURCES.items():
        component = embedded[url]
        assert component["source_sha256"] == licenses.digest(original)
        assert component["version"] == "3.12.12"
        expected = original[: original.index(b"*/") + 2] if url != APACHE_URL else original
        assert list(component["files"].values()) == [expected]
        assert b"INERT" not in expected


def test_missing_embedded_notice_is_explicit_and_not_fabricated(runtime):
    (runtime / licenses.digest(HACL_URL.encode())).unlink()
    components, unresolved = licenses.runtime_notices(runtime)
    assert not any(c["source"] == HACL_URL for c in components)
    assert any(
        "Missing CPython embedded notice" in message and HACL_URL in message
        for message in unresolved
    )


def test_changed_embedded_notice_fails_closed(runtime):
    (runtime / licenses.digest(KARAMEL_URL.encode())).write_bytes(b"altered")
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        licenses.runtime_notices(runtime)


@pytest.mark.parametrize("data", [b"not a comment", b"/* unterminated", b"/* */"])
def test_malformed_reviewed_header_fails_closed(runtime, monkeypatch, data):
    monkeypatch.setitem(licenses.SOURCE_DIGESTS, HACL_URL, licenses.digest(data))
    (runtime / licenses.digest(HACL_URL.encode())).write_bytes(data)
    with pytest.raises(licenses.LicenseError, match="embedded notice header"):
        licenses.runtime_notices(runtime)


def test_other_cpython_version_does_not_reuse_reviewed_notices(runtime, monkeypatch):
    monkeypatch.setattr(licenses.platform, "python_version", lambda: "3.13.1")
    components, unresolved = licenses.runtime_notices(runtime)
    assert not any(c["name"].startswith("CPython embedded ") for c in components)
    assert any("Unreviewed CPython embedded notices: 3.13.1" in message for message in unresolved)
