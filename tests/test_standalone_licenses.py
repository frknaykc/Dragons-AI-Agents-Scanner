"""Inert regressions for artifact-derived, byte-preserving standalone notices."""

import importlib
import io
import json
import marshal
import platform
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
licenses = importlib.import_module("scripts.standalone_licenses")
stage = importlib.import_module("scripts.stage_standalone")
checksum_module = importlib.import_module("scripts.checksums")


class Distribution:
    def __init__(self, root: Path, name: str, files: dict[str, bytes]):
        self.metadata = {"Name": name}
        self.version = "1.2.3"
        self.root = root / name
        self.files = [Path(path) for path in files]
        for path, content in files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    def locate_file(self, item: Path) -> Path:
        return self.root / item


def test_distribution_texts_preserve_bytes_and_vendored_notices(tmp_path: Path) -> None:
    texts = {
        "example.dist-info/licenses/LICENSE": b"Copyright holder\r\nMIT text\r\n",
        "example.dist-info/licenses/vendor/NOTICE": b"Original attribution\n",
        "example.dist-info/LICENSE.extra": b"Another grant\n",
    }
    dist = Distribution(tmp_path, "example", {**texts, "example/__init__.py": b""})
    assert licenses.distribution_licenses(dist) == texts


def test_distribution_missing_license_fails_closed(tmp_path: Path) -> None:
    dist = Distribution(tmp_path, "example", {"example/__init__.py": b""})
    with pytest.raises(licenses.LicenseError, match="no authentic license"):
        licenses.distribution_licenses(dist)


def test_inventory_resolves_transitive_and_native_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        licenses.metadata,
        "packages_distributions",
        lambda: {
            "rich": ["rich"],
            "markdown_it": ["markdown-it-py"],
            "yaml": ["PyYAML"],
            "new_dependency": ["new-distribution"],
        },
    )
    inventory = {
        "modules": ["os", "dragonscan.cli", "rich.console", "markdown_it", "new_dependency.inner"],
        "native": ["libpython3.12.so", "yaml/_yaml.so"],
    }
    assert licenses.package_owners(inventory) == {
        "rich": ["rich"],
        "markdown-it-py": ["markdown_it"],
        "new-distribution": ["new_dependency"],
        "PyYAML": ["yaml"],
    }
    inventory["modules"].append("unknown.new")
    with pytest.raises(licenses.LicenseError, match="unmapped bundled Python package: unknown"):
        licenses.package_owners(inventory)


@pytest.fixture
def built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    name = stage.artifact_name(sys.platform, platform.machine(), "0.1.0")
    binary = tmp_path / "dist" / name
    binary.parent.mkdir()
    binary.write_bytes(b"inert executable fixture")
    (tmp_path / "LICENSE").write_bytes(b"Application license\r\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nversion='0.1.0'\n")
    inventory = {"modules": ["dragonscan", "rich", "mdurl", "os"], "native": ["libpython3.12.so"]}
    monkeypatch.setattr(licenses, "archive_inventory", lambda path: inventory)
    monkeypatch.setattr(
        licenses.metadata, "packages_distributions", lambda: {"rich": ["rich"], "mdurl": ["mdurl"]}
    )
    dists = {
        name: Distribution(
            tmp_path, name, {f"{name}.dist-info/LICENSE": f"{name} original\r\n".encode()}
        )
        for name in ("rich", "mdurl", "pyinstaller")
    }
    monkeypatch.setattr(licenses.metadata, "distribution", dists.__getitem__)
    monkeypatch.setattr(licenses.metadata, "version", lambda name: "0.1.0")
    monkeypatch.setattr(
        licenses,
        "runtime_notices",
        lambda cache: (
            [
                {
                    "name": "CPython",
                    "version": "3.12.12",
                    "scope": "bundled runtime",
                    "source": "fixture",
                    "files": {"LICENSE.txt": b"CPython original\n"},
                }
            ],
            ["Static native attribution needs review."],
        ),
    )
    directory = licenses.create_notices(binary, tmp_path, tmp_path / "cache")
    return binary, directory


def test_creation_has_versions_runtime_bootloader_and_actual_inventory(built) -> None:
    binary, directory = built
    result = licenses.verify_notices(binary)
    components = {component["name"]: component for component in result["components"]}
    assert set(components) == {
        "rich",
        "mdurl",
        "PyInstaller",
        "CPython",
        "Dragons AI Agent Scanner",
    }
    assert components["rich"]["version"] == "1.2.3"
    assert components["CPython"]["version"] == "3.12.12"
    for path in components["rich"]["license_files"]:
        assert (directory / path).read_bytes() == b"rich original\r\n"
    assert result["inventory"]["native"] == ["libpython3.12.so"]
    assert result["unresolved_obligations"]


@pytest.mark.parametrize(
    "mutation", ["binary", "text", "missing", "extra", "inventory", "owner", "runtime"]
)
def test_verifier_rejects_incomplete_or_changed_artifact(built, mutation: str) -> None:
    binary, directory = built
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    text = directory / manifest["components"][0]["license_files"][0]
    if mutation == "binary":
        binary.write_bytes(b"different executable")
    elif mutation == "text":
        text.write_bytes(b"altered copyright")
    elif mutation == "missing":
        text.unlink()
    elif mutation == "extra":
        (directory / "unexpected").write_text("not permitted")
    elif mutation == "inventory":
        manifest["inventory"]["native"] = []
    elif mutation == "runtime":
        manifest["components"] = [
            item for item in manifest["components"] if item["name"] != "CPython"
        ]
    else:
        manifest["components"] = [item for item in manifest["components"] if item["name"] != "rich"]
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(licenses.LicenseError):
        licenses.verify_notices(binary)


def test_staging_includes_and_reverifies_notices(built, monkeypatch: pytest.MonkeyPatch) -> None:
    binary, directory = built
    root = binary.parent.parent
    monkeypatch.setattr(stage, "ROOT", root)
    stage.main()
    staged = root / "release-staging" / binary.name
    assert staged.read_bytes() == binary.read_bytes()
    result = licenses.verify_notices(staged)
    assert (licenses.notice_directory(staged) / "THIRD_PARTY_NOTICES.txt").read_bytes() == (
        directory / "THIRD_PARTY_NOTICES.txt"
    ).read_bytes()
    assert result["sha256"] == licenses.digest(binary.read_bytes())


def test_staging_without_notices_fails_before_copy(built, monkeypatch: pytest.MonkeyPatch) -> None:
    binary, directory = built
    (directory / "manifest.json").unlink()
    root = binary.parent.parent
    monkeypatch.setattr(stage, "ROOT", root)
    with pytest.raises(FileNotFoundError):
        stage.main()
    assert not (root / "release-staging").exists()


def test_checksums_include_real_verified_notices_and_reject_tampering(built):
    binary, directory = built
    manifest = licenses.verify_notices(binary)
    checksums = checksum_module.checksums(binary.parent, "0.1.0")
    expected = {binary.name, directory.name + "/manifest.json"} | {
        directory.name + "/" + name for name in manifest["files"]
    }
    assert {line.split("  ", 1)[1] for line in checksums.splitlines()} == expected
    for line in checksums.splitlines():
        digest, name = line.split("  ", 1)
        assert digest == licenses.digest((binary.parent / name).read_bytes())
    (directory / "THIRD_PARTY_NOTICES.txt").write_text("altered")
    with pytest.raises(licenses.LicenseError, match="checksum mismatch"):
        checksum_module.checksums(binary.parent, "0.1.0")


def test_inventory_reads_pyz_and_native_entries_without_running_code(tmp_path) -> None:
    pyz = (
        b"PYZ\0"
        + b"test"
        + struct.pack("!i", 12)
        + marshal.dumps(
            {
                "rich": (0, 0, 0),
                "yaml": (1, 0, 0),
                "dragonscan.cli": (0, 0, 0),
            }
        )
    )
    library = io.BytesIO()
    with zipfile.ZipFile(library, "w") as archive:
        archive.writestr("os.pyc", b"not executable bytecode")
    body, toc = b"", b""
    for name, payload, kind, compressed in [
        ("PYZ.pyz", pyz, b"z", False),
        ("yaml/_yaml.so", b"inert native fixture", b"b", False),
        ("libpython.so", b"inert runtime fixture", b"b", False),
        ("base_library.zip", library.getvalue(), b"x", True),
    ]:
        encoded = name.encode() + b"\0"
        stored = zlib.compress(payload) if compressed else payload
        toc += (
            struct.pack(
                "!IIIIBc", 18 + len(encoded), len(body), len(stored), len(payload), compressed, kind
            )
            + encoded
        )
        body += stored
    cookie = struct.pack(
        "!8sIIII64s",
        b"MEI\014\013\012\013\016",
        len(body) + len(toc) + 88,
        len(body),
        len(toc),
        312,
        b"libpython.so",
    )
    binary = tmp_path / "inert-archive"
    binary.write_bytes(b"non-executable prefix" + body + toc + cookie + b"signature trailer")
    assert licenses.archive_inventory(binary) == {
        "modules": ["dragonscan.cli", "os", "rich", "yaml"],
        "native": ["libpython.so", "yaml/_yaml.so"],
    }
    binary.write_bytes(b"not an archive")
    with pytest.raises(licenses.LicenseError, match="archive cookie"):
        licenses.archive_inventory(binary)


@pytest.mark.parametrize("recipe_version", ["3.12.12", "3.12.11"])
def test_runtime_provenance_and_candidate_versions(tmp_path, monkeypatch, recipe_version) -> None:
    (tmp_path / "LICENSE.txt").write_bytes(b"Original CPython\r\n")
    (tmp_path / "BUILD").write_text("20251014\n")
    monkeypatch.setattr(licenses.sys, "base_prefix", str(tmp_path))
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(tmp_path))
    monkeypatch.setattr(licenses.platform, "python_version", lambda: "3.12.12")
    key = f"cpython-{sys.version_info.major}.{sys.version_info.minor}"
    recipe = {
        key: {"version": recipe_version},
        "zlib": {
            "version": "1.3.1",
            "license_file": "LICENSE.zlib.txt",
        },
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in {
            "pythonbuild/downloads.py": f"DOWNLOADS = {recipe!r}\n".encode(),
            "LICENSE.zlib.txt": b"Exact zlib grant\r\n",
        }.items():
            member = tarfile.TarInfo("python-build-standalone-20251014/" + name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    monkeypatch.setattr(
        licenses,
        "cached_source",
        lambda url, cache: (
            buffer.getvalue() if "codeload" in url else b"Exact CPython additional notices\n"
        ),
    )
    if recipe_version != "3.12.12":
        with pytest.raises(licenses.LicenseError, match="does not match interpreter"):
            licenses.runtime_notices(tmp_path / "cache")
        return
    components, unresolved = licenses.runtime_notices(tmp_path / "cache")
    assert components[0]["files"]["LICENSE.txt"] == b"Original CPython\r\n"
    candidate = components[-1]
    assert candidate["recipe_versions"] == {"zlib": "1.3.1"}
    assert candidate["files"]["LICENSE.zlib.txt"] == b"Exact zlib grant\r\n"
    assert "unconfirmed" in candidate["scope"]
    assert unresolved


def test_generated_sysconfig_module_is_stdlib(tmp_path, monkeypatch) -> None:
    (tmp_path / "_sysconfigdata__test_platform.py").write_text("# inert\n")
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(tmp_path))
    monkeypatch.setattr(licenses.metadata, "packages_distributions", dict)
    assert (
        licenses.package_owners({"modules": ["_sysconfigdata__test_platform"], "native": []}) == {}
    )


def test_retained_notices_do_not_require_original_environment(built, monkeypatch) -> None:
    binary, _ = built

    def forbidden(*args, **kwargs):
        raise AssertionError("verification consulted the build environment")

    monkeypatch.setattr(licenses, "stdlib_roots", forbidden)
    monkeypatch.setattr(licenses.metadata, "distribution", forbidden)
    monkeypatch.setattr(licenses.metadata, "packages_distributions", forbidden)
    assert licenses.verify_notices(binary)["schema"] == 1


def test_offline_missing_native_sources_are_explicit_not_fabricated(tmp_path, monkeypatch) -> None:
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("build attempted network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    (tmp_path / "LICENSE.txt").write_bytes(b"Authentic runtime fixture\n")
    (tmp_path / "BUILD").write_text("20251014\n")
    monkeypatch.setattr(licenses.sys, "base_prefix", str(tmp_path))
    monkeypatch.setattr(licenses.sysconfig, "get_path", lambda key: str(tmp_path))
    components, unresolved = licenses.runtime_notices(tmp_path / "empty-cache")
    assert [item["name"] for item in components] == ["CPython"]
    assert any("Missing offline runtime vendor source" in item for item in unresolved)
    assert any("additional third-party notices" in item for item in unresolved)
    assert licenses.digest(licenses.LIBYAML_0_2_5) == (
        "c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29"
    )
