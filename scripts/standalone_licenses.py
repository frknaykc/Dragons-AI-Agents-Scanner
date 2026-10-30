"""Build-only, artifact-derived notices; never import or execute bundled code.

License bytes come from installed distributions and versioned upstream sources.
The manifest distinguishes observed files from conservative runtime notices: it
is an inventory and integrity check, not a legal-compliance determination.
"""

import ast
import hashlib
import importlib.metadata as metadata
import io
import json
import marshal
import platform
import re
import struct
import sys
import sysconfig
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

# Exact bytes from https://raw.githubusercontent.com/yaml/libyaml/0.2.5/License
LIBYAML_0_2_5 = (
    b"Copyright (c) 2017-2020 Ingy d\xc3\xb6t Net\n"
    b"Copyright (c) 2006-2016 Kirill Simonov\n"
    b"\n"
    b"Permission is hereby granted, free of charge, to any person obtaining a copy of\n"
    b'this software and associated documentation files (the "Software"), to deal in\n'
    b"the Software without restriction, including without limitation the rights to\n"
    b"use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies\n"
    b"of the Software, and to permit persons to whom the Software is furnished to do\n"
    b"so, subject to the following conditions:\n"
    b"\n"
    b"The above copyright notice and this permission notice shall be included in all\n"
    b"copies or substantial portions of the Software.\n"
    b"\n"
    b'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
    b"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
    b"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
    b"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
    b"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
    b"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
    b"SOFTWARE.\n"
)


class LicenseError(ValueError):
    """The artifact cannot be paired with a complete, intact notice inventory."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def notice_directory(binary: Path) -> Path:
    return binary.with_name(binary.name + ".licenses")


def archive_inventory(binary: Path) -> dict[str, list[str]]:
    """Read PyInstaller 6 CArchive/PYZ tables using only the standard library."""
    data = binary.read_bytes()
    cookie = data.rfind(b"MEI\014\013\012\013\016")
    if cookie < 0 or cookie + 88 > len(data):
        raise LicenseError("missing PyInstaller archive cookie")
    _, size, toc_offset, toc_size, _, _ = struct.unpack_from("!8sIIII64s", data, cookie)
    start = cookie + 88 - size
    if start < 0 or toc_offset + toc_size > size - 88:
        raise LicenseError("invalid PyInstaller archive bounds")
    toc = data[start + toc_offset : start + toc_offset + toc_size]
    modules: set[str] = set()
    native: set[str] = set()
    position = 0
    while position < len(toc):
        if len(toc) - position < 18:
            raise LicenseError("truncated archive table")
        length, offset, size, unpacked, compressed, kind = struct.unpack_from(
            "!IIIIBc", toc, position
        )
        if length < 19 or position + length > len(toc) or offset + size > toc_offset:
            raise LicenseError("invalid archive entry bounds")
        name = toc[position + 18 : position + length].rstrip(b"\0").decode("utf-8")
        position += length
        if kind == b"b":
            native.add(name.replace("\\", "/"))
        if kind != b"z" and name != "base_library.zip":
            continue
        payload = data[start + offset : start + offset + size]
        if compressed:
            payload = zlib.decompress(payload)
        if len(payload) != unpacked:
            raise LicenseError("archive entry length mismatch")
        if kind == b"z":
            if payload[:4] != b"PYZ\0" or len(payload) < 12:
                raise LicenseError("invalid PYZ header")
            table_offset = struct.unpack_from("!i", payload, 8)[0]
            if not 12 <= table_offset < len(payload):
                raise LicenseError("invalid PYZ table offset")
            table = marshal.loads(payload[table_offset:])
            names = table.keys() if isinstance(table, dict) else (entry[0] for entry in table)
            modules.update(names)
        else:
            with zipfile.ZipFile(io.BytesIO(payload)) as library:
                modules.update(
                    item.removesuffix(".pyc").replace("/", ".").removesuffix(".__init__")
                    for item in library.namelist()
                    if item.endswith(".pyc")
                )
    if not modules or not native or not all(isinstance(name, str) for name in modules):
        raise LicenseError("standalone archive lacks valid modules or native components")
    return {"modules": sorted(modules), "native": sorted(native)}


def distribution_licenses(dist: metadata.Distribution) -> dict[str, bytes]:
    """Copy all license/notice material, including nested vendored licenses."""
    result = {}
    for item in dist.files or ():
        parts = tuple(part.lower() for part in item.parts)
        if "licenses" in parts or re.match(
            r"^(licen[cs]e|copying|notice|authors)([._-]|$)", item.name, re.I
        ):
            path = Path(str(dist.locate_file(item)))
            if path.is_file():
                content = path.read_bytes()
                if not content.strip():
                    raise LicenseError(f"empty license: {item}")
                result[str(item).replace("\\", "/")] = content
    if not result:
        raise LicenseError(f"no authentic license files for {dist.metadata['Name']}")
    return result


def stdlib_roots() -> set[str]:
    # Generated platform config modules are omitted from sys.stdlib_module_names.
    generated = Path(sysconfig.get_path("stdlib")).glob("_sysconfigdata_*.py")
    return set(sys.stdlib_module_names) | {path.stem for path in generated}


def package_owners(inventory: dict[str, list[str]]) -> dict[str, list[str]]:
    """Resolve actual archive roots, not declared dependency or allowlist guesses."""
    mapping = metadata.packages_distributions()
    roots = {name.split(".")[0] for name in inventory["modules"]}
    roots.update(name.split("/")[0] for name in inventory["native"] if "/" in name)
    result: dict[str, list[str]] = {}
    for root in sorted(roots):
        if root == "dragonscan" or root in stdlib_roots():
            continue
        # Native framework/library directory names are not Python package roots.
        if root.endswith(".framework") or root == "lib-dynload":
            continue
        owners = mapping.get(root)
        if not owners:
            raise LicenseError(f"unmapped bundled Python package: {root}")
        for owner in owners:
            result.setdefault(owner, []).append(root)
    return result


def cached_source(url: str, cache: Path) -> bytes | None:
    """Read an explicitly pre-provisioned upstream source; never access the network.

    Cache filenames are SHA-256(URL). Missing supplemental sources are recorded as
    unresolved, not replaced with fabricated/generic license text.
    """
    target = cache / digest(url.encode())
    if not target.is_file():
        return None
    data = target.read_bytes()
    if not data.strip() or len(data) > 8 * 1024 * 1024:
        raise LicenseError(f"invalid/oversized offline license source: {url}")
    return data


def runtime_notices(cache: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep vendor provenance separate from a claim of exact static-link coverage."""
    version = platform.python_version()
    prefix = Path(sys.base_prefix)
    candidates = [Path(sysconfig.get_path("stdlib")) / "LICENSE.txt", prefix / "LICENSE.txt"]
    license_path = next((path for path in candidates if path.is_file()), None)
    if license_path is None:
        raise LicenseError("the build interpreter's authentic LICENSE.txt is missing")
    components: list[dict[str, Any]] = [
        {
            "name": "CPython",
            "version": version,
            "scope": "bundled runtime",
            "source": "build interpreter LICENSE.txt",
            "files": {"LICENSE.txt": license_path.read_bytes()},
        }
    ]
    unresolved = [
        "Native file enumeration does not identify every statically linked component. "
        "Runtime vendor notices are conservative candidates, not proof of static-link coverage.",
        "Source-offer, relinking, attribution and platform redistributable obligations "
        "require release review; this manifest does not certify legal compliance.",
    ]
    url = f"https://raw.githubusercontent.com/python/cpython/v{version}/Doc/license.rst"
    additional = cached_source(url, cache)
    if additional is not None:
        components.append(
            {
                "name": "CPython additional notices",
                "version": version,
                "scope": "upstream runtime notice collection",
                "source": url,
                "files": {"license.rst": additional},
            }
        )
    else:
        unresolved.append(
            "CPython additional third-party notices are not available in the "
            "offline source cache: " + url
        )
    if sys.platform == "win32":
        unresolved.append(
            "Review the exact bundled Microsoft runtime DLL versions and their "
            "redistribution terms; CPython's license is not a CRT license."
        )
    build = prefix / "BUILD"
    if build.is_file() and re.fullmatch(r"\d{8}", build.read_text().strip()):
        tag = build.read_text().strip()
        url = (
            f"https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/refs/tags/{tag}"
        )
        data = cached_source(url, cache)
        if data is None:
            unresolved.append("Missing offline runtime vendor source: " + url)
            return components, unresolved
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
            base = f"python-build-standalone-{tag}/"
            member = source.extractfile(base + "pythonbuild/downloads.py")
            if member is None:
                raise LicenseError("runtime vendor source has no download manifest")
            tree = ast.parse(member.read())
            downloads = ast.literal_eval(
                next(
                    node.value
                    for node in tree.body
                    if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "DOWNLOADS" for t in node.targets)
                )
            )
            expected = downloads[f"cpython-{sys.version_info.major}.{sys.version_info.minor}"]
            if expected["version"] != version:
                raise LicenseError("runtime vendor tag does not match interpreter version")
            for item in source.getmembers():
                if not item.isfile() or not item.name.startswith(base + "LICENSE."):
                    continue
                filename = item.name.removeprefix(base)
                if "/" in filename:
                    continue
                matches = {
                    key: value["version"]
                    for key, value in downloads.items()
                    if value.get("license_file") == filename
                }
                if filename == "LICENSE.cpython.txt":
                    continue  # The installed interpreter's own text is more precise.
                stream = source.extractfile(item)
                assert stream is not None
                components.append(
                    {
                        "name": "runtime vendor " + filename,
                        "version": tag,
                        "recipe_versions": matches,
                        "scope": "candidate native library; inclusion unconfirmed",
                        "source": url,
                        "source_sha256": digest(data),
                        "files": {filename: stream.read()},
                    }
                )
        unresolved.append(
            "python-build-standalone recipe alternatives (for example libffi/OpenSSL) "
            "and unused library licenses are retained as candidates, not asserted as bundled. "
            "The full runtime build/link manifest is not shipped by uv's install-only runtime."
        )
    else:
        unresolved.append(
            "No python-build-standalone BUILD provenance; native runtime vendor "
            "licenses beyond CPython must be supplied/reviewed separately."
        )
    return components, unresolved


def create_notices(binary: Path, root: Path, cache: Path) -> Path:
    inventory = archive_inventory(binary)
    owners = package_owners(inventory)
    components: list[dict[str, Any]] = []
    for name, roots in sorted(owners.items()):
        dist = metadata.distribution(name)
        components.append(
            {
                "name": dist.metadata["Name"],
                "version": dist.version,
                "scope": "bundled Python package",
                "roots": roots,
                "license_expression": dist.metadata.get("License-Expression"),
                "license_metadata": dist.metadata.get("License"),
                "source": "installed distribution RECORD/license files",
                "files": distribution_licenses(dist),
            }
        )
    bundler = metadata.distribution("pyinstaller")
    components.append(
        {
            "name": "PyInstaller",
            "version": bundler.version,
            "scope": "embedded bootloader and runtime hooks",
            "source": "installed distribution RECORD/license files",
            "files": distribution_licenses(bundler),
        }
    )
    components.append(
        {
            "name": "Dragons AI Agent Scanner",
            "version": metadata.version("dragons-ai-agent-scanner"),
            "scope": "application",
            "source": "repository LICENSE",
            "files": {"LICENSE": (root / "LICENSE").read_bytes()},
        }
    )
    runtime, unresolved = runtime_notices(cache)
    components.extend(runtime)
    if any(name.startswith("yaml/") for name in inventory["native"]):
        # Trusted installed build dependency, not code extracted from the binary.
        from yaml import _yaml

        version = _yaml.get_version_string()
        if version != "0.2.5":
            raise LicenseError("LibYAML version needs its matching authentic notice")
        url = f"https://raw.githubusercontent.com/yaml/libyaml/{version}/License"
        components.append(
            {
                "name": "LibYAML",
                "version": version,
                "scope": "native library in PyYAML extension",
                "source": url,
                "files": {"License": LIBYAML_0_2_5},
            }
        )
    destination = notice_directory(binary)
    destination.mkdir(exist_ok=False)
    files = {}
    for index, component in enumerate(components):
        paths = []
        for file_index, (filename, content) in enumerate(sorted(component.pop("files").items())):
            # Generated indices keep distinct vendored files with identical basenames.
            path = f"texts/{index:03d}/{file_index:03d}/{Path(filename).name}"
            if path in files:
                raise LicenseError(f"colliding license filenames: {filename}")
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            files[path] = digest(content)
            paths.append(path)
        component["license_files"] = paths
    text = "THIRD-PARTY NOTICES\n\nDistribute this directory alongside the executable.\n\n"
    for component in components:
        text += f"{component['name']} {component['version']} ({component['scope']})\n"
        text += "  " + ", ".join(component["license_files"]) + "\n"
    text += "\nUNRESOLVED RELEASE REVIEW\n" + "\n".join(unresolved) + "\n"
    (destination / "THIRD_PARTY_NOTICES.txt").write_text(text, encoding="utf-8", newline="\n")
    files["THIRD_PARTY_NOTICES.txt"] = digest(text.encode())
    manifest = {
        "schema": 1,
        "binary": binary.name,
        "sha256": digest(binary.read_bytes()),
        "inventory": inventory,
        "stdlib_roots": sorted(stdlib_roots()),
        "components": components,
        "files": files,
        "unresolved_obligations": unresolved,
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    verify_notices(binary, destination)
    return destination


def verify_notices(binary: Path, directory: Path | None = None) -> dict[str, Any]:
    """Read the actual binary and every shipped notice, not just source metadata."""
    directory = directory or notice_directory(binary)
    if binary.is_symlink() or directory.is_symlink():
        raise LicenseError("symlinked executable/notice directory")
    manifest: dict[str, Any] = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["schema"] != 1 or manifest["binary"] != binary.name:
        raise LicenseError("notice manifest schema or executable name mismatch")
    if manifest["sha256"] != digest(binary.read_bytes()):
        raise LicenseError("executable checksum mismatch")
    inventory = archive_inventory(binary)
    if manifest["inventory"] != inventory:
        raise LicenseError("actual archive inventory differs from notices")
    expected = {"manifest.json", *manifest["files"]}
    actual = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise LicenseError("symlink in notices")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    if actual != expected:
        raise LicenseError("missing or unexpected notice files")
    for path, checksum in manifest["files"].items():
        if path.startswith("/") or ".." in Path(path).parts or "\\" in path:
            raise LicenseError("unsafe notice path")
        if digest((directory / path).read_bytes()) != checksum:
            raise LicenseError(f"notice checksum mismatch: {path}")
    roots = {root for item in manifest["components"] for root in item.get("roots", [])}
    required = {name.split(".")[0] for name in inventory["modules"]}
    runtime_roots = set(manifest["stdlib_roots"]) if "stdlib_roots" in manifest else stdlib_roots()
    required -= runtime_roots | {"dragonscan"}
    native_roots = {
        name.split("/")[0]
        for name in inventory["native"]
        if "/" in name
        and not name.split("/")[0].endswith(".framework")
        and name.split("/")[0] != "lib-dynload"
    }
    required |= native_roots - runtime_roots
    if not required <= roots:
        raise LicenseError("bundled package missing from license manifest")
    names = {component["name"] for component in manifest["components"]}
    if not {"CPython", "PyInstaller", "Dragons AI Agent Scanner"} <= names:
        raise LicenseError("runtime, bootloader or application license missing")
    for component in manifest["components"]:
        if not component["version"] or not component["license_files"]:
            raise LicenseError("component version/license is missing")
        if not set(component["license_files"]) <= manifest["files"].keys():
            raise LicenseError("component references absent license text")
    return manifest
