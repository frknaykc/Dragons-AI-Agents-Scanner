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

# Reviewed original upstream bytes, provisioned explicitly before an offline build.
CPYTHON_NOTICES_URL = "https://raw.githubusercontent.com/python/cpython/v3.12.12/Doc/license.rst"
PBS_SOURCE_URL = (
    "https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/refs/tags/20260211"
)
HACL_NOTICE_URL = (
    "https://raw.githubusercontent.com/python/cpython/v3.12.12/Modules/_hacl/Hacl_Hash_SHA2.h"
)
KARAMEL_NOTICE_URL = (
    "https://raw.githubusercontent.com/python/cpython/v3.12.12/"
    "Modules/_hacl/include/krml/internal/target.h"
)
# Revision recorded by CPython v3.12.12 Modules/_hacl/refresh.sh (read as data).
KARAMEL_LICENSE_URL = (
    "https://raw.githubusercontent.com/hacl-star/hacl-star/"
    "bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0/LICENSE"
)
CPYTHON_EMBEDDED_NOTICES = {
    "HACL-MIT.txt": (HACL_NOTICE_URL, True),
    "KaRaMeL-NOTICE.txt": (KARAMEL_NOTICE_URL, True),
    "KaRaMeL-LICENSE.txt": (KARAMEL_LICENSE_URL, False),
}
LIBFFI_UNIX_URL = "https://raw.githubusercontent.com/libffi/libffi/v3.4.6/LICENSE"
LIBFFI_WINDOWS_URL = (
    "https://raw.githubusercontent.com/python/cpython-source-deps/"
    "16fad4855b3d8c03b5910e405ff3a04395b39a98/LICENSE"
)
MPDECIMAL_URL = "https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-4.0.0.tar.gz"
NCURSES_URL = "https://astral-sh.github.io/mirror/files/ncurses-6.5.tar.gz"
# Supplements for the reviewed 3.12.12 / 20260211 runtime only. Preserve the
# vendor candidate collection separately; it contains outdated copyright years.
RUNTIME_SUPPLEMENTS = (
    ("libffi", "3.4.6", LIBFFI_UNIX_URL, None, ("linux", "darwin")),
    ("libffi", "3.4.2", LIBFFI_WINDOWS_URL, None, ("win32",)),
    ("mpdecimal", "4.0.0", MPDECIMAL_URL, "mpdecimal-4.0.0/COPYRIGHT.txt", ("linux", "darwin")),
    ("ncurses", "6.5", NCURSES_URL, "ncurses-6.5/COPYING", ("linux",)),
)
SOURCE_DIGESTS = {
    CPYTHON_NOTICES_URL: "341832873fd316a37927e79385093fbbfd40a467428480835fe435a80cadf4e5",
    PBS_SOURCE_URL: "a70d814140fb061d5724c477aeecfdf263e890d3a3515546763adc727f929628",
    HACL_NOTICE_URL: "093d7693084af0999d2a13d207311d74b5bdfdc9c08447ed4a979e3f7505ae6b",
    KARAMEL_NOTICE_URL: "d16a59f37a1d4982626870e370889eb9d332a9ad035661b8062f549fc734d061",
    KARAMEL_LICENSE_URL: "c5accbbd8546e94c34aed24afe689a617627d18eed5a6c48277e48db57c23851",
    LIBFFI_UNIX_URL: "67894089811f93fca47a76f85e017da6f8582d4ba0905963c6e0f1ad6df7a195",
    LIBFFI_WINDOWS_URL: "a61d06e8f7be57928e71e800eb9273b05cb8868c484108afe41e4305bb320dde",
    MPDECIMAL_URL: "942445c3245b22730fd41a67a7c5c231d11cb1b9936b9c0f76334fb7d0b4468c",
    NCURSES_URL: "136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6",
}

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
        normalized = name.replace("\\", "/")
        # Windows CArchive can store copied distribution metadata as type 'b'.
        # These are attribution/metadata files, not additional native libraries;
        # the distribution's actual Python/native modules still require notices.
        if (
            kind == b"b"
            and normalized != "base_library.zip"
            and not normalized.split("/")[0].endswith((".dist-info", ".egg-info"))
        ):
            native.add(normalized)
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
    if target.is_symlink():
        raise LicenseError("symlinked license source cache")
    if not target.is_file():
        if target.exists():
            raise LicenseError("license source cache is not a regular file")
        return None
    expected = SOURCE_DIGESTS.get(url)
    if expected is None:
        raise LicenseError(f"offline license source is not pinned: {url}")
    with target.open("rb") as source:
        data = source.read(8 * 1024 * 1024 + 1)
    if not data.strip() or len(data) > 8 * 1024 * 1024:
        raise LicenseError(f"invalid/oversized offline license source: {url}")
    if digest(data) != expected:
        raise LicenseError(f"offline license source checksum mismatch: {url}")
    return data


def runtime_supplements(cache: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Copy authentic platform-specific notices without extracting source code."""
    components: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for name, version, url, member, platforms in RUNTIME_SUPPLEMENTS:
        if sys.platform not in platforms:
            continue
        original = cached_source(url, cache)
        if original is None:
            unresolved.append("Missing reviewed runtime supplement: " + url)
            continue
        content = original
        if member is not None:
            with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as archive:
                item = archive.getmember(member)
                if not item.isfile() or not 0 < item.size <= 128 * 1024:
                    raise LicenseError("invalid runtime supplement member: " + member)
                stream = archive.extractfile(item)
                assert stream is not None
                content = stream.read()
        if not content.strip():
            raise LicenseError("empty runtime supplement: " + url)
        components.append(
            {
                "name": "reviewed runtime " + name,
                "version": version,
                "scope": "platform-specific PBS 20260211 / CPython 3.12.12 notice supplement",
                "source": url,
                "source_sha256": digest(original),
                "files": {f"{name}-{version}.txt": content},
            }
        )
    return components, unresolved


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
    if version != "3.12.12":
        unresolved.append("Unreviewed CPython embedded notices: " + version)
    else:
        for filename, (source_url, header_only) in CPYTHON_EMBEDDED_NOTICES.items():
            original = cached_source(source_url, cache)
            if original is None:
                unresolved.append("Missing CPython embedded notice: " + source_url)
                continue
            content = original
            if header_only:
                end = original.find(b"*/")
                if not original.startswith(b"/*") or end < 0 or not original[2:end].strip():
                    raise LicenseError("invalid CPython embedded notice header: " + source_url)
                content = original[: end + 2]  # Exact original comment; never copy code.
            components.append(
                {
                    "name": "CPython embedded " + filename,
                    "version": version,
                    "scope": "vendored HACL*/KaRaMeL runtime notices",
                    "source": source_url,
                    "source_sha256": digest(original),
                    "files": {filename: content},
                }
            )
    if sys.platform == "win32":
        unresolved.append(
            "Review the exact bundled Microsoft runtime DLL versions and their "
            "redistribution terms; CPython's license is not a CRT license."
        )
    build = prefix / "BUILD"
    if build.is_file() and re.fullmatch(r"\d{8}", build.read_text().strip()):
        tag = build.read_text().strip()
        if tag == "20260211" and version == "3.12.12":
            supplements, missing = runtime_supplements(cache)
            components.extend(supplements)
            unresolved.extend(missing)
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
