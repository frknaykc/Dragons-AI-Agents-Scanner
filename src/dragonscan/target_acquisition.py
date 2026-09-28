"""Explicit, bounded target acquisition. Acquired bytes are data, never executed."""

import http.client
import ipaddress
import lzma
import os
import re
import socket
import ssl
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlsplit

from dragonscan.discovery import (
    CONFIG_STEMS,
    DEPENDENCY_FILES,
    INSTRUCTION_NAMES,
    MCP_NAMES,
    DiscoveryError,
    classify,
)

MAX_INPUT = 32 * 1024 * 1024
MAX_DOWNLOAD = MAX_INPUT
MAX_MEMBERS = 2048
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_DEPTH = 16
MAX_PATH = 1024
MAX_REDIRECTS = 3
CHUNK = 64 * 1024
ARCHIVES = (".zip", ".tar", ".tar.gz", ".tgz")
REMOTE_NAMES = (
    INSTRUCTION_NAMES
    | MCP_NAMES
    | DEPENDENCY_FILES.keys()
    | {"settings.local.json", "claude.json", "requirements.txt", "requirements.in"}
    | {
        f"{stem}.{extension}"
        for stem in CONFIG_STEMS
        for extension in ("json", "yaml", "yml", "toml")
    }
)


class AcquisitionError(ValueError):
    """Untrusted acquisition could not satisfy the static-scan policy."""


class AcquisitionCleanupError(OSError):
    """Temporary workspace cleanup failed after scanning."""


@dataclass(frozen=True)
class AcquiredTarget:
    path: Path | None
    source: str
    kind: str
    status: str  # completed, partial, blocked, failed
    diagnostics: tuple[str, ...] = ()
    root: Path | None = None  # Only set for extracted archives


def _archive(name: str) -> bool:
    return name.lower().endswith(ARCHIVES)


def _member(name: str, root: Path) -> Path:
    if (
        not name
        or len(name) > MAX_PATH
        or "\\" in name
        or ":" in name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
        or name.startswith("/")
    ):
        raise AcquisitionError("unsafe archive member name")
    parts = PurePosixPath(name.rstrip("/")).parts
    if (
        not parts
        or len(parts) > MAX_DEPTH
        or any(part in {".", ".."} or len(part) > 255 for part in parts)
    ):
        raise AcquisitionError("unsafe archive member name or depth limit")
    # PurePosixPath collapses '.' and empty components: reject ambiguous spelling first.
    if any(part in {"", ".", ".."} for part in name.rstrip("/").split("/")):
        raise AcquisitionError("unsafe archive member name")
    destination = root.joinpath(*parts)
    if not destination.is_relative_to(root):
        raise AcquisitionError("archive member outside extraction root")
    return destination


def _extract(path: Path, root: Path) -> tuple[str, tuple[str, ...]]:
    seen: dict[str, bool] = {}  # casefolded relative path -> directory?
    spellings: dict[str, str] = {}
    total = 0
    count = 0
    skipped = False
    diagnostics: set[str] = set()

    def accept(name: str, size: int, directory: bool, regular: bool) -> Path | None:
        nonlocal count, total, skipped
        count += 1
        if count > MAX_MEMBERS:
            raise AcquisitionError("archive member limit exceeded")
        if not regular and not directory:
            skipped = True
            diagnostics.add("unsafe archive member skipped")
            return None
        try:
            destination = _member(name, root)
        except AcquisitionError:
            skipped = True
            diagnostics.add("unsafe archive member skipped")
            return None
        relative = destination.relative_to(root)
        key = str(relative).casefold()
        original_parents = [str(Path(*relative.parts[:i])) for i in range(1, len(relative.parts))]
        parents = [parent.casefold() for parent in original_parents]
        if (
            key in seen
            or any(parent in seen and not seen[parent] for parent in parents)
            or any(
                parent in spellings and spellings[parent] != original
                for parent, original in zip(parents, original_parents, strict=True)
            )
        ):
            skipped = True
            diagnostics.add("colliding archive member skipped")
            return None
        if size < 0 or size > MAX_MEMBER or total + size > MAX_TOTAL:
            raise AcquisitionError("archive uncompressed-size limit exceeded")
        # An implicit parent is recorded to prevent later file/dir collisions.
        for parent, original in zip(parents, original_parents, strict=True):
            seen.setdefault(parent, True)
            spellings.setdefault(parent, original)
        seen[key] = directory
        spellings[key] = str(relative)
        if not directory:
            total += size
        return destination

    def write(destination: Path, stream: object, size: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            with os.fdopen(fd, "wb") as output:
                remaining = size
                while remaining:
                    chunk = stream.read(min(CHUNK, remaining))  # type: ignore[attr-defined]
                    if not chunk:
                        raise AcquisitionError("archive member truncated")
                    output.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):  # type: ignore[attr-defined]
                    raise AcquisitionError("archive member exceeds declared size")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    try:
        if path.name.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                for item in archive.infolist():
                    mode = (item.external_attr >> 16) & 0xFFFF
                    special = item.create_system == 3 and stat.S_IFMT(mode) not in {
                        0,
                        stat.S_IFREG,
                        stat.S_IFDIR,
                    }
                    directory = item.is_dir()
                    if item.create_system == 3 and stat.S_IFMT(mode) in {
                        stat.S_IFREG,
                        stat.S_IFDIR,
                    }:
                        special = special or (stat.S_IFMT(mode) == stat.S_IFDIR) != directory
                    destination = accept(
                        item.filename,
                        item.file_size,
                        directory and not special,
                        not special and not directory,
                    )
                    if destination is None:
                        continue
                    if directory:
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        with archive.open(item) as stream:
                            write(destination, stream, item.file_size)
        else:
            with tarfile.open(path, "r:*") as tar:
                for tar_item in tar:
                    regular = (
                        tar_item.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
                        and not tar_item.sparse
                        and not any(key.startswith("GNU.sparse.") for key in tar_item.pax_headers)
                    )
                    destination = accept(tar_item.name, tar_item.size, tar_item.isdir(), regular)
                    if destination is None:
                        continue
                    if tar_item.isdir():
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        tar_stream = tar.extractfile(tar_item)
                        if tar_stream is None:
                            raise AcquisitionError("archive member unreadable")
                        with tar_stream:
                            write(destination, tar_stream, tar_item.size)
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        tarfile.TarError,
        struct.error,
        zlib.error,
        lzma.LZMAError,
        EOFError,
        UnicodeError,
        OSError,
        ValueError,
        RuntimeError,
        NotImplementedError,
    ) as exc:
        if isinstance(exc, AcquisitionError):
            raise
        raise AcquisitionError(f"archive parsing failed: {type(exc).__name__}") from None
    return ("partial" if skipped else "completed"), tuple(sorted(diagnostics))


def _public(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global


def validate_url(url: str) -> tuple[str, str, str]:
    """Return (host, pinned public address, request path). No network beyond DNS."""
    if len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise AcquisitionError("remote URL blocked: invalid characters or length")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise AcquisitionError("remote URL blocked: invalid authority") from None
    if (
        parsed.scheme != "https"
        or not host
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
        or not host.isascii()
        or not re.fullmatch(r"[A-Za-z0-9.:-]+", host)
    ):
        raise AcquisitionError("remote URL blocked: HTTPS public unauthenticated port 443 only")
    if parsed.path.lower().endswith(".git"):
        raise AcquisitionError("remote Git transport unavailable")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not _public(str(literal)):
        raise AcquisitionError("remote target blocked: private network destination")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = {str(entry[4][0]) for entry in addresses}
        if not ips or any(not _public(ip) for ip in ips):
            raise AcquisitionError("remote target blocked: private network destination")
    except (OSError, ValueError) as exc:
        if isinstance(exc, AcquisitionError):
            raise
        raise AcquisitionError("remote DNS resolution failed") from None
    return host, sorted(ips)[0], (parsed.path or "/")


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str):
        context = ssl.create_default_context()
        super().__init__(host, 443, timeout=8, context=context)
        self.ip = ip
        self.tls_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self.ip, 443), timeout=self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _download(url: str, destination: Path) -> str:
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        host, ip, route = validate_url(current)
        connection = _PinnedHTTPS(host, ip)
        try:
            connection.request(
                "GET",
                route,
                headers={
                    "Host": f"[{host}]" if ":" in host else host,
                    "Accept": "application/octet-stream",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                if hop == MAX_REDIRECTS:
                    raise AcquisitionError("remote redirect limit exceeded")
                location = response.getheader("Location")
                if not location:
                    raise AcquisitionError("remote redirect missing location")
                next_url = urljoin(current, location)
                validate_url(next_url)
                current = next_url
                continue
            if response.status != 200:
                raise AcquisitionError("remote download failed: HTTP status not successful")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_DOWNLOAD):
                raise AcquisitionError("download limit exceeded: Content-Length")
            declared_length = int(length) if length is not None else None
            with destination.open("xb") as output:
                received = 0
                while chunk := response.read(min(CHUNK, MAX_DOWNLOAD + 1 - received)):
                    received += len(chunk)
                    if received > MAX_DOWNLOAD:
                        raise AcquisitionError("download limit exceeded: response bytes")
                    output.write(chunk)
            if declared_length is not None and received != declared_length:
                raise AcquisitionError("remote download incomplete")
            return current
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            if isinstance(exc, AcquisitionError):
                raise
            raise AcquisitionError(f"remote download failed: {type(exc).__name__}") from None
        finally:
            connection.close()
    raise AcquisitionError("remote redirect limit exceeded")


def _copy_local(source: Path, destination: Path) -> None:
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT:
            raise AcquisitionError("archive input is not a bounded regular file")
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise AcquisitionError("archive changed during open")
            with os.fdopen(fd, "rb", closefd=False) as input_file, destination.open("xb") as output:
                copied = 0
                while chunk := input_file.read(CHUNK):
                    copied += len(chunk)
                    if copied > MAX_INPUT:
                        raise AcquisitionError("archive input limit exceeded")
                    output.write(chunk)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AcquisitionError(f"archive input inaccessible: {type(exc).__name__}") from None


@contextmanager
def acquire(target: str, *, remote: bool, git: bool) -> Iterator[AcquiredTarget]:
    """Only explicit targets enter this layer; temporary bytes die with the context."""
    if remote and git:
        yield AcquiredTarget(
            None, "remote Git", "git", "blocked", ("remote Git transport unavailable",)
        )
        return
    path = Path(target).absolute() if not remote else None
    name = ""
    static_name = ""
    if remote:
        try:
            parsed = urlsplit(target)
            if parsed.path.lower().endswith(".git"):
                raise AcquisitionError("remote Git transport unavailable")
            name = Path(parsed.path).name
            if not _archive(name) and classify(Path(name), explicit=True) is None:
                raise AcquisitionError("unsupported remote artifact name")
            if not _archive(name):
                static_name = name.lower()
                if static_name.startswith("requirements-") and static_name.endswith(
                    (".txt", ".in")
                ):
                    static_name = "requirements" + Path(static_name).suffix
                if static_name not in REMOTE_NAMES:
                    raise AcquisitionError("unsupported remote artifact name")
        except AcquisitionError as exc:
            yield AcquiredTarget(None, "remote target", "remote", "blocked", (str(exc),))
            return
        except ValueError:
            yield AcquiredTarget(
                None, "remote target", "remote", "blocked", ("invalid remote target",)
            )
            return
    else:
        assert path is not None
        if git:
            if path.is_symlink() or not path.is_dir() or not (path / ".git").exists():
                yield AcquiredTarget(
                    None, str(path), "git", "blocked", ("local Git working tree unavailable",)
                )
            else:
                yield AcquiredTarget(path, str(path), "git", "completed")
            return
        if not _archive(path.name):
            yield AcquiredTarget(path, str(path), "local", "completed")
            return
    try:
        temporary = tempfile.TemporaryDirectory(prefix="dragonscan-acquire-")
    except OSError:
        yield AcquiredTarget(
            None,
            "remote target" if remote else str(path),
            "remote" if remote else "archive",
            "failed",
            ("acquisition workspace unavailable",),
        )
        return
    try:
        workspace = Path(temporary.name)
        archive_name = name if remote else path.name if path is not None else ""
        original = workspace / (
            "input.zip" if archive_name.lower().endswith(".zip") else "input.tar"
        )
        extracted = workspace / "content"
        try:
            if remote:
                # Use fixed parser-eligible names, never raw server-provided filenames.
                if not _archive(name):
                    original = workspace / static_name
                _download(target, original)
                source_name = target
            else:
                assert path is not None
                _copy_local(path, original)
                source_name = str(path)
            if not _archive(archive_name):
                result = AcquiredTarget(original, source_name, "remote", "completed")
            else:
                extracted.mkdir(mode=0o700)
                status, diagnostics = _extract(original, extracted)
                result = AcquiredTarget(
                    extracted,
                    source_name,
                    "remote_archive" if remote else "archive",
                    status,
                    diagnostics,
                    extracted,
                )
        except (AcquisitionError, DiscoveryError) as exc:
            reason = str(exc)
            status = (
                "blocked"
                if any(
                    word in reason
                    for word in ("limit", "blocked", "unsupported", "unavailable", "unsafe")
                )
                else "failed"
            )
            result = AcquiredTarget(
                None,
                "remote target" if remote else str(path),
                "remote" if remote else "archive",
                status,
                (reason,),
            )
        yield result
    finally:
        try:
            temporary.cleanup()
        except OSError:
            raise AcquisitionCleanupError("acquisition workspace cleanup failed") from None
