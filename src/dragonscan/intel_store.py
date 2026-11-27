"""Serialize local feed writers; the release and its authentication are one atomic file."""

import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class FeedError(ValueError):
    """Invalid optional intelligence or unsuccessful explicit update."""


def _check_ancestors(path: Path) -> None:
    # Trusted state cannot live under a directory replaceable by another user.
    # Sticky root-owned temp dirs are safe for a checked user-owned child.
    for parent in path.absolute().parents:
        if not parent.exists():
            continue
        meta = parent.lstat()
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid not in {0, os.getuid()}
            or (meta.st_mode & 0o022 and not meta.st_mode & stat.S_ISVTX)
        ):
            raise FeedError("unsafe intelligence state ancestor permissions")


@contextmanager
def locked_store(store: Path) -> Iterator[None]:
    if os.name != "posix":
        raise FeedError(
            "intelligence updates require verified store permissions; Windows ACLs are unsupported"
        )
    import fcntl

    if any(p.is_symlink() for p in (store, *store.parents)):
        raise FeedError("store symlink not allowed")
    try:
        _check_ancestors(store)
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(store, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        try:
            meta = os.fstat(fd)
            if meta.st_mode & 0o022 or meta.st_uid != os.getuid():
                raise FeedError("store must be owned by this user and not group/world writable")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)
    except OSError as exc:
        raise FeedError(f"intelligence store unavailable ({type(exc).__name__})") from None


def read_bounded(path: Path, maximum: int, *, trusted: bool = False) -> bytes:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise FeedError("feed symlink not allowed")
    try:
        if trusted:
            if os.name != "posix":
                raise FeedError("cannot verify signer policy permissions")
            _check_ancestors(path)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise FeedError("feed is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags | getattr(os, "O_NONBLOCK", 0)), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
                raise FeedError("feed changed during load")
            if trusted and (opened.st_uid not in {0, os.getuid()} or opened.st_mode & 0o022):
                raise FeedError("unsafe signer policy permissions")
            raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                raise FeedError("feed size limit exceeded")
            return raw
    except OSError as exc:
        raise FeedError(f"feed unavailable ({type(exc).__name__})") from None


def atomic_write(path: Path, raw: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix=".intel-", dir=path.parent) as name:
        staged = Path(name) / "release"
        with staged.open("xb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, path)


def check_version(old: str, new: str, old_hash: str, new_hash: str) -> None:
    def numeric(version: str) -> tuple[int, ...]:
        numbers = tuple(int(part) for part in version.split("."))
        return numbers + (0,) * (3 - len(numbers))

    if numeric(new) < numeric(old):
        raise FeedError("feed version downgrade blocked")
    if numeric(new) == numeric(old) and new_hash != old_hash:
        raise FeedError("different content at the same version")
