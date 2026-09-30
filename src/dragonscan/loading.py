"""Bounded, non-executing reads of untrusted artifacts."""

import os
import stat
from pathlib import Path

MAX_BYTES = 1_048_576


class LoadError(ValueError):
    """Artifact cannot be read safely."""


def load_text(path: Path) -> str:
    return load_text_with_bytes(path)[0]


def load_text_with_bytes(path: Path) -> tuple[str, bytes]:
    """Return the parsed text and exact bounded file bytes for identity checks."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise LoadError("artifact is not a regular file")
        if before.st_size > MAX_BYTES:
            raise LoadError("artifact exceeds 1 MiB limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise LoadError("artifact changed during load")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise LoadError("artifact exceeds 1 MiB limit")
            if b"\x00" in data:
                raise LoadError("artifact contains binary data")
            return data.decode("utf-8-sig"), data
        finally:
            os.close(fd)
    except (OSError, UnicodeError) as exc:
        raise LoadError(f"cannot read artifact: {type(exc).__name__}") from exc
