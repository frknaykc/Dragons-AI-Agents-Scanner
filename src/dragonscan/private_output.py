"""Private report files, secured before any report bytes are written.

POSIX uses exclusive creation with mode 0600. Windows uses a protected DACL
for the current process user, SYSTEM and Administrators, without inherited ACEs.
Callers must select a trusted output directory; directory owners/administrators
can still rename or delete entries and privileged users can take ownership.
"""

import os
import uuid
from pathlib import Path


def _create(path: Path) -> int:
    if os.name == "nt":
        from dragonscan.windows_output import create_private_file

        return create_private_file(path)
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)


def write_private_report(path: Path, text: str, *, overwrite: bool = False) -> None:
    """Create exclusively, or atomically replace without following the old file.

    Replacement uses a secured sibling file on the same filesystem. Existing data
    is preserved on write/replace failure. Never fall back to insecure creation.
    """
    temporary = path.with_name(f".dragonscan-{uuid.uuid4().hex}") if overwrite else path
    descriptor = _create(temporary)
    try:
        try:
            handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(descriptor)
            raise
        with handle:
            handle.write(text)
        if overwrite:
            os.replace(temporary, path)
    except BaseException:
        # Do not let cleanup expose an OS error containing report paths/content.
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
