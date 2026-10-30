"""Real report writers and native ACL inspection; all inputs are inert."""

import ctypes
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import report_permissions
from click.testing import CliRunner
from report_permissions import assert_private, set_windows_dacl, windows_sddl

from dragonscan import cli, private_output
from dragonscan.models import ScanReport
from dragonscan.policy import evaluate


@pytest.mark.parametrize("alias", ["LA", "S-1-5-21-100-200-300-500"])
@pytest.mark.parametrize("invalid", [None, "wrong-owner", "extra-grant", "inherited"])
def test_permission_inspection_compares_full_sid_without_relaxing_acl(monkeypatch, alias, invalid):
    sid = "S-1-5-21-100-200-300-500"
    sddl = f"O:{alias}D:P(A;;FA;;;{alias})(A;;FA;;;SY)(A;;FA;;;BA)"
    if invalid == "extra-grant":
        sddl += "(A;;FR;;;WD)"
    if invalid == "inherited":
        sddl = sddl.replace("D:P", "D:")
    actual_owner = "S-1-5-21-100-200-300-1001" if invalid == "wrong-owner" else sid
    monkeypatch.setattr(report_permissions, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(report_permissions, "windows_security", lambda path: (sddl, actual_owner))
    monkeypatch.setattr(report_permissions, "windows_process_sid", lambda: sid)
    if invalid:
        with pytest.raises(AssertionError):
            assert_private(Path("inert.json"))
    else:
        assert_private(Path("inert.json"))


@pytest.mark.parametrize("failure", ["security-query", "acl-mismatch", "crt-transfer"])
def test_native_creation_fails_closed_before_writing(tmp_path, monkeypatch, failure):
    from dragonscan import windows_output

    destination = tmp_path / "report.json"
    destination.write_text("original")
    if os.name != "nt":
        # This branch checks only the platform guard, not native Windows behavior.
        with pytest.raises(OSError, match="require Windows"):
            windows_output.create_private_file(tmp_path / "new.json")
        assert not (tmp_path / "new.json").exists()
        return

    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    query = advapi.GetSecurityInfo
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_ulong,
        *([ctypes.POINTER(ctypes.c_void_p)] * 5),
    ]
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    observed, closed = [], []

    def observe(handle):
        (temporary,) = tmp_path.glob(".dragonscan-*")
        assert temporary.stat().st_size == 0
        observed.append(handle)

    def checked_query(handle, kind, flags, *args):
        observe(handle)
        if failure == "security-query":
            return 5  # ERROR_ACCESS_DENIED
        # A real owner-only descriptor omits the required DACL, forcing mismatch.
        return query(handle, kind, 1 if failure == "acl-mismatch" else flags, *args)

    def checked_close(handle):
        closed.append(handle)
        return close(handle)

    def failed_transfer(handle, flags):
        observe(handle)
        raise OSError("inert CRT transfer failure")

    monkeypatch.setattr(advapi, "GetSecurityInfo", checked_query)
    monkeypatch.setattr(kernel, "CloseHandle", checked_close)
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **kw: {"kernel32": kernel, "advapi32": advapi}[name]
    )
    if failure == "crt-transfer":
        monkeypatch.setattr(msvcrt, "open_osfhandle", failed_transfer)
    with pytest.raises(OSError):
        private_output.write_private_report(destination, "sensitive inert bytes", overwrite=True)
    assert observed and all(handle in closed for handle in observed)
    assert destination.read_text() == "original"
    assert not list(tmp_path.glob(".dragonscan-*"))


@pytest.mark.parametrize("fmt", ["json", "sarif"])
@pytest.mark.parametrize("overwrite", [False, True])
def test_cli_exports_are_private(tmp_path: Path, fmt: str, overwrite: bool) -> None:
    source = tmp_path / "SKILL.md"
    source.write_text("Ordinary local instructions")
    destination = tmp_path / f"report.{fmt}"
    if overwrite:
        destination.write_text("old report")  # default inherited ACL / umask
        if os.name != "nt":
            destination.chmod(0o644)
    result = CliRunner().invoke(
        cli.main, ["scan", str(source), "--format", fmt, "--output", str(destination)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(destination.read_text())
    assert_private(destination)
    assert not list(tmp_path.glob(".dragonscan-*"))


def test_private_before_first_write_and_after_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("old")
    replace = os.replace
    observed = []

    def checked_replace(source: Path, target: Path) -> None:
        assert_private(source)
        observed.append(source)
        replace(source, target)

    fdopen = os.fdopen

    def checked_open(descriptor: int, *args: object, **kwargs: object):
        (temporary,) = tmp_path.glob(".dragonscan-*")
        assert temporary.stat().st_size == 0
        assert_private(temporary)
        return fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(private_output.os, "fdopen", checked_open)
    monkeypatch.setattr(private_output.os, "replace", checked_replace)
    private_output.write_private_report(destination, "new", overwrite=True)
    assert observed and destination.read_text() == "new"
    assert_private(destination)


def test_exclusive_write_never_truncates_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    private_output.write_private_report(destination, "original")
    with pytest.raises(OSError):
        private_output.write_private_report(destination, "replacement")
    assert destination.read_text() == "original"
    assert_private(destination)


@pytest.mark.parametrize("failure", ["fdopen", "write", "replace"])
def test_failure_cleanup_preserves_old_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("original")
    original_fdopen = os.fdopen

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EACCES, "synthetic-sensitive-error-do-not-disclose")

    if failure == "write":

        class BrokenWriter:
            def __init__(self, fd: int):
                self.handle = original_fdopen(fd, "w")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.handle.close()

            write = fail

        monkeypatch.setattr(private_output.os, "fdopen", lambda fd, *args, **kw: BrokenWriter(fd))
    else:
        monkeypatch.setattr(private_output.os, failure, fail)
    source = tmp_path / "SKILL.md"
    source.write_text("Ordinary instructions")
    result = CliRunner().invoke(
        cli.main, ["scan", str(source), "--format", "json", "--output", str(destination)]
    )
    assert result.exit_code == 3
    assert "Report output failed" in result.output
    assert "synthetic-sensitive-error" not in result.output
    assert destination.read_text() == "original"
    assert not list(tmp_path.glob(".dragonscan-*"))


def test_installed_auto_report_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    report = ScanReport(tmp_path, (), ())
    path = cli._save_installed_report(report, evaluate(report))
    assert_private(path)


def test_parent_grants_are_not_inherited_by_reports(tmp_path: Path) -> None:
    directory = tmp_path / "shared"
    directory.mkdir()
    original = windows_sddl(directory) if os.name == "nt" else ""
    previous_umask = os.umask(0)
    try:
        if os.name == "nt":
            set_windows_dacl(directory, "D:P(A;OICI;FA;;;WD)")
        else:
            directory.chmod(0o777)
        destination = directory / "report.json"
        private_output.write_private_report(destination, "inert evidence")
        assert_private(destination)
    finally:
        os.umask(previous_umask)
        if os.name == "nt":
            set_windows_dacl(directory, original)
        else:
            directory.chmod(0o700)


def test_atomic_overwrite_does_not_modify_hardlink_target(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.write_text("original")
    destination = tmp_path / "report.json"
    os.link(original, destination)
    private_output.write_private_report(destination, "new report", overwrite=True)
    assert original.read_text() == "original"
    assert destination.read_text() == "new report"
    assert_private(destination)


def test_restricted_and_denied_directory(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    source = tmp_path / "SKILL.md"
    source.write_text("Ordinary instructions")
    destination = directory / "report.json"
    private_output.write_private_report(destination, "original")
    assert_private(destination)
    original = windows_sddl(directory) if os.name == "nt" else ""
    if os.name == "nt":
        owner = windows_sddl(destination).removeprefix("O:").split("D:")[0]
        set_windows_dacl(
            directory, f"D:P(D;;GW;;;{owner})(A;;FA;;;{owner})(A;;FA;;;SY)(A;;FA;;;BA)"
        )
    else:
        directory.chmod(0o500)
    try:
        result = CliRunner().invoke(
            cli.main, ["scan", str(source), "--format", "json", "--output", str(destination)]
        )
        assert result.exit_code == 3, result.output
        assert "Report output failed" in result.output
        assert destination.read_text() == "original"
        assert not list(directory.glob(".dragonscan-*"))
    finally:
        if os.name == "nt":
            set_windows_dacl(directory, original)
        else:
            directory.chmod(0o700)
