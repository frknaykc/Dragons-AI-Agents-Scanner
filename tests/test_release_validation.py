"""Safety boundaries of the opt-in inert release verifier, not product behavior."""

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
validation = importlib.import_module("scripts.release_validation")


def test_release_runtime_environment_drops_credentials_and_user_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "inert-test-placeholder")
    monkeypatch.setenv("PYTHONPATH", "unrelated-path")
    monkeypatch.setenv("HOME", "unrelated-home")
    monkeypatch.setenv("SYSTEMROOT", "C:\\Windows")
    environment = validation.clean_environment(tmp_path)
    assert "OPENAI_API_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["HOME"] == environment["USERPROFILE"] == str(tmp_path)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["TEMP"] == environment["TMPDIR"] == str(tmp_path)


def test_release_selection_excludes_execution_and_network_integrations() -> None:
    assert {
        "subprocess.Popen",
        "os.system",
        "socket.connect",
        "socket.bind",
        "socket.sendto",
    } <= validation.DENIED
    assert "test_tui_keyboard.py" in validation.SAFE_TESTS
    assert not any(
        word in name
        for name in validation.SAFE_TESTS
        for word in ("dynamic", "provider", "network", "osv", "distribution", "phase4")
    )
    assert all((ROOT / "tests" / name).is_file() for name in validation.SAFE_TESTS)


def test_windows_ipc_exception_requires_exact_stdlib_call_chain(monkeypatch):
    from asyncio.proactor_events import BaseProactorEventLoop

    def inert_socketpair():
        pass

    monkeypatch.setattr(validation.sys, "platform", "win32")
    monkeypatch.setattr(validation.socket, "socketpair", inert_socketpair)
    caller = SimpleNamespace(
        f_code=inert_socketpair.__code__,
        f_back=SimpleNamespace(f_code=BaseProactorEventLoop._make_self_pipe.__code__),
    )
    assert validation.is_asyncio_self_pipe("socket.bind", (None, ("127.0.0.1", 0)), caller)
    assert validation.is_asyncio_self_pipe("socket.connect", (None, ("::1", 1234)), caller)
    for event, args, frame in (
        ("socket.connect", (None, ("192.0.2.1", 1234)), caller),
        ("socket.bind", (None, ("0.0.0.0", 0)), caller),
        ("socket.getaddrinfo", (None, ("127.0.0.1", 0)), caller),
        ("subprocess.Popen", (), caller),
        ("socket.connect", (None, ("127.0.0.1", 1234)), None),
        ("socket.connect", (), caller),
    ):
        assert not validation.is_asyncio_self_pipe(event, args, frame)
    caller.f_back.f_code = inert_socketpair.__code__
    assert not validation.is_asyncio_self_pipe("socket.connect", (None, ("127.0.0.1", 1)), caller)
