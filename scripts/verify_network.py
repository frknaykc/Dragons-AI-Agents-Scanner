"""Hosted, non-privileged observation of default standalone scans; no scanned code is run."""

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from pathlib import Path
from typing import Any

from scripts.build_standalone import ARCHITECTURES, ROOT, artifact_name
from scripts.smoke_standalone import check_native_binary, runtime_environment

# strace follows the whole child tree and includes unsuccessful system calls. Never publish its
# raw output: syscall arguments may contain environment-dependent information.
INET = re.compile(r"\b(?:connect|sendto|sendmsg|sendmmsg)\([^\n]*\bAF_INET6?\b")
PID = re.compile(r"^\s*(\d+)\s+(\d+\.\d+)\s+")


def trace_events(text: str) -> list[dict[str, str]]:
    """Reduce raw Linux syscalls to payload-free, process-attributed event classes."""
    events = []
    first: float | None = None
    for line in text.splitlines():
        match = PID.match(line)
        if match is None:
            if INET.search(line):
                raise ValueError("strace output lacks process attribution")
            continue
        stamp = float(match.group(2))
        if first is None:
            first = stamp
        if not INET.search(line):
            continue
        kind = "tcp_or_udp_connect" if "connect(" in line else "datagram_send"
        destination = "loopback" if re.search(r"127\.0\.0\.1|::1", line) else "other_or_unknown"
        events.append(
            {
                "pid": match.group(1),
                "type": kind,
                "relative_ms": str(round((stamp - first) * 1000)),
                "destination_class": destination,
            }
        )
    return events


def loopback_probe(port: int, udp: bool = False, hold: float = 0) -> list[str]:
    """Command for an independent child process, not an artifact-supplied command."""
    code = (
        "import socket,time,sys; "
        "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM if sys.argv[2]=='udp' "
        "else socket.SOCK_STREAM); "
        "s.sendto(b'probe',('127.0.0.1',int(sys.argv[1]))) if sys.argv[2]=='udp' "
        "else s.connect(('127.0.0.1',int(sys.argv[1]))); "
        "time.sleep(float(sys.argv[3])); s.close()"
    )
    return [sys.executable, "-c", code, str(port), "udp" if udp else "tcp", str(hold)]


def observe_linux(
    command: list[str], cwd: Path, env: dict[str, str]
) -> tuple[int, str, list[dict[str, str]], str]:
    if not shutil.which("strace"):
        raise RuntimeError("strace unavailable on runner")
    with tempfile.TemporaryDirectory(prefix="dragons-trace-") as temp:
        trace = Path(temp) / "network.log"
        result = subprocess.run(
            [
                "strace",
                "-f",
                "-qq",
                "-ttt",
                "-s",
                "0",
                "-e",
                "trace=connect,sendto,sendmsg,sendmmsg",
                "-o",
                str(trace),
                *command,
            ],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        raw = trace.read_text(encoding="utf-8", errors="replace") if trace.exists() else ""
        if result.returncode == 1 and "ptrace" in result.stderr.lower():
            raise RuntimeError("strace ptrace unavailable on runner")
        if not trace.exists():
            raise RuntimeError("strace did not produce an observation trace")
        return result.returncode, result.stdout, trace_events(raw), result.stderr


def socket_snapshot(pid: int) -> bool:
    """Poll established TCP sockets only; never claim failed-attempt or UDP coverage."""
    if sys.platform == "win32":
        output = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=10, check=True
        ).stdout
        return any(
            row.split()[-1] == str(pid) and "ESTABLISHED" in row.upper()
            for row in output.splitlines()
            if row.split()
        )
    output = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:ESTABLISHED"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    ).stdout
    return any("ESTABLISHED" in line for line in output.splitlines())


def observe_poll(
    command: list[str], cwd: Path, env: dict[str, str]
) -> tuple[int, str, list[dict[str, str]], str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    events: list[dict[str, str]] = []
    started = time.monotonic()
    try:
        while process.poll() is None:
            if socket_snapshot(process.pid):
                events.append(
                    {
                        "pid": str(process.pid),
                        "type": "established_tcp_sample",
                        "relative_ms": str(round((time.monotonic() - started) * 1000)),
                        "destination_class": "unknown",
                    }
                )
            time.sleep(0.05)
        stdout, stderr = process.communicate(timeout=10)
        return (
            process.returncode,
            stdout.decode("utf-8", "replace"),
            events,
            stderr.decode("utf-8", "replace"),
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def positive_controls(observer: Any, runtime: Path, env: dict[str, str]) -> dict[str, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted: list[bool] = []
        release = threading.Event()

        def accept() -> None:
            listener.settimeout(8)
            with listener.accept()[0]:
                accepted.append(True)
                release.wait(timeout=6)

        worker = threading.Thread(target=accept)
        worker.start()
        try:
            status, _, tcp, _ = observer(loopback_probe(port, hold=2), runtime, env)
        finally:
            release.set()
            worker.join(timeout=9)
        if status != 0 or not accepted or not tcp:
            raise RuntimeError(
                "TCP positive control failed: connection or process attribution absent"
            )
        controls = {"tcp_loopback": True}
    if observer is observe_linux:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            status, _, events, _ = observer(
                loopback_probe(udp.getsockname()[1], udp=True), runtime, env
            )
            udp.settimeout(4)
            received, _ = udp.recvfrom(16)
            if status != 0 or received != b"probe" or not events:
                raise RuntimeError("UDP positive control failed")
            controls["udp_loopback"] = True
    return controls


def main() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    target = ARCHITECTURES[(sys.platform.lower(), platform.machine().lower())]
    expected_arch = "ARM64" if target == "macos-arm64" else "X64"
    assert os.environ.get("RUNNER_ARCH") == expected_arch
    assert (
        os.environ.get("RUNNER_OS")
        == {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}[sys.platform]
    )
    binary = ROOT / "dist" / artifact_name(sys.platform, platform.machine(), version)
    check_native_binary(binary, target)
    observer = observe_linux if sys.platform == "linux" else observe_poll
    result: dict[str, Any] = {
        "commit": os.environ.get("GITHUB_SHA"),
        "runner": os.environ.get("RUNNER_NAME"),
        "runner_os": os.environ["RUNNER_OS"],
        "runner_arch": os.environ["RUNNER_ARCH"],
        "platform": target,
        "observer": "strace child-tree network syscalls"
        if sys.platform == "linux"
        else "netstat established-TCP polling"
        if sys.platform == "win32"
        else "lsof established-TCP polling",
        "observer_version": "unknown",
        "privileges": "runner user only",
        "positive_controls": {},
        "scans": {},
        "verdict": "INCONCLUSIVE — MONITORING LIMITATION",
        "blind_spots": (
            [
                "DNS via local non-socket resolver or untraced kernel path",
                "TLS/HTTP payloads not inspected",
            ]
            if sys.platform == "linux"
            else [
                "brief connections between samples",
                "connection attempts that do not establish",
                "UDP/DNS and child processes",
                "HTTP payloads not inspected",
            ]
        ),
    }
    if sys.platform == "linux":
        version_result = (
            subprocess.run(["strace", "-V"], capture_output=True, text=True, check=False)
            if shutil.which("strace")
            else None
        )
        result["observer_version"] = (
            version_result.stdout.splitlines()[0]
            if version_result and version_result.returncode == 0
            else "unavailable"
        )
    else:
        result["observer_version"] = "OS-provided tool on " + platform.platform()
    with tempfile.TemporaryDirectory(prefix="dragons-offline-") as temp:
        runtime = Path(temp)
        executable = runtime / binary.name
        shutil.copy2(binary, executable)
        check_native_binary(executable, target)
        shutil.copyfile(
            ROOT / "benchmarks/corpus/benign-credential-guide/AGENTS.md", runtime / "AGENTS.md"
        )
        shutil.copyfile(
            ROOT / "benchmarks/corpus/quality-instruction-safety-bypass/SKILL.md",
            runtime / "SKILL.md",
        )
        (runtime / "mcp.json").write_text(
            json.dumps({"mcpServers": {"remote": {"url": "http://127.0.0.1:38741/mcp"}}}),
            encoding="utf-8",
        )
        (runtime / "SOUL.md").write_text(
            "# Local text\nReference URL: http://127.0.0.1:38742/guide\n", encoding="utf-8"
        )
        env = runtime_environment(dict(os.environ), sys.platform)
        env["HOME" if sys.platform != "win32" else "USERPROFILE"] = str(runtime)
        env["TMPDIR" if sys.platform != "win32" else "TEMP"] = str(runtime)
        try:
            result["positive_controls"] = positive_controls(observer, runtime, env)
            for label, fixture in (
                ("clean", "AGENTS.md"),
                ("finding", "SKILL.md"),
                ("mcp", "mcp.json"),
                ("url_text", "SOUL.md"),
            ):
                started = time.monotonic()
                status, output, events, _ = observer(
                    [str(executable), "scan", fixture, "--format", "json"], runtime, env
                )
                report = json.loads(output)
                valid = status == 0 and report["scan_status"] == "complete" and not report["errors"]
                ids = [item["detection_id"] for item in report["findings"]]
                if label == "clean":
                    valid = valid and not ids and report["policy"]["status"] == "pass"
                if label == "finding":
                    valid = (
                        valid
                        and len(ids) == 1
                        and ids[0] == "DRAGON-PI-002"
                        and report["findings"][0]["line"] == 3
                    )
                result["scans"][label] = {
                    "command": "dragonscan scan " + fixture + " --format json",
                    "exit_code": status,
                    "contract_ok": valid,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "events": {
                        kind: sum(event["type"] == kind for event in events)
                        for kind in sorted({event["type"] for event in events})
                    },
                    "event_metadata": events[:200],
                    "event_metadata_truncated": len(events) > 200,
                    "process_attribution": "trace PID/child tree"
                    if sys.platform == "linux"
                    else "sampled direct PID",
                }
                if not valid:
                    raise RuntimeError("scan contract failed: " + label)
            if sys.platform == "linux":
                result["verdict"] = (
                    "NETWORK ACTIVITY DETECTED"
                    if any(scan["events"] for scan in result["scans"].values())
                    else "VERIFIED — NO OUTBOUND CONNECTION OBSERVED"
                )
            elif any(scan["events"] for scan in result["scans"].values()):
                result["verdict"] = "NETWORK ACTIVITY DETECTED"
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            result["verdict"] = (
                "BLOCKED — RUNNER CAPABILITY"
                if not result["positive_controls"]
                else "INCONCLUSIVE — MONITORING LIMITATION"
            )
            result["failure"] = str(exc).split(":", 1)[0][:80]
    output_path = ROOT / "network-validation.json"
    output_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if len(result["scans"]) != 4 or not all(
        scan["contract_ok"] for scan in result["scans"].values()
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
