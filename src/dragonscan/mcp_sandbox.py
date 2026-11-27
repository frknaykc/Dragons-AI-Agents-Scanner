"""Opt-in candidate backend: local Linux Docker Engine, never pull or auto-start it.

Only the private staged executable is mounted. The operator supplies an already
reviewed, secret-free local runtime image ID. Probe this daemon/image/flag set
with our own fixture before starting the selected executable.
"""

import os
import re
import select
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LIMIT = 16 << 20
_CLI = "/usr/bin/docker"
_SOCKET = "/var/run/docker.sock"


class IsolationError(ValueError):
    """Fixed local diagnostic, never target or engine output."""


def platform_check(image: str) -> None:
    if sys.platform != "linux":
        raise IsolationError("required isolation: only a native Linux daemon can be probed")
    if not _IMAGE.fullmatch(image):
        raise IsolationError("required isolation: supply a reviewed local sha256 image ID")
    if not hasattr(os, "pidfd_open") or not os.path.isfile(_CLI) or not Path(_SOCKET).is_socket():
        raise IsolationError("required isolation: native local Docker or Linux pidfds unavailable")


def _copy_executable(source: Path, staged: Path) -> None:
    if not source.is_absolute() or ".." in source.parts:
        raise IsolationError("invalid isolated executable path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        for part in source.parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as src:
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and 0 < st.st_size <= _LIMIT):
            raise IsolationError("invalid or oversized isolated executable")
        data = src.read(_LIMIT + 1)
        if len(data) != st.st_size or os.fstat(fd).st_ctime_ns != st.st_ctime_ns:
            raise IsolationError("isolated executable changed while staging")
    with staged.open("xb") as stream:
        stream.write(data)
    staged.chmod(0o555)


def _create_args(image: str, staged: Path, name: str) -> list[str]:
    if any(ch in str(staged) for ch in ',\n\r"'):
        raise IsolationError("unsupported isolated staging path")
    return [
        "create",
        "--pull=never",
        "--rm",
        "--name",
        name,
        "--interactive",
        "--runtime=runc",
        "--network=none",
        "--read-only",
        "--ipc=none",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=65534:65534",
        "--workdir=/",
        "--no-healthcheck",
        "--log-driver=none",
        "--pids-limit=16",
        "--cpus=0.5",
        "--memory=96m",
        "--memory-swap=96m",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=1048576:1048576",
        "--ulimit=core=0:0",
        "--mount",
        f"type=bind,source={staged},target=/dragonscan-target,readonly",
        "--entrypoint=/usr/bin/env",
        image,
        "-i",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "LC_ALL=C",
        "/usr/bin/timeout",
        "--signal=KILL",
        "12s",
        "/dragonscan-target",
    ]


# In-container acceptance data only. No external address, target metadata,
# host socket, attacker code, package runner, or tool invocation is involved.
_PROBE = """#!/usr/local/bin/python3 -I
import errno, os, resource, socket, sys, time
from pathlib import Path
marker, port, host_pid_ns, host_net_ns = __PROBE_INPUTS__
if not __debug__:
    sys.exit(1)
assert os.getuid() == 65534
assert not set(os.environ) - {"PATH", "LC_ALL", "LC_CTYPE"}
assert os.statvfs("/").f_flag & os.ST_RDONLY
assert os.statvfs("/dragonscan-target").f_flag & os.ST_RDONLY
assert os.readlink("/proc/self/ns/pid") != host_pid_ns
assert os.readlink("/proc/self/ns/net") != host_net_ns
try:
    open(marker, "rb").close()
except FileNotFoundError:
    pass
else:
    sys.exit(1)
try:
    open("/.dragonscan-boundary-write-check", "xb").close()
except OSError as exc:
    assert exc.errno in {errno.EROFS, errno.EACCES}
else:
    sys.exit(1)
assert set(os.listdir("/sys/class/net")) == {"lo"}
with socket.socket() as s:
    s.settimeout(0.5)
    assert s.connect_ex(("127.0.0.1", port)) == errno.ECONNREFUSED
cg = Path("/sys/fs/cgroup")
assert int((cg/"memory.max").read_text()) == 96 * 1024 * 1024
assert int((cg/"memory.swap.max").read_text()) == 0
assert int((cg/"pids.max").read_text()) == 16
quota, period = map(int, (cg/"cpu.max").read_text().split())
assert 0 < quota * 2 == period
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (1048576, 1048576)
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
assert int(status["NoNewPrivs"]) == 1 and int(status["CapEff"], 16) == 0
assert int(status["Seccomp"]) == 2
if os.fork():
    print("isolated-fixture-ready", flush=True)
time.sleep(30)
"""


def _close_process(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe:
            pipe.close()
    proc.wait(timeout=2)


class DockerSandbox:
    def __init__(self, image: str, root: Path):
        self.image = image
        self.root = root
        self.config = root / "empty-client-config"
        self.config.mkdir(mode=0o700)
        self.prefix = [_CLI, "--config", str(self.config), "--host", "unix://" + _SOCKET]
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.config)}
        self.name: str | None = None

    def _control(self, *args: str, check: bool = True) -> bytes:
        # Fixed ID/PID/status templates, or the one scanner-generated name.
        try:
            result = subprocess.run(
                [*self.prefix, *args],
                cwd="/",
                env=self.env,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise IsolationError("isolated engine control unavailable or timed out") from None
        if check and result.returncode:
            raise IsolationError("isolated engine rejected local configuration")
        if len(result.stdout) > 256:
            raise IsolationError("unexpected isolated engine reply")
        return result.stdout.strip()

    def remove(self) -> bool:
        if self.name is None:
            return True
        name = self.name
        try:
            self._control("rm", "--force", name, check=False)
            gone = not self._control(
                "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.ID}}"
            )
            if gone:
                self.name = None
            return gone
        except IsolationError:
            return False

    def start(self, staged: Path) -> subprocess.Popen[bytes]:
        if self.name is not None:
            raise IsolationError("previous isolated container cleanup not confirmed")
        name = "dragonscan-" + uuid.uuid4().hex
        self.name = name
        try:
            self._control(*_create_args(self.image, staged, name))
            return subprocess.Popen(
                [*self.prefix, "start", "--attach", "--interactive", name],
                cwd="/",
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
        except BaseException:
            self.remove()
            raise

    def target(self, source: Path) -> subprocess.Popen[bytes]:
        staged = self.root / "selected-executable"
        _copy_executable(source, staged)
        return self.start(staged)

    def _pidfds(self) -> list[int]:
        # Verify the *native* host PID tree for this harmless fixture, not merely
        # a container status or a signal delivery. Refuse daemon VM/PID mismatch.
        assert self.name is not None
        raw = self._control("inspect", "--format", "{{.State.Pid}}", self.name)
        if not raw.isdigit() or int(raw) < 2:
            raise IsolationError("native probe process identity unavailable")
        pid = int(raw)
        pidfd_open = getattr(os, "pidfd_open", None)
        if pidfd_open is None:
            raise IsolationError("native probe requires Linux pidfds")
        fds: list[int] = []
        try:
            for index in range(3):  # timeout -> python probe -> forked sleeper
                fds.append(pidfd_open(pid))
                if index < 2:
                    children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                    if len(children) != 1 or not children[0].isdigit():
                        raise IsolationError("native probe descendant identity unavailable")
                    pid = int(children[0])
            return fds
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise

    def probe(self) -> None:
        # No image-supplied volumes. An ID, never a mutable tag or registry name.
        identity = self._control(
            "image",
            "inspect",
            "--format",
            '{{.Id}} {{.Os}} {{if index .Config "Volumes"}}volumes{{else}}none{{end}}',
            self.image,
        )
        if identity != (self.image + " linux none").encode():
            raise IsolationError("reviewed local Linux image without volumes required")
        marker = self.root / "out-of-scope-marker"
        marker.write_bytes(b"harmless")
        fixture = self.root / "trusted-probe"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            inputs = (
                str(marker),
                listener.getsockname()[1],
                os.readlink("/proc/self/ns/pid"),
                os.readlink("/proc/self/ns/net"),
            )
            fixture.write_text(_PROBE.replace("__PROBE_INPUTS__", repr(inputs)))
            fixture.chmod(0o555)
            proc = self.start(fixture)
            fds: list[int] = []
            try:
                assert proc.stdout is not None
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    ready = selector.select(5)
                if not ready or os.read(proc.stdout.fileno(), 128) != b"isolated-fixture-ready\n":
                    raise IsolationError("filesystem/network/quota probe did not attest isolation")
                fds = self._pidfds()
                if not self.remove():
                    raise IsolationError("isolated probe container cleanup unconfirmed")
                deadline = time.monotonic() + 2
                for fd in fds:
                    if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                        raise IsolationError("isolated probe descendant cleanup unconfirmed")
            finally:
                for fd in fds:
                    os.close(fd)
                try:
                    _close_process(proc)
                finally:
                    if not self.remove():
                        raise IsolationError("isolated probe cleanup unconfirmed")


@contextmanager
def prepared(image: str) -> Iterator[DockerSandbox]:
    platform_check(image)
    with tempfile.TemporaryDirectory(prefix="dragonscan-isolated-") as directory:
        backend = DockerSandbox(image, Path(directory))
        try:
            try:
                backend.probe()
            except (OSError, subprocess.TimeoutExpired):
                raise IsolationError("isolated backend preflight unavailable") from None
            yield backend
        finally:
            if not backend.remove():
                raise IsolationError("isolated container cleanup unconfirmed")
