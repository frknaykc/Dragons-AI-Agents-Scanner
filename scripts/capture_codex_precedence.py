"""Record one inert Codex feature-list oracle in a synthetic home; never run a session."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def capture() -> dict[str, object]:
    binary = shutil.which("codex")
    if not binary:
        raise RuntimeError("codex-cli 0.146.0 required")
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory).resolve()
        project = root / "project"
        user = root / "home" / ".codex"
        user.mkdir(parents=True)
        local = project / ".codex"
        local.mkdir(parents=True)
        (project / ".git").mkdir()
        env = {
            "HOME": str(user.parent),
            "CODEX_HOME": str(user),
            "PATH": str(Path(binary).parent) + os.pathsep + os.defpath,
            "TMPDIR": str(root),
            "XDG_CONFIG_HOME": str(root / "xdg"),
        }

        def run(*argv: str) -> str:
            return subprocess.run(
                [binary, *argv],
                cwd=project,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            ).stdout.strip()

        version = run("--version")
        if version != "codex-cli 0.146.0":
            raise RuntimeError("unexpected oracle version")
        cases = []
        for trusted in (False, True):
            for user_flag, project_flag in ((True, False), (False, True)):
                trust = "trusted" if trusted else "untrusted"
                user_config = f'[projects.{json.dumps(str(project))}]\ntrust_level = "{trust}"\n'
                user_config += f"[features]\ncomputer_use = {str(user_flag).lower()}\n"
                (user / "config.toml").write_text(user_config)
                (local / "config.toml").write_text(
                    f"[features]\ncomputer_use = {str(project_flag).lower()}\n"
                )
                (row,) = (
                    s.split()
                    for s in run("features", "list").splitlines()
                    if s.split()[:1] == ["computer_use"]
                )
                if row[-1] not in {"true", "false"}:
                    raise RuntimeError("unrecognized feature state")
                cases.append(
                    dict(
                        trusted=trusted,
                        user=user_flag,
                        project=project_flag,
                        effective=row[-1] == "true",
                    )
                )
    return {"version": version, "key": "features.computer_use", "cases": cases}


if __name__ == "__main__":
    print(json.dumps(capture(), indent=2))
