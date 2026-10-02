"""Local-only boundary between a composite Action and the existing Dragons CLI."""

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def scan_action(
    workspace: Path,
    runner_temp: Path,
    cli: Path,
    target: str,
    fail_on: str,
    fail_on_incomplete: str,
    github_output: Path,
    *,
    env: dict[str, str] | None = None,
) -> tuple[int, Path | None]:
    """Scan a checked-out path without interpreting input as shell or scanning outside it."""
    source_env = os.environ if env is None else env
    sarif: Path | None = None
    try:
        if fail_on_incomplete not in {"true", "false"}:
            raise ValueError("fail-on-incomplete must be true or false")
        root = workspace.resolve(strict=True)
        # Reject remote acquisition and shell-like expansion, even when the name exists locally.
        if urlsplit(target).scheme or "$" in target or "`" in target:
            raise ValueError("target must be a local path in GITHUB_WORKSPACE")
        path = (root / target).resolve(strict=False)
        if not path.is_relative_to(root):
            raise ValueError("target escapes GITHUB_WORKSPACE")
        # A nonexistent in-workspace path is left to the CLI (operational exit 3).
        if path.exists():
            path = path.resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError("target escapes GITHUB_WORKSPACE")
    except (ValueError, OSError, RuntimeError):
        print("Dragons Action input rejected: invalid or outside workspace", file=sys.stderr)
        code = 2
    else:
        try:
            runner_temp.mkdir(parents=True, exist_ok=True)
            candidate = runner_temp / "dragons.sarif"
            candidate.unlink(missing_ok=True)
            command = [str(cli), "scan", str(path), "--format", "sarif"]
            if fail_on:
                command.extend(("--fail-on", fail_on))
            if fail_on_incomplete == "true":
                command.append("--fail-on-incomplete")
            command.extend(("--output", str(candidate)))
            # No target-controlled string is ever evaluated by a shell.
            scanner_env = {
                "PATH": os.defpath,
                "HOME": source_env.get("HOME", str(Path.home())),
                "LANG": "C.UTF-8",
            }
            completed = subprocess.run(command, cwd=root, check=False, env=scanner_env)
            code = completed.returncode
            if code not in {0, 1, 2, 3}:
                print("Dragons Action scanner process failed unexpectedly", file=sys.stderr)
                code = 3
            if candidate.is_file() and candidate.stat().st_size:
                sarif = candidate
            elif code == 0:
                code = 3  # Success without a report cannot be presented as a passing gate.
        except OSError:
            print("Dragons Action operational failure during scan", file=sys.stderr)
            code = 3
    with github_output.open("a", encoding="utf-8") as output:
        output.write(f"exit-code={code}\nsarif-path={sarif or ''}\n")
    print(f"Dragons scan exit code: {code}", file=sys.stderr)
    return code, sarif


def main() -> None:
    temp = Path(os.environ["RUNNER_TEMP"])
    scan_action(
        Path(os.environ["GITHUB_WORKSPACE"]),
        temp,
        temp / "dragons-venv" / "bin" / "dragonscan",
        os.environ["INPUT_TARGET"],
        os.environ["INPUT_FAIL_ON"],
        os.environ["INPUT_FAIL_ON_INCOMPLETE"],
        Path(os.environ["GITHUB_OUTPUT"]),
    )


if __name__ == "__main__":
    main()
