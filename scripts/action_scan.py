"""Local-only boundary between a composite Action and the existing Dragons CLI."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def scan_action(
    workspace: Path,
    runner_temp: Path,
    cli: Path,
    target: str,
    fail_on: str,
    github_output: Path,
    *,
    env: dict[str, str] | None = None,
) -> tuple[int, Path | None]:
    """Scan a checked-out path without interpreting input as shell or scanning outside it."""
    source_env = os.environ if env is None else env
    sarif: Path | None = None
    try:
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
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Dragons Action target rejected: {exc}", file=sys.stderr)
        code = 2
    else:
        try:
            runner_temp.mkdir(parents=True, exist_ok=True)
            directory = Path(tempfile.mkdtemp(prefix="dragonscan-", dir=runner_temp))
            candidate = directory / "dragons.sarif"
            command = [str(cli), "scan", str(path), "--format", "sarif"]
            if fail_on:
                command.extend(("--fail-on", fail_on))
            # No target-controlled string is ever evaluated by a shell.
            scanner_env = {
                "PATH": os.defpath,
                "HOME": source_env.get("HOME", str(Path.home())),
                "LANG": "C.UTF-8",
            }
            with candidate.open("x", encoding="utf-8") as output:
                completed = subprocess.run(
                    command, cwd=root, stdout=output, check=False, env=scanner_env
                )
            code = completed.returncode
            if candidate.stat().st_size:
                sarif = candidate
            else:
                candidate.unlink()
        except OSError as exc:
            print(f"Dragons Action operational failure: {exc}", file=sys.stderr)
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
        Path(os.environ["GITHUB_OUTPUT"]),
    )


if __name__ == "__main__":
    main()
