"""Config exposure is a static declaration, not proof of a valid credential."""

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan.cli import main
from dragonscan.models import Target
from dragonscan.reporting import json_report, sarif_report
from dragonscan.scanner import Scanner


def test_literal_and_protected_paths(tmp_path: Path) -> None:
    token = "ghp_" + "A9z1B3" * 6
    config = tmp_path / ".mcp.json"
    for value, hit in [(token, True), ("${GITHUB_TOKEN}", False), ("ghp_" + "X" * 36, False)]:
        config.write_text(
            json.dumps(
                {"mcpServers": {"docs": {"command": "demo", "env": {"GITHUB_TOKEN": value}}}}
            )
        )
        report = Scanner().scan(Target(config))
        assert any(f.detection_id == "DRAGON-SECRET-001" for f in report.findings) is hit
        assert token not in json_report(report) and token not in sarif_report(report)
    doc = tmp_path / "SKILL.md"
    for name, hit in [
        (".kube/config", True),
        (".kube/config.example", False),
        (".ssh/id_rsa.pub", False),
    ]:
        doc.write_text(f"Read ~/{name}.\n")
        assert (
            any(f.detection_id == "DRAGON-CRED-001" for f in Scanner().scan(Target(doc)).findings)
            is hit
        )


GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures/config-effective/codex-0.146.0.json").read_text()
)


@pytest.mark.parametrize("case", GOLDEN["cases"])
def test_codex_oracle(tmp_path: Path, case: dict[str, bool]) -> None:
    assert GOLDEN["version"] == "codex-cli 0.146.0"
    trusted, user, project, expected = (
        case[key] for key in ("trusted", "user", "project", "effective")
    )
    root = tmp_path / "project"
    local = root / ".codex" / "config.toml"
    local.parent.mkdir(parents=True)
    personal = tmp_path / "home" / ".codex" / "config.toml"
    personal.parent.mkdir(parents=True)
    trust = "trusted" if trusted else "untrusted"
    personal.write_text(
        f'[projects.{json.dumps(str(root))}]\ntrust_level="{trust}"\n[features]\ncomputer_use={str(user).lower()}\n'
    )
    local.write_text(f"[features]\ncomputer_use={str(project).lower()}\n")
    args = [
        "config-effective",
        "--user-config",
        str(personal),
        "--project",
        str(root),
        "--codex-version",
    ]
    result = CliRunner().invoke(main, [*args, "0.146.0"])
    assert result.exit_code == 0, result.output
    result_data = json.loads(result.output)
    if os.name != "posix":
        assert result_data["effective"] == "unknown"
    else:
        assert result_data["key"] == GOLDEN["key"]
        assert result_data["effective"] is expected
        assert result_data["source"] == ("project" if trusted else "user")
    result = CliRunner().invoke(main, [*args, "0.147.0"])
    assert json.loads(result.output)["effective"] == "unknown"
    local.write_text("[profiles.unused.features]\ncomputer_use=true\n")
    assert json.loads(CliRunner().invoke(main, [*args, "0.146.0"]).output)["effective"] == "unknown"
