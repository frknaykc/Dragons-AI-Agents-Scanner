"""Static package-to-script proof; bodies are parser input, never imported or run."""

import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.models import Target
from dragonscan.policy import evaluate
from dragonscan.report_context import evidence_kind
from dragonscan.scanner import Scanner

RULE = "DRAGON-EXEC-005"
BODY = "value = input()\ncopy = value\neval(copy)\n"


def package(root: Path, body: str, directive: str = "Load notes/guide.md.") -> Path:
    (root / "notes").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "SKILL.md").write_text(directive, encoding="utf-8")
    (root / "notes/guide.md").write_text("Run python ../scripts/check.py.", encoding="utf-8")
    script = root / "scripts/check.py"
    script.write_text(body, encoding="utf-8")
    return script


def test_execution_input_requires_exact_package_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".hermes/skills/probe"
    script = package(root, BODY)

    def deny(*args: object, **kwargs: object) -> None:
        pytest.fail("static scan attempted I/O outside the package reader")

    monkeypatch.setattr(subprocess, "Popen", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr("builtins.input", deny)
    for report in (
        Scanner().scan(Target(root)),
        Scanner().scan_installed(home=tmp_path, agent="Hermes Agent"),
    ):
        (finding,) = (f for f in report.findings if f.detection_id == RULE)
        assert finding.artifact == root / "SKILL.md"
        assert [(s.artifact, s.line) for s in finding.path] == [
            (root / "SKILL.md", 1),
            (root / "notes/guide.md", 1),
            (script, 1),
            (script, 3),
        ]
        assert finding.source and finding.sink and evidence_kind(finding) == "static_inferred"
        assert finding.flow and finding.flow.source_type == "untrusted_script_input"


@pytest.mark.parametrize(
    "directive", ["See [guide](notes/guide.md).", "Load notes/missing.md.", "Notes only."]
)
def test_script_inventory_cannot_lend_authority(tmp_path: Path, directive: str) -> None:
    package(tmp_path, BODY, directive)
    assert not any(f.detection_id == RULE for f in Scanner().scan(Target(tmp_path)).findings)


@pytest.mark.parametrize(
    "body",
    [
        "value = input()\neval('1')",
        'value = input()\nvalue = "1"\neval(value)',
        "value = input()\nprint(value)",
        "from pathlib import Path\nvalue = Path('README.md').read_text()\nprint(value)",
        "from urllib.request import urlopen\nvalue = urlopen('https://example.invalid/')\nprint(value)",
    ],
)
def test_unconnected_input_is_not_a_finding(tmp_path: Path, body: str) -> None:
    package(tmp_path, body)
    assert not any(f.detection_id == RULE for f in Scanner().scan(Target(tmp_path)).findings)


def test_unknown_program_is_partial_not_clean(tmp_path: Path) -> None:
    package(tmp_path, "handler = globals()[input()]\nhandler(1)")
    report = Scanner().scan(Target(tmp_path))
    assert evaluate(report).scan_status == "partial"
    assert not any(f.detection_id == RULE for f in report.findings)


@pytest.mark.parametrize(
    ("runtime", "suffix", "body"),
    [
        ("sh", "sh", 'cmd="$1"\n"$cmd"'),
        ("pwsh -File", "ps1", "$cmd = $args[0]\n& $cmd"),
        ("node", "js", "const cmd = process.argv[2];\neval(cmd);"),
    ],
)
def test_text_adapter_evidence_reaches_package_report(
    tmp_path: Path, runtime: str, suffix: str, body: str
) -> None:
    script = package(tmp_path, body).rename(tmp_path / f"scripts/check.{suffix}")
    guide = tmp_path / "notes/guide.md"
    guide.write_text(f"Run {runtime} ../scripts/{script.name}.", encoding="utf-8")
    report = Scanner().scan(Target(tmp_path))
    (finding,) = (f for f in report.findings if f.detection_id == RULE)
    assert [(s.artifact, s.line) for s in finding.path] == [
        (tmp_path / "SKILL.md", 1),
        (guide, 1),
        (script, 1),
        (script, 2),
    ]
    assert evidence_kind(finding) == "static_inferred"
