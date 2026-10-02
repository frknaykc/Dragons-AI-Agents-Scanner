"""Offline benchmark gate contract."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.benchmark_gate import check, main


@pytest.fixture
def baseline() -> dict[str, object]:
    return {
        "status": "completed",
        "summary": {"evaluated_cases": 48, "failed_cases": 0, "tp": 50, "fp": 0, "fn": 0},
        "correctness": {"failed": 0},
        "coverage": {"total_rules": 46},
    }


def test_baseline_and_regressions(baseline: dict[str, object]) -> None:
    assert check(baseline)
    for key, value in (("fp", 1), ("fn", 1), ("tp", 49), ("failed_cases", 1)):
        changed = json.loads(json.dumps(baseline))
        changed["summary"][key] = value
        assert not check(changed)
    changed = json.loads(json.dumps(baseline))
    changed["correctness"]["failed"] = 1
    assert not check(changed)
    changed["coverage"]["total_rules"] = 47
    assert not check(changed)


def test_cli_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, baseline: dict[str, object]
) -> None:
    report = tmp_path / "benchmark.json"
    report.write_text(json.dumps(baseline))
    monkeypatch.setattr("sys.argv", ["benchmark_gate", str(report)])
    assert main() == 0
