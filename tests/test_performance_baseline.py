"""Quick correctness checks for the opt-in, offline performance harness."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "performance_baseline.py"


def harness():
    spec = importlib.util.spec_from_file_location("performance_baseline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_workload_matrix_and_smoke_selection():
    module = harness()
    full = {(item.kind, item.size) for item in module.workloads(False)}
    assert full == {
        ("files", 100),
        ("files", 1000),
        ("files", 10000),
        ("nearmax", 1),
        ("oversize", 1),
        ("ioc", 100),
        ("ioc", 10000),
        ("graph", 100),
        ("graph", 10000),
        ("high_branch", 1000),
    }
    assert {item.kind for item in module.workloads(True)} == {
        "files",
        "oversize",
        "ioc",
        "graph",
        "high_branch",
    }
    assert max(item.size for item in module.workloads(True)) <= 1000


def test_oversize_is_rejected_not_read_as_success(tmp_path):
    module = harness()
    result = module.measure(module.Workload("oversize", 1), tmp_path)
    assert result["status"] == "ok"
    assert result["counters"]["errors"] == 1
    assert result["counters"]["artifacts"] == 1
    assert result["counters"]["bytes"] == 0
    assert result["metrics"]["peak_rss_mb"] > 0


def test_nearmax_reports_evasion_partial_instead_of_claiming_full_coverage(tmp_path):
    module = harness()
    result = module.measure(module.Workload("nearmax", 1), tmp_path)
    assert result["status"] == "partial", result
    assert module.MAX_BYTES - 128 < result["counters"]["bytes"] < module.MAX_BYTES
    assert result["counters"]["errors"] == 0
    assert result["counters"]["diagnostics"] == 1
    assert result["counters"]["partial"] == 1
    assert result["counters"]["processed"] == 1


def test_synthetic_ioc_and_graph_are_bounded_and_checked(tmp_path):
    module = harness()
    for kind, size in (("ioc", 100), ("graph", 100), ("high_branch", 50)):
        result = module.measure(module.Workload(kind, size), tmp_path)
        assert result["status"] == "ok", result
        assert result["counters"]["requested"] == size
        assert result["counters"]["processed"] == size
        assert result["metrics"]["wall_seconds"] >= 0


def test_partial_counters_survive_worker_error(tmp_path, monkeypatch):
    module = harness()

    def interrupted(case, root, counters):
        counters["processed"] = 3
        raise RuntimeError("injected interruption")

    monkeypatch.setattr(module, "_files", interrupted)
    result = module.measure(module.Workload("files", 100), tmp_path)
    assert result["status"] == "error"
    assert result["counters"] == {"requested": 100, "processed": 3}
    assert "injected interruption" in result["error"]


def test_scan_fixture_is_static_and_offline(tmp_path, monkeypatch):
    import socket

    module = harness()

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network connection")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    result = module.measure(module.Workload("files", 10), tmp_path)
    assert result["status"] == "ok", result
    assert result["counters"]["bytes"] == 610


def test_smoke_cli_offline_json(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--smoke"],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
        cwd=tmp_path,
    )
    data = json.loads(completed.stdout)
    assert data["schema_version"] == 1
    assert len(data["results"]) == 5
    assert all(item["status"] == "ok" for item in data["results"]), data
    assert all("wall_seconds" in item["metrics"] for item in data["results"])
    assert not completed.stderr


def test_invalid_selection_is_rejected():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--case", "files:10001"],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert not completed.stdout
    assert "invalid choice" in completed.stderr or "unsupported" in completed.stderr
