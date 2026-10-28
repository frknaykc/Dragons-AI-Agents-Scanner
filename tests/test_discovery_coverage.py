"""Discovery coverage over inert synthetic trees; no installed user data is read."""

import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from dragonscan.discovery import DiscoveryError, discover, discover_installed_bounded
from dragonscan.installed_agents import discover_installed
from dragonscan.models import Target
from dragonscan.policy import evaluate
from dragonscan.scanner import Scanner


def _write(root: Path, relative: str, text: str = "Ordinary local guidance.\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _skills(root: Path, count: int) -> list[Path]:
    # Reverse creation order so ordering cannot accidentally follow insertion order.
    return sorted(
        _write(root, f"skills/group-{index // 100:03}/skill-{index:05}/SKILL.md")
        for index in reversed(range(count))
    )


@pytest.mark.parametrize("count", [10, 64, 65, 165, 1000])
def test_hermes_default_discovers_every_supported_skill_ordered_once(
    tmp_path: Path, count: int
) -> None:
    root = tmp_path / ".hermes"
    expected = _skills(root, count)
    # Unclassified entries must not consume a hidden cumulative default budget.
    for path in expected:
        _write(path.parent, "README.md")
        _write(path.parent, "notes.txt")
    result = discover_installed(home=tmp_path, agent="Hermes Agent")
    paths = [item.path for item in result.artifacts]
    assert paths == expected
    assert len(paths) == len(set(paths)) == count
    assert result.environments[0].resolution == "complete"
    assert result.environments[0].diagnostic is None


@pytest.mark.parametrize("installed_project,count", [(False, 10001), (True, 1000)])
def test_project_discovery_has_no_implicit_total_artifact_cap(
    tmp_path: Path, installed_project: bool, count: int
) -> None:
    expected = _skills(tmp_path, count)
    artifacts = discover(Target(tmp_path), installed_project=installed_project)
    assert [a.path for a in artifacts] == expected


@pytest.mark.parametrize("count", [10, 64, 65, 165, 1000])
def test_scanner_attempts_each_discovered_skill_once_even_with_explicit_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    import dragonscan.scanner as scanner

    root = tmp_path / ".hermes"
    expected = _skills(root, count)
    attempts: list[Path] = []
    real_load = scanner.load_text

    def track_load(path: Path) -> str:
        attempts.append(path)
        return real_load(path)

    monkeypatch.setattr(scanner, "load_text", track_load)
    report = Scanner().scan_installed(Target(root), home=tmp_path, agent="Hermes Agent")
    assert [a.path for a in report.artifacts] == expected
    assert attempts == expected
    assert not report.errors
    assert all(env.resolution == "complete" for env in report.installed_environments)
    for key in ("discovered", "attempted", "loaded", "parsed", "fully_analyzed"):
        assert report.coverage[key] == count
    for key in ("partially_analyzed", "failed", "skipped"):
        assert report.coverage[key] == 0
    assert evaluate(report).scan_status == "complete"


@pytest.mark.parametrize("per_root", [False, True])
def test_explicit_installed_artifact_budgets_still_diagnose_partial(
    tmp_path: Path, per_root: bool
) -> None:
    expected = _skills(tmp_path / ".hermes", 165)
    result = discover_installed(
        home=tmp_path,
        agent="Hermes Agent",
        max_artifacts=None if per_root else 65,
        max_artifacts_per_root=65 if per_root else None,
    )
    assert [a.path for a in result.artifacts] == expected[:65]
    assert result.environments[0].resolution == "partial"
    assert "artifact limit" in (result.environments[0].diagnostic or "")


def test_explicit_project_budget_still_fails_closed(tmp_path: Path) -> None:
    _skills(tmp_path, 65)
    with pytest.raises(DiscoveryError, match="artifact count exceeds limit"):
        discover(Target(tmp_path), max_artifacts=64)


def test_hermes_profiles_privacy_symlinks_and_mixed_files(tmp_path: Path) -> None:
    root = tmp_path / ".hermes"
    expected = {
        _write(root, "config.yaml", "{}"),
        _write(root, "skills/local/SKILL.md"),
        _write(root, "profiles/work/skills/local/SKILL.md"),
        _write(root, "profiles/work/memories/MEMORY.md"),
    }
    for relative in (
        ".env",
        "auth.json",
        "sessions/SKILL.md",
        "cache/SKILL.md",
        "profiles/work/.env",
        "profiles/work/sessions/SKILL.md",
        "skills/local/README.md",
    ):
        _write(root, relative, "PRIVATE SYNTHETIC DATA")
    outside = _write(tmp_path, "outside/SKILL.md")
    (root / "skills" / "linked").symlink_to(outside.parent, target_is_directory=True)
    (root / "skills" / "local" / "AGENTS.md").symlink_to(outside)
    (root / "skills" / "cycle").symlink_to(root, target_is_directory=True)
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "skills" / "local" / "SOUL.md")
    result = discover_installed(home=tmp_path, agent="Hermes Agent")
    assert {a.path for a in result.artifacts} == expected
    assert len(result.artifacts) == len(expected)
    assert result.environments[0].resolution == "complete"


def test_unreadable_subtree_retains_other_skills_with_safe_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".hermes"
    good = _write(root, "skills/a-good/SKILL.md")
    denied = _write(root, "skills/b-denied/SKILL.md")
    real_scandir = os.scandir

    def guarded_scandir(path):
        if Path(path) == denied.parent:
            raise PermissionError("PRIVATE SYNTHETIC DATA")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)
    result = discover_installed(home=tmp_path, agent="Hermes Agent")
    assert [a.path for a in result.artifacts] == [good]
    assert result.environments[0].resolution == "partial"
    assert "PermissionError" in (result.environments[0].diagnostic or "")
    assert "PRIVATE" not in (result.environments[0].diagnostic or "")


@pytest.mark.parametrize(
    "limit,diagnostic",
    [("max_directory_entries", "directory entry limit"), ("max_pending_dirs", "frontier limit")],
)
def test_working_traversal_limits_are_explicit_and_keep_other_evidence(
    tmp_path: Path, limit: str, diagnostic: str
) -> None:
    good = _write(tmp_path, "AGENTS.md")
    for index in range(5):
        _write(tmp_path, f"wide/child-{index}/SKILL.md")
    artifacts, message = discover_installed_bounded(
        Target(tmp_path),
        max_depth=8,
        max_entries=None,
        max_artifacts=None,
        max_directory_entries=2 if limit == "max_directory_entries" else 100,
        max_pending_dirs=2 if limit == "max_pending_dirs" else 100,
    )
    assert good in {a.path for a in artifacts}
    assert diagnostic in (message or "")


def test_explicit_entry_budget_and_default_depth_are_diagnosed(tmp_path: Path) -> None:
    root = tmp_path / ".hermes"
    good = _write(root, "skills/a-good/SKILL.md")
    _write(root, "skills/deep/one/two/three/four/five/six/SKILL.md")
    limited = discover_installed(home=tmp_path, agent="Hermes Agent", max_entries_per_root=2)
    assert limited.environments[0].resolution == "partial"
    assert "entry limit" in (limited.environments[0].diagnostic or "")
    deep = discover_installed(home=tmp_path, agent="Hermes Agent")
    assert good in {a.path for a in deep.artifacts}
    assert "depth limit" in (deep.environments[0].diagnostic or "")


def test_directory_entry_limit_is_not_cumulative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dragonscan.discovery as discovery

    monkeypatch.setattr(discovery, "MAX_ENTRIES", 3)
    expected = sorted(
        _write(tmp_path, f"part-{index}/{name}.md")
        for index in range(3)
        for name in ("AGENTS", "MEMORY", "SKILL")
    )
    messages: list[str] = []
    assert [a.path for a in discover(Target(tmp_path), limit_diagnostics=messages)] == expected
    assert not messages


def test_per_root_budget_also_applies_to_known_configuration_extras(tmp_path: Path) -> None:
    root = tmp_path / ".hermes"
    _write(root, "config.yaml", "{}")
    _write(root, "SOUL.md")
    result = discover_installed(home=tmp_path, agent="Hermes Agent", max_artifacts_per_root=1)
    assert len(result.artifacts) == 1
    assert "artifact limit" in (result.environments[0].diagnostic or "")


def test_working_limits_bound_enumeration_and_pending_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dragonscan.discovery as discovery

    for index in range(6):
        _write(tmp_path, f"part-{index}/SKILL.md")
    real_scandir = discovery.os.scandir
    enumerated = 0

    @contextmanager
    def counted_scandir(path):
        nonlocal enumerated
        with real_scandir(path) as entries:

            def counted_entries():
                nonlocal enumerated
                for entry in entries:
                    enumerated += 1
                    yield entry

            yield counted_entries()

    monkeypatch.setattr(discovery.os, "scandir", counted_scandir)
    artifacts, message = discover_installed_bounded(
        Target(tmp_path),
        max_depth=8,
        max_entries=None,
        max_artifacts=None,
        max_directory_entries=3,
    )
    assert not artifacts
    assert enumerated == 4  # At most the bounded buffer plus one overflow probe.
    assert "directory entry limit" in (message or "")

    real_push = discovery.heapq.heappush
    queue_sizes: list[int] = []

    def checked_push(queue, item):
        real_push(queue, item)
        queue_sizes.append(len(queue))

    monkeypatch.setattr(discovery.heapq, "heappush", checked_push)
    artifacts, message = discover_installed_bounded(
        Target(tmp_path),
        max_depth=8,
        max_entries=None,
        max_artifacts=None,
        max_pending_dirs=2,
    )
    assert len(artifacts) == 2
    assert max(queue_sizes) == 2
    assert "frontier limit" in (message or "")
