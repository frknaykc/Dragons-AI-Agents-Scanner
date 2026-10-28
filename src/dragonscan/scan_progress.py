"""Optional in-process scan observations; no rendering or artifact execution."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dragonscan.models import Artifact, Finding, ScanReport


@dataclass(frozen=True)
class ScanProgress:
    phase: Literal["discover", "ready", "start", "processed", "correlate", "finished"]
    artifact: Artifact | None = None
    artifacts: tuple[Artifact, ...] = ()
    agents: tuple[tuple[Path, str], ...] = ()
    findings: tuple[Finding, ...] = ()
    errors: int = 0  # Failed artifact attempts, including parse failures.
    report: ScanReport | None = None
