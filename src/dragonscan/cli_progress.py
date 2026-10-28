"""TTY-only live scan rows; the final report remains the authoritative result."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from dragonscan.models import Artifact, Severity
from dragonscan.scan_progress import ScanProgress


@dataclass
class AgentProgress:
    total: int = 0
    processed: int = 0
    errors: int = 0
    counts: Counter[Severity] = field(default_factory=Counter)
    path: str = "Waiting"
    active: bool = False


class TerminalScanProgress:
    def __init__(self, console: Console, *, enabled: bool, installed: bool) -> None:
        self.enabled = enabled
        self.installed = installed
        self.console = console
        self.rows: dict[str, AgentProgress] = {}
        self.owners: dict[Path, str] = {}
        self.phase = "Discover Agents" if installed else "Discover Artifacts"
        self.live = Live(
            console=console,
            refresh_per_second=8,
            transient=True,
            redirect_stdout=False,
            redirect_stderr=False,
        )

    def start(self) -> None:
        if self.enabled:
            self.live.update(self.render())
            self.live.start(refresh=True)

    def stop(self) -> None:
        if self.enabled:
            self.live.stop()

    def _row(self, artifact: Artifact) -> AgentProgress:
        owner = self.owners.setdefault(artifact.path, "Local artifacts")
        return self.rows.setdefault(owner, AgentProgress())

    def __call__(self, event: ScanProgress) -> None:
        if not self.enabled:
            return
        if event.phase == "ready":
            self.rows.clear()
            self.owners.clear()
            for path, agent in event.agents:
                # Deduplicated artifacts have one row owner, even when several
                # installed origins reference the same file.
                self.owners.setdefault(path, agent)
            for artifact in event.artifacts:
                self._row(artifact).total += 1
            self.phase = "Scanning · counts so far"
        elif event.phase == "start" and event.artifact is not None:
            for row in self.rows.values():
                row.active = False
            row = self._row(event.artifact)
            row.path = str(event.artifact.path)
            row.active = True
        elif event.phase == "processed" and event.artifact is not None:
            row = self._row(event.artifact)
            row.processed += 1
            row.errors += event.errors
            row.counts.update(finding.severity for finding in event.findings)
        elif event.phase == "correlate":
            self.phase = "Correlating · finalizing findings"
            for row in self.rows.values():
                row.active = False
        elif event.phase == "finished" and event.report is not None:
            # Cross-artifact findings arrive after per-file processing. Replace,
            # do not append, so the live totals agree with the final report.
            for row in self.rows.values():
                row.counts.clear()
            for finding in event.report.findings:
                owner = self.owners.get(finding.artifact, "Unattributed")
                self.rows.setdefault(owner, AgentProgress()).counts[finding.severity] += 1
            self.phase = "Scan finished"
        self.live.update(self.render())

    def render(self) -> RenderableType:
        header = Table.grid(padding=(0, 1))
        header.add_row(Spinner("dots"), Text(self.phase, style="bold"))
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=1)
        table.add_column(max_width=22, no_wrap=True, overflow="ellipsis")
        table.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        table.add_column(no_wrap=True)
        agent_width = min(
            22,
            max(
                (len(f"{index} {ascii(agent)[1:-1]}") for index, agent in enumerate(self.rows, 1)),
                default=0,
            ),
        )
        compact = self.console.size.width < 110
        spacing = " " if compact else "  "
        for index, (agent, row) in enumerate(self.rows.items(), 1):
            counts = row.counts
            summary = Text(
                f"{'Files' if compact else 'Scanned'} {row.processed}/{row.total}{spacing}"
                f"{'F' if compact else 'Findings'} {sum(counts.values())}{spacing}"
            )
            for level, label, style in (
                (Severity.CRITICAL, "C", "bold red"),
                (Severity.HIGH, "H", "red"),
                (Severity.MEDIUM, "M", "yellow"),
                (Severity.LOW, "L", "cyan"),
                (Severity.INFO, "I", "dim"),
            ):
                summary.append(f"{label} {counts[level]}{spacing}", style=style)
            summary.append(f"Error {row.errors}", style="red" if row.errors else "dim")
            label = f"{index} {ascii(agent)[1:-1]}"
            path = ascii(row.path)[1:-1]
            width = max(1, self.console.size.width - 5 - agent_width - summary.cell_len)
            if len(path) > width:
                path = "…" + path[-(width - 1) :] if width > 1 else "…"
            # Same ASCII-escaping boundary as terminal reports. No markup, ANSI,
            # newline, bidi control or artifact content can alter the live layout.
            table.add_row(
                Spinner("dots") if row.active else Text("·", style="dim"),
                Text(label, style="bold"),
                Text(path, style="dim", no_wrap=True, overflow="ellipsis"),
                summary,
            )
        return Group(header, table)
