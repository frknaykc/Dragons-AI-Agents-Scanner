"""Local-only interactive scanner and report browser."""

import subprocess
import sys
import unicodedata
from dataclasses import dataclass, replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Literal

from rich.text import Text
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Input, Select, SelectionList, Static, Tree

from dragonscan.discovery import DiscoveryError, discover
from dragonscan.installed_agents import SPECS
from dragonscan.models import ArtifactKind, Diagnostic, Finding, ScanReport, Severity, Target
from dragonscan.policy import PolicyResult, evaluate
from dragonscan.private_output import write_private_report
from dragonscan.report_context import INTERPRETATION, context_rows
from dragonscan.reporting import json_report, risk_label, sarif_report, terminal_report
from dragonscan.scanner import Scanner
from dragonscan.target_acquisition import acquire


def _safe_text(value: object) -> str:
    """Escape terminal controls and bidi formatting without changing report data."""
    return "".join(
        ascii(char)[1:-1] if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char
        for char in str(value)
    )


# The splash artwork is authored for a terminal, not rendered from or stored as an image.
LOGO = (
    "██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗",
    "██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║",
    "██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║",
    "██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║",
    "██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║",
    "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝",
)
PALETTE = ("#a82916", "#cc3512", "#e8520c", "#fa7b0c", "#ffb32c", "#ffe078")
COMPACT_LOGO = (
    "╔╦╗╦═╗╔═╗╔═╗╔═╗╔╗╔",
    " ║║╠╦╝╠═╣║ ╦║ ║║║║║",
    "═╩╝╩╚═╩ ╩╚═╝╚═╝╝╚╝",
)
# Block letters are assembled for the welcome banner; the splash artwork is unchanged.
TITLE = "DRAGONSCAN"
TITLE_GLYPHS = {
    "A": (" ███ ", "█   █", "█████", "█   █", "█   █"),
    "C": (" ████", "█    ", "█    ", "█    ", " ████"),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "G": (" ████", "█    ", "█  ██", "█   █", " ████"),
    "I": ("███", " █ ", " █ ", " █ ", "███"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "O": (" ███ ", "█   █", "█   █", "█   █", " ███ "),
    "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
    "S": (" ████", "█    ", " ███ ", "    █", "████ "),
    "T": ("█████", "  █  ", "  █  ", "  █  ", "  █  "),
}
COMPACT_TITLE_GLYPHS = {
    "A": (" ██ ", "████", "█  █"),
    "C": (" ███", "█   ", " ███"),
    "D": ("███ ", "█  █", "███ "),
    "E": ("████", "███ ", "████"),
    "G": (" ███", "█ ██", " ███"),
    "I": ("███", " █ ", "███"),
    "N": ("█  █", "██ █", "█ ██"),
    "O": (" ██ ", "█  █", " ██ "),
    "R": ("███ ", "███ ", "█  █"),
    "S": (" ███", " ██ ", "███ "),
    "T": ("████", " ██ ", " ██ "),
}
# The Braille spacing preserves the shape in a fixed-width terminal.
BACKGROUND_DRAGON = (
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡄⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡄⢸⣿⣇⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⢠⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⢲⣤⡀⠀⠀⠀⠀⠀⠀⠀⣸⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⢸⣇⠀⠀⠀⠀⠀⠀⠀⢀⣠⡖",
    "⠀⠹⣿⣆⠀⠀⠀⠀⠀⣰⣿⠇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⠸⣿⣆⠀⠀⠀⠀⠀⣰⣿⠏⠀",
    "⠀⠀⢻⣿⡆⠀⠀⠐⢿⣿⣿⣦⣼⣿⣿⡇⠀⠀⠀⠀⠀⢰⣿⣿⣇⣴⣿⣿⡿⠂⠀⠀⢰⣿⡟⠀⠀",
    "⠀⠀⢸⣿⡇⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⠏⠁⠀⠀⠀⢸⣿⡇⠀⠀",
    "⠀⠀⢸⣿⣿⡄⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⢠⣾⣿⡇⠀⠀",
    "⢰⡄⠸⣿⣿⣿⣦⣄⠀⠀⢸⣿⣿⣿⣿⣿⡀⠀⠀⠀⢀⣿⣿⣿⣿⣿⡇⠀⠀⣠⣴⣿⣿⣿⡇⢠⡆",
    "⢸⣿⣆⢻⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⡟⠁⠀⣀⠀⠈⢻⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⡟⣰⣿⡇",
    "⠀⣿⣿⣷⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢾⣿⡷⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣾⣿⣿⠀",
    "⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠉⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⡀",
    "⢸⣦⡈⢿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⡄⠀⢠⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⡿⢁⣴⡇",
    "⠀⢿⣿⣮⣿⣿⣿⣿⣿⡇⠈⠻⣿⣿⣿⣿⣿⣿⣶⣿⣿⣿⣿⣿⣿⠟⠁⢸⣿⣿⣿⣿⣿⣵⣿⡿⠁",
    "⠀⠈⢻⣿⣿⣿⣿⣿⣿⡇⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⢸⣿⣿⣿⣿⣿⣿⡟⠁⠀",
    "⠀⠀⠀⠉⠻⢿⣿⣿⣿⣧⠀⠀⡀⠀⠙⣿⣿⣿⣿⣿⣿⣿⠋⠀⢀⠀⠀⣼⣿⣿⣿⣿⠟⠉⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣷⣄⣹⣷⣤⣈⣿⣿⣿⣿⣿⣁⣤⣾⣏⣠⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⡇⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢸⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡇⢷⣿⣿⣿⣿⣿⣿⣿⣿⣿⡾⢸⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡇⣈⢿⣿⣿⣿⣿⣿⣿⣿⡿⣡⢸⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠶⣾⣿⣿⣿⣿⣿⣿⣿⣷⠶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
)
MODES = ("all", "agent", "path")
MODE_LABELS = ("All known local agents", "One known agent", "Specific file / directory")
MODE_DESCRIPTIONS = (
    "Discover supported local agents",
    "Choose a supported agent",
    "Enter a local file or directory",
)
SHORTCUT_ICONS = {
    "←/→": "⇄",
    "↑/↓": "↕",
    "Enter": "↵",
    "Tab": "⇥",
    "Esc": "↩",
    "Space": "◻",
    "Q": "×",
    "Ctrl+E": "⇩",
    "Ctrl+R": "↻",
}
KIND_GROUPS = {
    "guidance": frozenset(
        (ArtifactKind.INSTRUCTIONS, ArtifactKind.SKILL, ArtifactKind.MEMORY, ArtifactKind.SOUL)
    ),
    "mcp": frozenset((ArtifactKind.MCP_CONFIG,)),
    "configuration": frozenset(
        (
            ArtifactKind.AGENT_CONFIG,
            ArtifactKind.PLUGIN_METADATA,
            ArtifactKind.HOOK_CONFIG,
            ArtifactKind.STRUCTURED_CONFIG,
        )
    ),
    "supply": frozenset((ArtifactKind.SCRIPT, ArtifactKind.DEPENDENCY_MANIFEST)),
}


def _brand_art(*, compact: bool = False) -> Text:
    art = Text()
    lines = COMPACT_LOGO if compact else LOGO
    colors = PALETTE[::2] if compact else PALETTE
    width = max(map(len, lines))
    for index, (line, color) in enumerate(zip(lines, colors, strict=True)):
        art.append(line.ljust(width), style=f"bold {color}")
        if index < len(lines) - 1:
            art.append("\n")
    return art


def _title_lines(variant: Literal["full", "compact", "plain"]) -> tuple[str, ...]:
    """Render the DragonScan wordmark at the available terminal width."""
    if variant == "plain":
        return (TITLE,)
    glyphs = COMPACT_TITLE_GLYPHS if variant == "compact" else TITLE_GLYPHS
    return tuple(
        "  ".join(glyphs[letter][row] for letter in TITLE).rstrip()
        for row in range(len(glyphs["A"]))
    )


def _title_art(variant: Literal["full", "compact", "plain"]) -> Text:
    art = Text()
    lines = _title_lines(variant)
    for index, line in enumerate(lines):
        art.append(line, style=f"bold {PALETTE[min(index // 2 + 2, len(PALETTE) - 1)]}")
        if index < len(lines) - 1:
            art.append("\n")
    return art


def _braille_art(lines: tuple[str, ...], *, dim: bool = False) -> Text:
    art = Text()
    width = max(map(len, BACKGROUND_DRAGON))
    for index, line in enumerate(lines):
        color = "#8d321b" if dim else PALETTE[min(index // 5, len(PALETTE) - 1)]
        art.append(line.ljust(width, "⠀"), style=color)
        if index < len(lines) - 1:
            art.append("\n")
    return art


def _mode_art(mode: str, *, width: int, expanded: bool, detail: str | None = None) -> Text:
    """Draw supported targets as a keyboard-operated list, not fake buttons."""
    art = Text()
    for index, (key, label, description) in enumerate(
        zip(MODES, MODE_LABELS, MODE_DESCRIPTIONS, strict=True), start=1
    ):
        selected = key == mode
        marker = (
            "▾"
            if selected and detail == key
            else "▸"
            if selected and key != "all"
            else "▶"
            if selected
            else " "
        )
        prefix = f" {marker}  "
        icon = ("▦", "◉", "▤")[index - 1]
        suffix = f"  {label}"
        row = prefix + icon + suffix
        if width >= len(row) + 4:
            suffix += " " * (width - len(row) - 2) + "› "
        style = "bold #fff4df on #53200d" if selected else "#d5bca0"
        art.append(prefix, style=style)
        art.append(icon, style="bold #ffe078 on #53200d" if selected else "#d5bca0")
        art.append(suffix, style=style)
        if expanded:
            art.append("\n")
            art.append(f"       {description}", style="#d99c68" if selected else "#92775e")
        if index < len(MODES):
            art.append("\n")
    return art


class ModeChoice(Static):
    """Keyboard focus target for the supported local scan targets."""

    can_focus = True

    def on_click(self, event: events.Click) -> None:
        self.focus()
        row = event.y - 1  # top border
        stride = 2 if self.app.size.height >= 32 else 1
        index = row // stride
        if 0 <= row < stride * len(MODES) and 0 <= index < len(MODES):
            assert isinstance(self.app, ScanApp)
            selected = MODES[index]
            if self.app.mode == selected and selected != "all":
                self.app._toggle_target_detail()
            else:
                self.app._set_mode(selected)


@dataclass(frozen=True)
class ResultItem:
    kind: Literal["agent", "severity", "finding", "paths", "path", "diagnostic"]
    label: str
    count: int = 0
    finding: Finding | None = None
    path: Path | None = None
    detail: str = ""


SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff7664",
    Severity.HIGH: "#ffa263",
    Severity.MEDIUM: "#ffe078",
    Severity.LOW: "#8bcff4",
    Severity.INFO: "#a3c8a0",
}


class ScanApp(App[None]):
    """A staged local scan flow with an explicit, separate results view."""

    CSS = """
    Screen { background: #080807; color: #f1e4d0; }
    #splash { align: center middle; background: #080807; }
    #splash-panel { width: 78; max-width: 96%; height: auto; padding: 1 2;
                    border: round #c44813; background: #100b08; }
    #splash-art, #dragon-art { width: 100%; text-align: center; height: auto; }
    #dragon-art { margin-top: 1; }
    #splash-caption, #splash-progress { width: 100%; text-align: center; margin-top: 1; }
    #splash-caption { color: #c78b59; border-top: solid #6a2b12; padding-top: 1; }
    #splash-progress { color: #ffd65b; text-style: bold; border-top: solid #6a2b12; }
    #splash .hint { text-align: center; }
    #splash-panel.compact { padding: 0 2; }
    #splash-panel.compact #dragon-art,
    #splash-panel.compact #splash-caption,
    #splash-panel.compact #splash-progress,
    #splash-panel.compact .hint { margin: 0; }
    #splash-panel.compact #splash-caption { padding-top: 0; }
    #splash-panel.large { padding: 0 2; }
    #splash-panel.large #dragon-art,
    #splash-panel.large #splash-caption,
    #splash-panel.large #splash-progress,
    #splash-panel.large .hint { margin: 0; }
    #splash-panel.large #splash-caption { padding-top: 0; }
    #main { height: 1fr; display: none; }
    #banner { height: 8; margin: 0 1; border: round #a82916;
              layout: horizontal; background: #170d09; }
    #brand-pane { width: 1fr; height: 1fr; content-align: center middle; }
    #brand { height: 5; text-align: center; color: #ffd65b; }
    #brand-caption { height: 1; text-align: center; color: #ffb32c; }
    #banner-meta { width: 33; height: 1fr; padding: 0 1;
                   border-left: solid #a82916; color: #e5a657;
                   content-align: left middle; }
    #content { height: 1fr; padding: 0 2; layers: backdrop foreground;
               border-bottom: solid #6a2b12; }
    #watermark { layer: foreground; dock: right; width: 37; height: 1fr;
                 background: transparent; }
    .page { layer: foreground; height: 1fr; display: none; padding: 0 1;
            background: transparent; }
    .heading { height: auto; margin: 0 0 1 0; color: #ffd65b; text-style: bold; }
    .description { height: auto; margin-bottom: 1; color: #c6a985; }
    #scope .heading, #scope .description { margin-bottom: 0; }
    #scope Input { margin-bottom: 0; }
    #scope .input-label { height: auto; margin-top: 1; color: #ffe078;
                          text-style: bold; }
    #kinds-note { margin: 0 0 1 0; }
    .hint { height: auto; color: #a88666; margin: 1 0; }
    #target { max-width: 90; }
    #welcome-intro { height: auto; padding: 1 0; margin-bottom: 1;
                     border-bottom: solid #a82916; }
    #welcome-intro .welcome-heading { margin-bottom: 0; }
    #welcome-intro .description { margin: 0; }
    .welcome-heading { height: auto; color: #ffd65b; text-style: bold; }
    #target .heading { height: 3; padding: 0 1; margin-bottom: 0;
                       border: round #a82916; color: #ffe078; }
    #target-description { margin-bottom: 1; }
    #target .hint { padding: 0 1; border: round #3d8bb3; color: #8bcff4; }
    .target-detail { height: auto; margin: 0 0 1 1; padding: 1 2;
                     border-left: heavy #ffb32c; background: #170d09; }
    .detail-title { height: auto; color: #ffe078; text-style: bold; }
    .detail-help { height: auto; color: #c6a985; margin: 0 0 1 0; }
    .detail-example { height: auto; color: #8bcff4; margin: 0 0 1 0; }
    .target-detail Button { width: auto; min-width: 23; margin: 0;
                            background: #7e320e; color: #fff1d5; }
    .target-detail Button:focus { background: #bd5318; }
    #path { margin-bottom: 1; }
    #navigation { height: 2; padding: 0 2; background: #100b08;
                  border-top: solid #a82916; color: #ffd65b; }
    #navigation.target-hints { height: 3; padding-bottom: 1; }
    #mode { height: 5; color: #ffe078; background: #100b08;
            border: round #6a2b12; margin-bottom: 1; }
    #mode:focus { border: round #ffb32c; }
    Input, Select { margin-bottom: 1; background: #170d09; color: #fff4df; }
    Input { border: solid #704b28; }
    Input:focus { border: solid #ffb32c; background: #21140d; }
    Input > .input--placeholder { color: #d8c3a5; text-style: none; }
    Select > SelectCurrent { border: solid #704b28; color: #fff4df;
                             background: #170d09; }
    Select:focus > SelectCurrent { border: solid #ffb32c;
                                   background: #21140d; }
    Select > SelectOverlay { border: solid #704b28; }
    SelectionList:focus { border: solid #ffb32c; }
    #agent SelectOverlay { max-height: 8; }
    SelectionList { height: 10; background: #170d09; border: solid #693019; }
    #status { height: 2; padding: 0 2; color: #ffd65b; }
    #activity { display: none; height: 1; color: #fa7b0c; }
    #results-layout { height: 1fr; min-height: 12; }
    #findings-tree { width: 42%; height: 1fr; border: solid #704b28;
                     background: #130e0b; color: #f1e4d0; }
    #findings-tree, #finding-pane, #results-content {
        scrollbar-color: #704b28;
        scrollbar-color-hover: #ffb32c;
        scrollbar-color-active: #ffb32c;
        scrollbar-background: #130e0b;
    }
    #findings-tree:focus { border: solid #ffb32c; }
    #findings-tree > .tree--guides { color: #84664f; }
    #findings-tree > .tree--cursor { background: #62300f; color: #fff4df;
                                    text-style: bold; }
    #finding-pane { width: 1fr; height: 1fr; padding: 0 2;
                    border: solid #704b28; background: #170d09; }
    #finding-content { height: auto; color: #f1e4d0; }
    #results-layout.stacked { layout: vertical; height: 12; min-height: 8; max-height: 100%; }
    #results-layout.stacked #findings-tree { width: 100%; height: 1fr; }
    #results-layout.stacked #finding-pane { width: 100%; height: 1fr; padding: 0 1; }
    .empty-results { color: #c6a985; padding: 0 0 1 0; }
    #summary { height: auto; margin-bottom: 1; }
    #coverage { height: auto; padding: 0 1; margin-bottom: 1;
                border-left: solid #8ab17d; }
    #coverage.partial { color: #ffe078; border-left: solid #fa7b0c; }
    #coverage.failed { color: #ff9885; border-left: solid #a82916; }
    #results-content { height: 1fr; }
    #review { height: auto; color: #f1e4d0; }
    #scan-action { height: auto; margin-top: 1; padding: 0 1;
                   border: solid #a75b1a; background: #21140d; }
    #scan-action .action-title { height: auto; color: #ffe078;
                                 text-style: bold; }
    #scan-instruction { height: auto; color: #f1d5ac; }
    #start-scan { width: auto; min-width: 24; height: 1; padding: 0 2;
                  border: none; background: #87350d; color: #fff4df;
                  text-style: bold; }
    #start-scan:focus { border: none; background: #bd5318; }
    """
    BINDINGS = [
        Binding("enter", "advance_stage", "Next", priority=True, show=False),
        Binding("escape", "back_stage", "Back", priority=True, show=False),
        Binding("ctrl+e", "export_report", "Export", priority=True, show=False),
        Binding("ctrl+r", "restart_scan", "New scan", priority=True, show=False),
        ("q", "quit", "Quit"),
    ]
    PAGES = ("target", "scope", "confirm", "results")

    def __init__(self) -> None:
        super().__init__()
        self.title = "DragonScan"
        self.report: ScanReport | None = None
        self.policy: PolicyResult | None = None
        self.saved_path: Path | None = None
        self.stage = "splash"
        self.mode = "all"
        self.detail: str | None = None
        self.scanning = False
        self._frame = 0

    def compose(self) -> ComposeResult:
        with Container(id="splash"):
            with Container(id="splash-panel"):
                yield Static(_brand_art(), id="splash-art")
                yield Static(_braille_art(BACKGROUND_DRAGON), id="dragon-art")
                yield Static("AI AGENT SCANNER  ·  LOCAL FIRST", id="splash-caption")
                yield Static("◐  Loading", id="splash-progress")
                yield Static("Enter / Space skip    ·    q quit", classes="hint")
        with VerticalScroll(id="main"):
            with Container(id="banner"):
                with Container(id="brand-pane"):
                    yield Static(_title_art("compact"), id="brand")
                    yield Static("AI AGENT SCANNER  ─  LOCAL INSPECTION", id="brand-caption")
                yield Static("", id="banner-meta")
            with VerticalScroll(id="content"):
                yield Static("", id="watermark")
                with VerticalScroll(id="target", classes="page"):
                    with Container(id="welcome-intro"):
                        yield Static("Welcome to DragonScan", classes="welcome-heading")
                        yield Static(
                            "Inspect agent artifacts locally without executing them.",
                            classes="description",
                        )
                    yield Static("01  /  What would you like to scan?", classes="heading")
                    yield Static(
                        "Use arrow keys to select a target, then Enter to continue.",
                        id="target-description",
                        classes="description",
                    )
                    yield ModeChoice("", id="mode")
                    with Container(id="agent-detail", classes="target-detail"):
                        yield Static("02  /  Choose an agent", classes="detail-title")
                        yield Static(
                            "Select one supported local agent. Enter on the field opens the list; "
                            "arrow keys move, Enter confirms, Esc closes it.",
                            classes="detail-help",
                        )
                        yield Select(
                            [(spec.kind, spec.kind) for spec in SPECS],
                            value=SPECS[0].kind,
                            id="agent",
                        )
                        yield Button("Continue to scan scope  →", id="agent-next")
                    with Container(id="path-detail", classes="target-detail"):
                        yield Static("02  /  Local file or directory path", classes="detail-title")
                        yield Static(
                            "Enter a supported artifact file or directory path.",
                            classes="detail-help",
                        )
                        yield Input(
                            placeholder="./agent-directory/SKILL.md",
                            id="path",
                        )
                        yield Static(
                            "Examples: ./agent-directory/SKILL.md  or  ./agent-directory\n"
                            "Relative to your working directory; local paths only.",
                            classes="detail-example",
                        )
                        yield Button("Continue to scan scope  →", id="path-next")
                    yield Static(
                        "Discovery checks supported local agent locations; "
                        "no artifact code is executed.",
                        id="target-notice",
                        classes="hint",
                    )
                with VerticalScroll(id="scope", classes="page"):
                    yield Static("02  /  Scan scope", classes="heading")
                    yield Static(
                        "Leave numeric fields blank to use the default limits.",
                        classes="description",
                    )
                    yield Static("File groups to analyze (specific paths only):", id="kinds-label")
                    yield SelectionList[str](
                        ("Instructions / skills / memory / soul", "guidance", True),
                        ("MCP configurations", "mcp", True),
                        ("Agent / plugin / hook configurations", "configuration", True),
                        ("Scripts and dependency manifests", "supply", True),
                        id="kinds",
                    )
                    yield Static(
                        "Known agents: all supported file types are included.",
                        id="kinds-note",
                        classes="hint",
                    )
                    for name, label, placeholder in (
                        ("entries", "Entries per root", "Blank = per-directory safety limits"),
                        ("artifacts", "Artifact budget", "Blank = no total artifact cap"),
                        ("per-root", "Artifacts per root", "Blank = no per-root artifact cap"),
                        ("depth", "Maximum depth", "Blank = mode default"),
                    ):
                        yield Static(label, id=f"{name}-label", classes="input-label")
                        yield Input(placeholder=placeholder, id=name)
                    yield Static(
                        "Reached limits and narrowed scope are reported as incomplete coverage.",
                        classes="hint",
                    )
                with VerticalScroll(id="confirm", classes="page"):
                    yield Static("03  /  Ready to scan", classes="heading")
                    yield Static("", id="review", markup=False)
                    with Container(id="scan-action"):
                        yield Static("NEXT  /  Start local analysis", classes="action-title")
                        yield Static(
                            "Press Enter or click below to start the scan. Esc changes scope.",
                            id="scan-instruction",
                        )
                        yield Button("▶  Start local scan", id="start-scan")
                    yield Static("Scans use local, static analysis only.", classes="hint")
                with Container(id="results", classes="page"):
                    yield Static("04  /  Findings and coverage", classes="heading")
                    yield Static("", id="coverage", markup=False)
                    with VerticalScroll(id="results-content"):
                        yield Static("", id="summary", markup=False)
                        yield Static("", classes="empty-results", markup=False)
                        with Horizontal(id="results-layout"):
                            yield Tree("Findings", id="findings-tree")
                            with VerticalScroll(id="finding-pane"):
                                yield Static(
                                    "Select an agent to explore the scan.", id="finding-content"
                                )
                        yield Static("Save the report to a new private file:", classes="hint")
                        yield Select(
                            [("JSON", "json"), ("SARIF", "sarif"), ("Terminal text", "terminal")],
                            value="json",
                            id="export-format",
                        )
                        yield Input(placeholder="Output file path", id="export-path")
            yield Static("", id="activity")
            yield Static("", id="status", markup=False)
            yield Static("", id="navigation")

    def copy_to_clipboard(self, text: str) -> None:
        """Copy a Textual selection to the macOS clipboard as well as the terminal."""
        super().copy_to_clipboard(text)
        if sys.platform != "darwin" or not text:
            return
        try:
            subprocess.run(("pbcopy",), input=text, text=True, check=True, timeout=2)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.notify("Could not access the macOS clipboard.", severity="warning")

    def on_mount(self) -> None:
        self._set_mode("all")
        self._show_stage("splash")
        self.set_interval(0.12, self._tick)
        self.set_timer(2.0, self._end_splash)

    def on_resize(self, event: events.Resize) -> None:
        width, height = event.size.width, event.size.height
        self.query_one("#main").styles.border = (
            ("round", "#a82916") if width >= 110 and height >= 32 else ("none", "transparent")
        )
        variant: Literal["full", "compact", "plain"]
        if width >= 90 and height >= 26:
            variant = "full"
        elif width >= 52 and height >= 20:
            variant = "compact"
        else:
            variant = "plain"
        if self.stage == "results" and height < 32:
            variant = "plain"
        self._set_brand(variant)
        self.query_one("#brand-caption").display = width >= 45
        meta = self.query_one("#banner-meta", Static)
        meta.display = width >= 118 and height >= 26
        if meta.display:
            self._update_banner_meta()
        self.query_one("#mode").styles.height = 8 if height >= 32 else 5
        intro = self.query_one("#welcome-intro")
        heading = self.query_one("#target .heading")
        if height < 28:
            intro.styles.padding = (0, 0)
            intro.styles.margin = (0, 0)
            heading.styles.height = 1
            heading.styles.border = ("none", "transparent")
        else:
            intro.styles.padding = (1, 0)
            intro.styles.margin = (0, 0, 1, 0)
            heading.styles.height = 3
            heading.styles.border = ("round", "#a82916")
        self.query_one("#target-notice").display = height >= 28
        self._render_mode()
        if self.stage == "target" and self.detail is not None:
            self.call_after_refresh(self._reveal_target_detail)

        full_art = event.size.width >= 70 and event.size.height >= 42
        panel = self.query_one("#splash-panel")
        panel.set_class(not full_art, "compact")
        panel.set_class(full_art, "large")
        self.query_one("#splash-art", Static).update(
            _brand_art(compact=event.size.width < 80 or event.size.height < 50)
        )
        self.query_one("#dragon-art", Static).update(
            _braille_art(BACKGROUND_DRAGON) if full_art else self._compact_splash_art(event)
        )
        self.query_one("#dragon-art", Static).display = (
            event.size.width >= 45 and event.size.height >= 20
        )
        self.query_one("#results-layout").set_class(width < 105, "stacked")
        self._update_navigation(width)
        if self.stage == "results":
            tree = self.query_one("#findings-tree", Tree)
            node = tree.get_node_at_line(tree.cursor_line) if tree.cursor_line >= 0 else None
            if node is not None:
                self.call_after_refresh(self._present_result, node.data)
        watermark = self.query_one("#watermark", Static)
        # A dock must never take the space needed by forms or the results inspector.
        watermark.display = width >= 115 and height >= 35 and self.stage != "results"
        if watermark.display:
            visible = min(len(BACKGROUND_DRAGON), event.size.height - 6)
            start = (len(BACKGROUND_DRAGON) - visible) // 2
            watermark.update(_braille_art(BACKGROUND_DRAGON[start : start + visible], dim=True))

    def _set_brand(self, variant: Literal["full", "compact", "plain"]) -> None:
        brand = self.query_one("#brand", Static)
        brand.update(_title_art(variant))
        brand.styles.height = len(_title_lines(variant))
        self.query_one("#banner").styles.height = len(_title_lines(variant)) + 3

    @staticmethod
    def _compact_splash_art(event: events.Resize) -> Text:
        visible = min(len(BACKGROUND_DRAGON), max(7, event.size.height - 12))
        start = (len(BACKGROUND_DRAGON) - visible) // 2
        return _braille_art(BACKGROUND_DRAGON[start : start + visible])

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "advance_stage":
            return self.stage == "splash" or (
                not self.scanning
                and self.stage in ("target", "scope", "confirm")
                and not isinstance(self.focused, Select)
                and not (self.stage == "target" and self.query_one("#agent", Select).expanded)
            )
        if action == "back_stage":
            return not self.scanning and (
                self.stage in ("scope", "confirm")
                or (
                    self.stage == "target"
                    and self.detail is not None
                    and not self.query_one("#agent", Select).expanded
                )
            )
        if action in ("export_report", "restart_scan"):
            return self.stage == "results" and not self.scanning
        return super().check_action(action, parameters)

    def action_advance_stage(self) -> None:
        if self.stage == "splash":
            self._end_splash()
        elif self.stage == "target" and isinstance(self.focused, ModeChoice) and self.mode != "all":
            self._toggle_target_detail()
        elif not self.scanning and self.stage in ("target", "scope", "confirm"):
            self._advance()

    def _toggle_target_detail(self) -> None:
        self.detail = None if self.detail == self.mode else self.mode
        self._update_mode()
        self._render_mode()
        self._update_navigation()
        if self.detail == "agent":
            self.set_focus(self.query_one("#agent", Select))
        elif self.detail == "path":
            self.set_focus(self.query_one("#path", Input))
        else:
            self.set_focus(self.query_one("#mode", ModeChoice))
        if self.detail is not None:
            self.call_after_refresh(self._reveal_target_detail)

    def _reveal_target_detail(self) -> None:
        if self.stage != "target" or self.detail not in ("agent", "path"):
            return
        field = (
            self.query_one("#agent", Select)
            if self.detail == "agent"
            else self.query_one("#path", Input)
        )
        self.set_focus(field)
        target = self.query_one("#target", VerticalScroll)
        if self.size.height >= 32:
            target.scroll_to_widget(self.query_one(f"#{self.detail}-next", Button), animate=False)
        elif self.detail == "path":
            target.scroll_to_widget(
                self.query_one("#path-detail .detail-example", Static), animate=False
            )
        else:
            target.scroll_to_widget(field, animate=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self.stage == "confirm" and event.button.id == "start-scan" and not self.scanning:
            self._advance()
        elif (
            self.stage == "target"
            and self.detail == self.mode
            and event.button.id == f"{self.mode}-next"
        ):
            self._advance()

    def action_back_stage(self) -> None:
        if not self.scanning and self.stage == "target" and self.detail is not None:
            self.detail = None
            self._update_mode()
            self._render_mode()
            self.set_focus(self.query_one("#mode", ModeChoice))
            self._update_navigation()
        elif not self.scanning and self.stage in ("scope", "confirm"):
            self._show_stage(self.PAGES[self.PAGES.index(self.stage) - 1])

    def action_export_report(self) -> None:
        if self.stage == "results" and not self.scanning:
            self._export()

    def action_restart_scan(self) -> None:
        if self.stage == "results" and not self.scanning:
            self._show_stage("target")

    def on_key(self, event: events.Key) -> None:
        if self.stage == "splash":
            if event.key in ("enter", "space"):
                self._end_splash()
                event.stop()
            return
        if self.scanning:
            return
        focused = self.focused
        if event.key in ("up", "down") and self.stage == "target":
            if isinstance(focused, ModeChoice):
                step = -1 if event.key == "up" else 1
                self._set_mode(MODES[(MODES.index(self.mode) + step) % len(MODES)])
                event.stop()
        elif event.key in ("left", "right") and self.stage == "target":
            if not isinstance(focused, (Input, Select)) and not (
                self.mode == "agent" and self.query_one("#agent", Select).expanded
            ):
                step = -1 if event.key == "left" else 1
                self._set_mode(MODES[(MODES.index(self.mode) + step) % len(MODES)])
                event.stop()
        elif event.key == "r" and self.stage == "results" and not isinstance(focused, Input):
            self.action_restart_scan()
            event.stop()

    def _tick(self) -> None:
        # Textual stops running before pruning widgets, while timers may still fire.
        if not self.is_running:
            return
        if self.stage != "splash" and not self.scanning:
            return
        frames = "◐◓◑◒"
        self._frame = (self._frame + 1) % len(frames)
        if self.stage == "splash":
            self.query_one("#splash-progress", Static).update(f"{frames[self._frame]}  Loading")
        else:
            self.query_one("#activity", Static).update(
                f"{frames[self._frame]}  Scanning local artifacts…"
            )

    def _end_splash(self) -> None:
        if self.is_running and self.stage == "splash":
            self._show_stage("target")

    def _update_banner_meta(self) -> None:
        try:
            release = version("dragons-ai-agent-scanner")
        except PackageNotFoundError:
            release = "unknown"
        status = "Scanning" if self.scanning else "Review" if self.stage == "results" else "Ready"
        self.query_one("#banner-meta", Static).update(
            f"VERSION   {release}\n"
            "MODE      Local inspection\n"
            "ENGINE    Static analysis\n"
            f"STATUS    {status}"
        )

    def _show_stage(self, stage: str) -> None:
        self.stage = stage
        if self.size.height < 32:
            variant: Literal["full", "compact", "plain"] = (
                "plain" if stage == "results" or self.size.width < 52 else "compact"
            )
            self._set_brand(variant)
        self._update_banner_meta()
        self.query_one("#splash").display = stage == "splash"
        self.query_one("#main").display = stage != "splash"
        self.query_one("#watermark").display = (
            stage != "results" and self.size.width >= 115 and self.size.height >= 35
        )
        for page in self.PAGES:
            self.query_one(f"#{page}").display = stage == page
        self._update_navigation()
        self.query_one("#scan-action").display = not self.scanning
        self.query_one("#status", Static).update("")
        if stage == "target":
            self.set_focus(self.query_one("#mode", ModeChoice))
        elif stage == "scope":
            self.set_focus(
                self.query_one("#kinds", SelectionList)
                if self.mode == "path"
                else self.query_one("#entries", Input)
            )
        elif stage == "confirm" and not self.scanning:
            self.set_focus(self.query_one("#start-scan", Button))
            self.call_after_refresh(self._reveal_scan_action)
        else:
            self.set_focus(None)

    def _reveal_scan_action(self) -> None:
        if self.stage == "confirm" and not self.scanning:
            self.query_one("#confirm", VerticalScroll).scroll_to_widget(
                self.query_one("#scan-action"), animate=False
            )

    def _update_navigation(self, width: int | None = None) -> None:
        items: tuple[tuple[str, str, str], ...]
        if self.stage == "target":
            if self.detail == "agent":
                items = (
                    ("↑/↓", "Choose agent", "Select"),
                    ("Enter", "Open list", "Open"),
                    ("Tab", "Next field", "Next"),
                    ("Esc", "Close detail", "Back"),
                )
            elif self.detail == "path":
                items = (
                    ("Tab", "Next field", "Next"),
                    ("Enter", "Continue", "Next"),
                    ("Esc", "Close detail", "Back"),
                )
            else:
                items = (
                    ("←/→", "Change target", "Target"),
                    ("Enter", "Continue" if self.mode == "all" else "Open details", "Open"),
                    ("Q", "Quit", "Quit"),
                )
        elif self.stage == "scope":
            items = ((("Space", "Toggle group", "Toggle"),) if self.mode == "path" else ()) + (
                ("Tab", "Next field", "Fields"),
                ("Enter", "Continue", "Next"),
                ("Esc", "Back", "Back"),
            )
        elif self.stage == "confirm":
            items = (("Enter", "Start scan", "Start"), ("Esc", "Change scope", "Back"))
        elif self.stage == "results":
            items = (
                ("↑/↓", "Select", "Select"),
                ("Enter", "Open", "Open"),
                ("Ctrl+E", "Export", "Export"),
                ("←/→", "Fold", "Fold"),
                ("Ctrl+R", "New scan", "New"),
            )
        else:
            items = ()
        navigation = self.query_one("#navigation", Static)
        navigation.set_class(self.stage == "target" and self.detail is None, "target-hints")
        if self.scanning:
            navigation.update("Scanning local artifacts…")
            return
        terminal_width = width if width is not None else self.size.width
        available = max(0, terminal_width - 4)
        if navigation.content_region.width:
            available = min(available, navigation.content_region.width)
        art = Text(overflow="crop", no_wrap=True)
        for index, (key, label, short) in enumerate(items):
            for caption in (label, short):
                fragment = Text()
                if art:
                    fragment.append("   ")
                icon = SHORTCUT_ICONS[key]
                if index == 0:
                    fragment.append(f" [{key}]  {icon} {caption} ", style="bold #27170f on #e7d2af")
                else:
                    fragment.append(f"[{key}]", style="bold #fff4df on #51321f")
                    fragment.append(f" {icon}", style="bold #ffb32c")
                    fragment.append(f" {caption}", style="#e4caa6")
                if art.cell_len + fragment.cell_len <= available:
                    art.append_text(fragment)
                    break
        navigation.update(art)

    def _render_mode(self) -> None:
        width, height = self.size
        available = width - (49 if width >= 115 and height >= 35 else 14)
        self.query_one("#mode", Static).update(
            _mode_art(
                self.mode,
                width=max(20, min(76, available)),
                expanded=height >= 32,
                detail=self.detail,
            )
        )

    def _set_mode(self, mode: str) -> None:
        if self.mode != mode:
            self.detail = None
        self.mode = mode
        self._render_mode()
        self.query_one("#target-description", Static).update(
            "Choose a target with the arrow keys. Enter opens its details; Esc closes them."
            if mode != "all"
            else "Choose a target with the arrow keys. Enter continues with all local agents."
        )
        self.query_one("#target-notice", Static).update(
            "Static analysis of the chosen local path; no artifact code is executed."
            if mode == "path"
            else "Discovery checks supported local agent locations; no artifact code is executed."
        )
        self._update_mode()
        if self.stage == "target":
            self._update_navigation()

    def _update_mode(self) -> None:
        mode = self.mode
        self.query_one("#agent-detail").display = self.detail == "agent" and mode == "agent"
        self.query_one("#path-detail").display = self.detail == "path" and mode == "path"
        self.query_one("#kinds", SelectionList).display = mode == "path"
        self.query_one("#kinds-label").display = mode == "path"
        self.query_one("#kinds-note").display = mode != "path"
        for name in ("entries", "per-root"):
            self.query_one(f"#{name}", Input).display = mode != "path"
            self.query_one(f"#{name}-label", Static).display = mode != "path"

    def _configuration(self) -> tuple[str, Path | None, dict[str, int]]:
        mode = self.mode
        path = self.query_one("#path", Input).value.strip()
        if mode == "path" and not path:
            raise ValueError("Select a local file or directory.")
        budgets: dict[str, int] = {}
        for field, name in (
            ("entries", "max_entries_per_root"),
            ("artifacts", "max_artifacts"),
            ("per-root", "max_artifacts_per_root"),
            ("depth", "max_depth"),
        ):
            value = self.query_one(f"#{field}", Input).value.strip()
            if (mode != "path" or field in ("artifacts", "depth")) and value:
                if not value.isdecimal() or int(value) < 1:
                    raise ValueError("Discovery limits must be positive integers.")
                budgets[name] = int(value)
        selected = self.query_one("#kinds", SelectionList).selected
        if mode == "path" and not selected:
            raise ValueError("Select at least one file group.")
        if mode == "path" and Path(path).is_file():
            if "max_artifacts" in budgets or "max_depth" in budgets:
                raise ValueError("Depth and artifact budgets require a local directory.")
            if Path(path).suffix.lower() in (".zip", ".tar", ".gz", ".tgz") and (
                len(selected) != len(KIND_GROUPS)
            ):
                raise ValueError("File-group selection is unavailable for archive scans.")
        return mode, Path(path) if mode == "path" else None, budgets

    def _advance(self) -> None:
        if self.stage in ("target", "scope"):
            if self.stage == "scope":
                try:
                    mode, path, budgets = self._configuration()
                except ValueError as exc:
                    self.query_one("#status", Static).update(str(exc))
                    return
                subject = (
                    str(path)
                    if mode == "path"
                    else (
                        str(self.query_one("#agent", Select).value)
                        if mode == "agent"
                        else "All known local agents"
                    )
                )
                groups = self.query_one("#kinds", SelectionList).selected
                limits = (
                    ", ".join(
                        f"{name.replace('_', ' ').title()}: {value}"
                        for name, value in budgets.items()
                    )
                    if budgets
                    else "Defaults"
                )
                cautions = []
                if mode == "path" and len(groups) < len(KIND_GROUPS):
                    cautions.append(
                        "Excluded file groups: "
                        + ", ".join(group for group in KIND_GROUPS if group not in groups)
                    )
                if "max_depth" in budgets:
                    cautions.append("Paths beyond the depth limit will not be scanned.")
                self.query_one("#review", Static).update(
                    f"Target: {_safe_text(subject)}\n"
                    f"File groups: {', '.join(groups) if mode == 'path' else 'All supported'}\n"
                    f"Limits: {limits}\n"
                    + (
                        "\n".join(cautions)
                        if cautions
                        else "Coverage is reported with the results."
                    )
                )
            elif self.stage == "target" and self.mode == "path":
                if not self.query_one("#path", Input).value.strip():
                    self.query_one("#status", Static).update("Enter a file or directory path.")
                    return
            self.query_one("#status", Static).update("")
            self._show_stage(self.PAGES[self.PAGES.index(self.stage) + 1])
        elif self.stage == "confirm":
            try:
                mode, path, budgets = self._configuration()
            except ValueError as exc:
                self.query_one("#status", Static).update(str(exc))
                return
            self.report = None
            self.policy = None
            self.saved_path = None
            self.query_one("#summary", Static).update("")
            self.query_one("#findings-tree", Tree).clear()
            self.query_one("#finding-content", Static).update("")
            self.scanning = True
            self.query_one("#activity", Static).display = True
            self._show_stage("confirm")
            self.query_one("#status", Static).update("Scanning local artifacts…")
            agent = str(self.query_one("#agent", Select).value) if mode == "agent" else None
            selected_groups = frozenset(self.query_one("#kinds", SelectionList).selected)
            self._scan(mode, path, budgets, agent, selected_groups)

    @work(thread=True, exclusive=True)
    def _scan(
        self,
        mode: str,
        path: Path | None,
        budgets: dict[str, int],
        agent: str | None,
        groups: frozenset[str],
    ) -> None:
        try:
            scanner = Scanner()
            if mode == "path":
                assert path is not None

                if path.suffix.lower() in (".zip", ".tar", ".gz", ".tgz") and not path.is_dir():
                    with acquire(str(path), remote=False, git=False) as acquired:
                        report = scanner.scan_acquired(acquired)
                elif len(groups) == len(KIND_GROUPS) and "max_depth" not in budgets:
                    report = scanner.scan(Target(path), max_artifacts=budgets.get("max_artifacts"))
                else:
                    discovery_messages: list[str] = []
                    artifacts = discover(
                        Target(path),
                        max_artifacts=budgets.get("max_artifacts"),
                        max_depth=budgets.get("max_depth"),
                        limit_diagnostics=discovery_messages,
                    )

                    kinds = frozenset().union(*(KIND_GROUPS[group] for group in groups))
                    selected = tuple(item for item in artifacts if item.kind in kinds)
                    if not selected:
                        raise DiscoveryError("No supported files found in the selected scope.")
                    report = scanner.scan(Target(path), artifacts=selected)
                    report = replace(
                        report,
                        coverage={
                            **report.coverage,
                            "discovered": len(artifacts),
                            "skipped": len(artifacts) - len(selected),
                        },
                    )
                    if discovery_messages:
                        report = replace(
                            report,
                            diagnostics=(
                                *report.diagnostics,
                                *(
                                    Diagnostic("coverage", message)
                                    for message in discovery_messages
                                ),
                            ),
                        )
                    exclusions = []
                    if len(selected) < len(artifacts):
                        exclusions.append(
                            f"Excluded artifacts: {len(artifacts) - len(selected)} "
                            "(file-group selection)"
                        )
                    if len(groups) < len(KIND_GROUPS):
                        exclusions.append("Unselected file groups were not analyzed")
                    if "max_depth" in budgets:
                        exclusions.append(
                            f"Directory depth limited to {budgets['max_depth']}; "
                            "deeper files were not analyzed"
                        )
                    if exclusions:
                        report = replace(
                            report,
                            diagnostics=(
                                *report.diagnostics,
                                Diagnostic("coverage", "; ".join(exclusions)),
                            ),
                        )

            else:
                report = scanner.scan_installed(
                    agent=agent,
                    max_entries_per_root=budgets.get("max_entries_per_root"),
                    max_artifacts=budgets.get("max_artifacts"),
                    max_artifacts_per_root=budgets.get("max_artifacts_per_root"),
                    max_depth=budgets.get("max_depth"),
                )
            policy = evaluate(report)
            saved = None
            if mode != "path":
                from dragonscan.cli import _save_installed_report

                saved = _save_installed_report(report, policy)
            self.call_from_thread(self._finish, report, policy, saved)
        except (DiscoveryError, ValueError, OSError) as exc:
            self.call_from_thread(self._failed, f"Scan could not be completed: {exc}")
        except Exception:
            # Unexpected parser or provider errors must never be exposed as clean scans.
            self.call_from_thread(self._failed, "Scan failed unexpectedly.")

    def _failed(self, message: str) -> None:
        self.scanning = False
        self.query_one("#activity", Static).display = False
        self._show_stage("confirm")
        self.query_one("#status", Static).update(
            Text(f"Risk: NOT ASSESSED · {_safe_text(message)}")
        )

    def _finish(self, report: ScanReport, policy: PolicyResult, saved: Path | None) -> None:
        self.scanning = False
        self.query_one("#activity", Static).display = False
        self._show_stage("results")
        self.report, self.policy, self.saved_path = report, policy, saved
        self.query_one("#status", Static).update(
            f"{policy.scan_status} · {len(report.artifacts)} artifacts · "
            f"{len(report.findings)} findings · {policy.status}"
        )
        severity_counts = {severity: 0 for severity in Severity}
        for finding in report.findings:
            severity_counts[finding.severity] += 1
        breakdown = "  ·  ".join(
            f"{severity.value.upper()} {count}"
            for severity, count in severity_counts.items()
            if count
        )
        self.query_one("#summary", Static).update(
            f"Target: {_safe_text(report.target)}\n"
            f"Artifacts: {len(report.artifacts)}  ·  Findings: {len(report.findings)}"
            + f"\nRisk: {risk_label(report, policy).upper()}"
            + (f"\nSeverities: {breakdown}" if breakdown else "")
            + (
                f"\nAnalysis: {report.coverage['attempted']} attempted · "
                f"{report.coverage['parsed']} parsed · "
                f"{report.coverage['fully_analyzed']} full · "
                f"{report.coverage['partially_analyzed']} partial · "
                f"{report.coverage['failed']} failed"
                if report.coverage
                else ""
            )
            + (f"\nDetailed JSON: {_safe_text(saved)}" if saved else "")
        )
        coverage = self.query_one("#coverage", Static)
        coverage.remove_class("partial", "failed")
        if policy.scan_status == "complete":
            coverage.update("Coverage: COMPLETE for the selected scope.")
        elif policy.scan_status == "partial":
            coverage.add_class("partial")
            coverage.update(
                "Coverage: PARTIAL — some content was not analyzed. "
                "Review coverage and diagnostics below."
            )
        else:
            coverage.add_class("failed")
            coverage.update("Coverage: FAILED — scan errors occurred. Review diagnostics below.")
        self._populate_results(report, policy)
        self.call_after_refresh(self._focus_results)

    def _populate_results(self, report: ScanReport, policy: PolicyResult) -> None:
        tree = self.query_one("#findings-tree", Tree)
        tree.clear()
        tree.show_root = False
        empty = self.query_one(".empty-results", Static)
        empty.display = not report.findings
        if not report.findings:
            empty.update(
                "No findings in analyzed content."
                if policy.scan_status == "complete"
                else f"No findings in analyzed content; coverage is {policy.scan_status.upper()}."
            )

        # scanned_artifact preserves associations when several agents share one physical file.
        agents_by_path: dict[Path, set[str]] = {}
        for origin in report.artifact_origins:
            if origin.agent:
                agents_by_path.setdefault(origin.scanned_artifact or origin.artifact, set()).add(
                    origin.agent
                )
        groups: dict[str, set[Path]] = {}
        paths = dict.fromkeys(
            (
                *[artifact.path for artifact in report.artifacts],
                *[f.artifact for f in report.findings],
            )
        )
        for path in paths:
            names = agents_by_path.get(path) or {"Local target"}
            for name in names:
                groups.setdefault(name, set()).add(path)
        order = sorted((name for name in groups if name != "Local target"), key=str.casefold)
        if "Local target" in groups:
            order.append("Local target")
        for name in order:
            artifacts = groups[name]
            findings = [finding for finding in report.findings if finding.artifact in artifacts]
            agent = tree.root.add(
                Text(_safe_text(name), style="bold #8bcff4"),
                ResultItem("agent", name, len(findings)),
            )
            for severity in Severity:
                matches = [finding for finding in findings if finding.severity == severity]
                if not matches:
                    continue
                label = severity.value.title()
                color = SEVERITY_COLORS[severity]
                severity_node = agent.add(
                    Text(f"{label}  ·  {len(matches)}", style=f"bold {color}"),
                    ResultItem("severity", label, len(matches)),
                )
                for finding in matches:
                    severity_node.add_leaf(
                        Text(
                            _safe_text(f"{finding.detection_id}  ·  {finding.title}"), style=color
                        ),
                        ResultItem("finding", finding.detection_id, finding=finding),
                    )
            files = agent.add(
                Text(f"Scanned paths  ·  {len(artifacts)}", style="#d8c3a5"),
                ResultItem("paths", name, len(artifacts)),
            )
            for path in sorted(artifacts, key=str):
                files.add_leaf(
                    Text(_safe_text(f"{path.name}  ·  {path.parent.name}"), style="#8bcff4"),
                    ResultItem("path", str(path), path=path),
                )

        diagnostics = [
            *report.errors,
            *(f"{item.level}: {item.message}" for item in report.diagnostics),
            *(
                f"{item.agent}: {item.diagnostic}"
                for item in report.installed_environments
                if item.diagnostic
            ),
        ]
        if diagnostics:
            tree.root.add_leaf(
                Text(f"Coverage and diagnostics  ·  {len(diagnostics)}", style="#ffe078"),
                ResultItem("diagnostic", "Coverage and diagnostics", detail="\n".join(diagnostics)),
            )
        self.query_one("#finding-content", Static).update(
            "Select an agent, severity, finding or scanned path to inspect details."
        )

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted[ResultItem]) -> None:
        if self.stage == "results" and event.control.id == "findings-tree":
            self._present_result(event.node.data)

    def on_tree_node_selected(self, event: Tree.NodeSelected[ResultItem]) -> None:
        if self.stage == "results" and event.control.id == "findings-tree":
            self._present_result(event.node.data)

    @on(events.MouseMove, "#findings-tree")
    def inspect_hovered_result(self, event: events.MouseMove) -> None:
        if self.stage != "results":
            return
        line = event.style.meta.get("line")
        if isinstance(line, int):
            node = self.query_one("#findings-tree", Tree).get_node_at_line(line)
            if node is not None:
                self._present_result(node.data)

    def _present_result(self, item: ResultItem | None) -> None:
        if item is None:
            return
        text = Text()
        if item.kind == "finding" and item.finding is not None:
            finding = item.finding
            compact = self.query_one("#results-layout").has_class("stacked")
            text.append(
                _safe_text(f"{finding.detection_id}  /  {finding.title}") + "\n",
                style="bold #fff4df",
            )
            text.append(
                f"SEVERITY  {finding.severity.value.upper()}",
                style=SEVERITY_COLORS[finding.severity],
            )
            text.append("   CONFIDENCE  " if compact else "\nCONFIDENCE  ", style="bold #d8c3a5")
            text.append(f"{finding.confidence.value.title()}\n", style="#8bcff4")
            text.append(f"CATEGORY  {_safe_text(finding.category)}\n", style="#d8c3a5")
            if compact:
                text.append("EVIDENCE\n", style="bold #ffe078")
                text.append(f"{_safe_text(finding.evidence)}\n")
            text.append("ARTIFACT  ", style="bold #d8c3a5")
            text.append(_safe_text(finding.artifact))
            if finding.line is not None:
                text.append(f":{finding.line}")
            if not compact:
                text.append("\nEVIDENCE\n", style="bold #ffe078")
                text.append(f"{_safe_text(finding.evidence)}\n")
            else:
                text.append("\n")
            text.append("REASON\n", style="bold #ffe078")
            text.append(f"{_safe_text(finding.explanation)}\n")
            for label, value in context_rows(finding):
                text.append(f"{label.upper()}\n", style="bold #ffe078")
                text.append(f"{_safe_text(value)}\n")
            text.append(f"{INTERPRETATION}\n", style="#8bcff4")
            text.append("REMEDIATION\n", style="bold #ffe078")
            text.append(_safe_text(finding.remediation))
        elif item.kind == "path":
            text.append("SCANNED PATH\n", style="bold #8bcff4")
            text.append(_safe_text(item.path))
        elif item.kind == "diagnostic":
            text.append("COVERAGE AND DIAGNOSTICS\n", style="bold #ffe078")
            text.append(_safe_text(item.detail))
        else:
            text.append(f"{_safe_text(item.label)}\n", style="bold #ffe078")
            text.append(
                f"{item.count} {'finding' if item.count == 1 else 'findings'}"
                if item.kind in ("agent", "severity")
                else f"{item.count} scanned {'path' if item.count == 1 else 'paths'}"
            )
            text.append("\nUse Enter or Right to expand; Left to collapse.", style="#c6a985")
        self.query_one("#finding-content", Static).update(text)
        self.query_one("#finding-pane", VerticalScroll).scroll_home(animate=False)

    def _focus_results(self) -> None:
        if self.stage != "results":
            return
        tree = self.query_one("#findings-tree", Tree)
        if self.report is not None and (self.report.artifacts or self.report.findings):
            self.set_focus(tree)
            tree.move_cursor(tree.root.children[0])
        else:
            self.set_focus(self.query_one("#export-format", Select))

    def _export(self) -> None:
        if self.report is None or self.policy is None:
            self.query_one("#status", Static).update("Run a scan first.")
            return
        destination = Path(self.query_one("#export-path", Input).value.strip())
        if not str(destination) or destination == Path("."):
            self.query_one("#status", Static).update("Select an output file.")
            return
        fmt = self.query_one("#export-format", Select).value
        text = (
            json_report(self.report, self.policy)
            if fmt == "json"
            else sarif_report(self.report, self.policy)
            if fmt == "sarif"
            else terminal_report(self.report, self.policy)
        )
        try:
            write_private_report(destination, text + "\n")
        except OSError:
            self.query_one("#status", Static).update(
                "Export failed; choose a new writable file path."
            )
            return
        self.query_one("#status", Static).update(
            Text(f"Saved: {_safe_text(destination.absolute())}")
        )


def run_tui() -> None:
    ScanApp().run()
