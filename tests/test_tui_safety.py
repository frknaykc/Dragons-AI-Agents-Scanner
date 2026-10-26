"""Untrusted report text stays inert at the terminal presentation boundary."""

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Input, Static, Tree

from dragonscan.models import (
    ArtifactOrigin,
    Classification,
    Confidence,
    Diagnostic,
    Finding,
    ScanReport,
    Severity,
)
from dragonscan.policy import evaluate
from dragonscan.tui import ResultItem, ScanApp

# In-memory text only: never emit these sequences to a real terminal.
UNTRUSTED = "[bold]Türkçe[reset]\x1b[2J\x1b]0;title\x07\x9b31m\u202e\u2066\r\x7f"
CONTROLS = ("\x1b", "\x07", "\x9b", "\u202e", "\u2066", "\r", "\x7f")


def assert_inert(text: str) -> None:
    assert not any(char in text for char in CONTROLS)
    assert "[bold]Türkçe[reset]" in text
    assert "\\x1b" in text and "\\u202e" in text


def report() -> ScanReport:
    path = Path("fixtures") / UNTRUSTED / "SKILL.md"
    finding = Finding(
        "DRAGON-PI-001",
        "prompt-injection",
        UNTRUSTED,
        Severity.HIGH,
        Confidence.HIGH,
        Classification.SUSPICIOUS,
        path,
        UNTRUSTED,
        UNTRUSTED,
        UNTRUSTED,
        "behavioral",
        source=UNTRUSTED,
        sink=UNTRUSTED,
    )
    return ScanReport(
        path,
        (),
        (finding,),
        diagnostics=(Diagnostic("coverage", UNTRUSTED),),
        artifact_origins=(ArtifactOrigin(path, "installed_agent", agent=UNTRUSTED),),
    )


@pytest.mark.parametrize("size", [(80, 26), (140, 50)])
def test_report_tree_details_and_summary_escape_untrusted_controls(size: tuple[int, int]) -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=size):
            app._end_splash()
            data = report()
            app._finish(data, evaluate(data), data.target)
            assert_inert(str(app.query_one("#summary", Static).render()))
            tree = app.query_one("#findings-tree", Tree)
            agent = tree.root.children[0]
            assert_inert(str(agent.label))
            assert_inert(str(agent.children[0].children[0].label))
            assert_inert(str(agent.children[1].children[0].label))
            for item in (
                ResultItem("finding", "finding", finding=data.findings[0]),
                ResultItem("path", "path", path=data.target),
                ResultItem("diagnostic", "diagnostic", detail=UNTRUSTED),
                ResultItem("agent", UNTRUSTED),
            ):
                app._present_result(item)
                assert_inert(str(app.query_one("#finding-content", Static).render()))
            # Escaping is presentation-only; evidence and provenance are unchanged.
            assert app.report is data
            assert data.findings[0].evidence == UNTRUSTED

    asyncio.run(run())


def test_scan_error_and_confirmation_escape_untrusted_text() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test():
            app._end_splash()
            app._failed(UNTRUSTED)
            assert_inert(str(app.query_one("#status", Static).render()))
            app._set_mode("path")
            app.query_one("#path", Input).value = "fixtures/" + UNTRUSTED + "/SKILL.md"
            app._show_stage("scope")
            app._advance()
            assert app.stage == "confirm"
            assert_inert(str(app.query_one("#review", Static).render()))

    asyncio.run(run())
