"""Keyboard navigation and splash geometry in the interactive scanner."""

import asyncio
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual import events
from textual.app import App
from textual.content import Content
from textual.pilot import Pilot
from textual.widgets import Button, Input, Select, SelectionList, Static, Tree
from textual.widgets.tree import TreeNode

from dragonscan.models import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    Classification,
    Confidence,
    Diagnostic,
    Finding,
    ScanReport,
    Severity,
    SourceFormat,
)
from dragonscan.policy import evaluate
from dragonscan.tui import BACKGROUND_DRAGON, ScanApp, _title_lines


def test_wordmark_fits_banner_and_lists_only_supported_targets() -> None:
    full = _title_lines("full")
    compact = _title_lines("compact")
    assert _title_lines("plain") == ("DRAGONSCAN",)
    assert len(full) == 5 and max(map(len, full)) + 4 <= 90
    assert len(compact) == 3 and max(map(len, compact)) + 4 <= 80
    assert "█" in full[0] and "█" in full[-1]


def test_braille_dragon_splash_adapts_without_clipping() -> None:
    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            art = app.query_one("#dragon-art", Static)
            panel = app.query_one("#splash-panel")
            if size == (120, 48):
                assert panel.has_class("large")
                assert BACKGROUND_DRAGON[0] in str(art.render())
                assert BACKGROUND_DRAGON[-1] in str(art.render())
            else:
                assert panel.has_class("compact")
                assert BACKGROUND_DRAGON[12] in str(art.render())
            assert panel.region.y >= 0
            assert panel.region.y + panel.region.height <= size[1]

    for size in ((80, 24), (120, 48)):
        asyncio.run(run(size))


def test_welcome_target_controls_are_visible_without_an_extra_step() -> None:
    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            await pilot.pause()
            assert app.stage == "target"
            assert app.focused is app.query_one("#mode")
            brand = app.query_one("#brand", Static)
            variant = (
                "full"
                if size[0] >= 90 and size[1] >= 26
                else "compact"
                if size[0] >= 52 and size[1] >= 20
                else "plain"
            )
            lines = _title_lines(variant)
            assert lines[0] in str(brand.render())
            assert lines[-1] in str(brand.render())
            assert brand.region.height == len(lines)
            assert brand.styles.text_align == "center"
            assert app.query_one("#banner").region.bottom <= app.query_one("#content").region.y
            assert app.query_one("#banner-meta").display == (size[0] >= 118 and size[1] >= 26)
            if size[0] >= 118 and size[1] >= 26:
                metadata = str(app.query_one("#banner-meta", Static).render())
                assert "VERSION" in metadata and "Static analysis" in metadata
                assert "Ready" in metadata
            assert "AI AGENT SCANNER" in str(app.query_one("#brand-caption", Static).render())
            assert not app.query("#welcome-logo")
            page = app.query_one("#target")
            intro = app.query_one("#welcome-intro")
            heading = app.query_one("#welcome-intro .welcome-heading", Static)
            section = app.query_one("#target .heading", Static)
            selector = app.query_one("#mode")
            assert intro.region.contains(heading.region.x, heading.region.y)
            assert intro.region.bottom <= section.region.y
            assert page.region.contains(selector.region.x, selector.region.y)
            assert selector.region.bottom <= app.query_one("#navigation").region.y
            assert page.region.width <= 90
            assert selector.region.width <= 90

    for size in (
        (60, 22),
        (68, 24),
        (80, 24),
        (82, 32),
        (90, 32),
        (120, 48),
        (154, 32),
        (160, 48),
        (300, 48),
    ):
        asyncio.run(run(size))


def test_navigation_keycaps_follow_stage_and_fit_terminal() -> None:
    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            await pilot.pause()
            navigation = app.query_one("#navigation", Static)

            def hints() -> Content:
                rendered = navigation.render()
                assert isinstance(rendered, Content)
                return rendered

            target = hints()
            assert "←/→" in target.plain and "Enter" in target.plain
            assert "Change target" in target.plain or "Target" in target.plain
            assert any(" on rgb(" in str(span.style) for span in target.spans)
            assert navigation.region.height == 3
            assert "[←/→]" in target.plain
            assert "[Enter]" in target.plain
            assert "⇄" in target.plain and "↵" in target.plain
            assert target.cell_length <= navigation.content_region.width
            assert "⇄" in app.export_screenshot()

            app._set_mode("path")
            app._toggle_target_detail()
            await pilot.pause()
            assert "Tab" in hints().plain
            assert "More options" not in hints().plain
            app._show_stage("scope")
            await pilot.pause()
            assert "Space" in hints().plain
            app._show_stage("confirm")
            await pilot.pause()
            assert "Start scan" in hints().plain
            app._show_stage("results")
            await pilot.pause()
            assert "Ctrl+E" in hints().plain
            assert all(
                Content(line).cell_length <= navigation.content_region.width
                for line in hints().plain.splitlines()
            )
            await pilot.resize_terminal(60, 24)
            await pilot.pause()
            assert navigation.region.height == 2
            assert all(
                Content(line).cell_length <= navigation.content_region.width
                for line in hints().plain.splitlines()
            )
            assert "Enter" in hints().plain

    for size in ((80, 24), (90, 36), (120, 48)):
        asyncio.run(run(size))


def test_target_cards_support_pointer_and_arrow_selection() -> None:
    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            await pilot.pause()
            choices = str(app.query_one("#mode", Static).render())
            for name in ("All known local agents", "One known agent", "Specific file / directory"):
                assert name in choices
            assert all(icon in choices for icon in ("▦", "◉", "▤"))
            assert " 01  " not in choices
            assert "Recently used" not in choices
            assert "System directory" not in choices
            await _click_target(pilot, 2)
            assert app.mode == "path"
            assert app.focused is app.query_one("#mode")
            assert "chosen local path" in str(app.query_one("#target-notice", Static).render())
            await pilot.press("up")
            assert app.mode == "agent"
            await _click_target(pilot, 0)
            assert app.mode == "all"
            assert "supported local agent locations" in str(
                app.query_one("#target-notice", Static).render()
            )
            assert app.query_one("#target-notice").display == (size[1] >= 28)

    for size in ((80, 24), (120, 48)):
        asyncio.run(run(size))


async def _click_target(pilot: Pilot[None], index: int) -> None:
    # Escape/focus can update scroll state before the compositor updates regions.
    # Pilot computes screen coordinates before its own pause: settle FIRST.
    await pilot.pause()
    await asyncio.wait_for(pilot.wait_for_scheduled_animations(), timeout=5)
    await pilot.pause()
    mode = pilot.app.query_one("#mode")
    mode.scroll_visible(animate=False)
    await pilot.pause()
    stride = 2 if pilot.app.size.height >= 32 else 1
    offset = (3, 1 + stride * index)
    hit, _ = pilot.app.get_widget_at(mode.region.x + offset[0], mode.region.y + offset[1])
    assert hit is mode, (mode.region, hit.id, pilot.app.size)
    assert await pilot.click(mode, offset=offset)


def test_target_details_reveal_fields_and_support_click_to_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Geometry/state only: never include user input or scanned content in traces.
    from dragonscan.tui import ModeChoice

    original = ModeChoice.on_click

    def trace(app: ScanApp, phase: str, offset: tuple[int, int]) -> None:
        mode = app.query_one("#mode")
        target = app.query_one("#target")
        print(
            "target-pointer",
            phase,
            tuple(app.size),
            offset,
            tuple(mode.region),
            target.scroll_y,
            target.scroll_target_y,
            app.mode,
            app.detail,
            app.focused.id if app.focused else None,
        )

    def clicked(widget: ModeChoice, event: events.Click) -> None:
        assert isinstance(widget.app, ScanApp)
        trace(widget.app, "delivered", (event.x, event.y))
        original(widget, event)
        trace(widget.app, "handled", (event.x, event.y))

    monkeypatch.setattr(ModeChoice, "on_click", clicked)

    async def click(pilot: Pilot[None], offset: tuple[int, int]) -> None:
        assert isinstance(pilot.app, ScanApp)
        trace(pilot.app, "requested", offset)
        stride = 2 if pilot.app.size.height >= 32 else 1
        await _click_target(pilot, (offset[1] - 1) // stride)

    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            await pilot.pause()
            stride = 2 if size[1] >= 32 else 1
            assert not app.query_one("#agent-detail").display
            assert not app.query_one("#path-detail").display
            await click(pilot, (3, 1 + stride))
            assert app.mode == "agent" and app.detail is None
            await click(pilot, (3, 1 + stride))
            await pilot.pause()
            agent = app.query_one("#agent", Select)
            assert app.detail == "agent" and app.focused is agent
            assert agent.region.y < app.query_one("#target").region.bottom
            assert not app.query_one("#path-detail").display
            await pilot.press("escape")
            assert app.detail is None and not app.query_one("#agent-detail").display
            await click(pilot, (3, 1 + stride * 2))
            await click(pilot, (3, 1 + stride * 2))
            await pilot.pause()
            path = app.query_one("#path", Input)
            assert app.detail == "path" and app.focused is path
            assert path.region.y < app.query_one("#target").region.bottom
            example = app.query_one("#path-detail .detail-example", Static)
            assert "./agent-directory/SKILL.md" in str(example.render())
            assert example.region.bottom <= app.query_one("#target").region.bottom
            await pilot.press("a")
            assert path.value == "a"
            assert example.region.bottom <= app.query_one("#target").region.bottom
            path.value = ""
            assert not app.query_one("#agent-detail").display
            assert isinstance(app.query_one("#path-next"), Button)
            app.query_one("#target").scroll_to_widget(app.query_one("#path-next"), animate=False)
            await pilot.pause()
            assert await pilot.click("#path-next")
            assert app.stage == "target"
            assert "Enter a file" in str(app.query_one("#status", Static).render())
            path.value = str(tmp_path)
            await pilot.pause(0.3)
            assert await pilot.click("#path-next")
            await pilot.pause()
            assert app.stage == "scope"

    for size in ((80, 24), (120, 48)):
        asyncio.run(run(size))


def test_target_pointer_waits_for_pending_layout_and_repeated_navigation() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._end_splash()
            for size in ((80, 24), (120, 48), (60, 22), (80, 24)):
                await pilot.resize_terminal(*size)
                await _click_target(pilot, 1)
                await pilot.press("enter")
                await _settle_results(pilot)
                assert app.detail == "agent"
                assert app.focused is app.query_one("#agent")
                mode = app.query_one("#mode")
                before = mode.region
                # Deliberately leave a real layout pending, as the native Escape
                # trace did. No sleep, renderer mock, or disabled animation.
                app.action_back_stage()
                assert app.detail is None
                await _click_target(pilot, 2)
                assert app.mode == "path" and app.detail is None
                assert app.focused is mode
                if size[1] < 32:
                    assert mode.region.y != before.y
                await _click_target(pilot, 2)
                await _settle_results(pilot)
                assert app.detail == "path"
                assert app.focused is app.query_one("#path")
                await pilot.press("escape")
                await _settle_results(pilot)
                assert app.detail is None and app.focused is mode
                await pilot.press("up", "enter")
                await _settle_results(pilot)
                assert app.mode == "agent" and app.detail == "agent"
                await pilot.press("escape", "left")
                assert app.mode == "all" and app.detail is None

    asyncio.run(run())


def test_title_reflows_on_resize_without_losing_target_focus() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(160, 48)) as pilot:
            app._end_splash()
            for size, variant in (
                ((60, 22), "compact"),
                ((80, 24), "compact"),
                ((120, 48), "full"),
                ((160, 48), "full"),
            ):
                await pilot.resize_terminal(*size)
                await pilot.pause()
                brand = app.query_one("#brand", Static)
                assert brand.region.height == len(_title_lines(variant))
                assert _title_lines(variant)[0] in str(brand.render())
                assert app.focused is app.query_one("#mode")
                assert app.query_one("#mode").region.bottom <= app.query_one("#navigation").region.y

    asyncio.run(run())


def test_braille_side_art_keeps_controls_full_width_when_narrow(tmp_path: Path) -> None:
    async def run(size: tuple[int, int]) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            for stage in ("target", "scope", "confirm", "results"):
                app._show_stage(stage)
                await pilot.pause()
                art = app.query_one("#watermark", Static)
                page = app.query_one(f"#{stage}")
                if size == (120, 48) and stage != "results":
                    assert art.display
                    assert "⣿" in str(art.render())
                    assert art.region.width == 37
                    assert page.region.width >= 70
                else:
                    assert not art.display
                    assert page.region.width >= 70
            report = ScanReport(tmp_path, (), ())
            app._finish(report, evaluate(report), None)
            await pilot.pause()
            assert not app.query_one("#watermark", Static).display
            if size == (120, 48):
                await pilot.resize_terminal(80, 24)
                await pilot.pause()
                assert not app.query_one("#watermark", Static).display
                assert app.query_one("#results").region.width >= 70

    for size in ((80, 24), (120, 48)):
        asyncio.run(run(size))


def test_keyboard_flow_and_native_input_keys(tmp_path: Path) -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.press("space")
            assert app.stage == "target"
            assert app.focused is app.query_one("#mode", Static)
            await pilot.press("right")
            assert app.mode == "agent"
            await pilot.press("right")
            assert app.mode == "path"
            assert "Specific file / directory" in str(app.query_one("#mode", Static).render())
            await pilot.press("enter")
            assert app.detail == "path" and app.stage == "target"
            assert app.focused is app.query_one("#path", Input)
            assert app.query_one("#path-detail").display
            assert "Examples:" in str(
                app.query_one("#path-detail .detail-example", Static).render()
            )
            await pilot.press("enter")
            assert "Enter a file" in str(app.query_one("#status", Static).render())
            await pilot.press("q")
            assert app.stage == "target"
            assert app.query_one("#path", Input).value == "q"
            app.query_one("#path", Input).value = str(tmp_path)
            await pilot.press("left")
            assert app.mode == "path"
            await pilot.press("enter")
            assert app.stage == "scope"
            assert app.focused is app.query_one("#kinds", SelectionList)
            await pilot.press("tab")
            assert app.focused is app.query_one("#artifacts", Input)
            await pilot.press("shift+tab")
            assert app.focused is app.query_one("#kinds", SelectionList)
            before = set(app.query_one("#kinds", SelectionList).selected)
            await pilot.press("space")
            assert set(app.query_one("#kinds", SelectionList).selected) != before
            await pilot.press("escape")
            assert app.stage == "target"
            assert app.focused is app.query_one("#mode", Static)
            await pilot.press("left")
            assert app.mode == "agent"
            await pilot.press("escape")
            assert app.stage == "target"
            assert app.focused is app.query_one("#mode", Static)

    asyncio.run(run())


def test_ctrl_c_copies_selected_text_to_macos_clipboard(monkeypatch: pytest.MonkeyPatch) -> None:
    copied: list[str] = []
    commands: list[tuple[tuple[str, ...], str]] = []
    monkeypatch.setattr("dragonscan.tui.sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(
        "dragonscan.tui.subprocess",
        SimpleNamespace(
            run=lambda command, **kwargs: commands.append((command, kwargs["input"])),
            CalledProcessError=subprocess.CalledProcessError,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(App, "copy_to_clipboard", lambda self, text: copied.append(text))

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            app._end_splash()
            monkeypatch.setattr(app.screen, "get_selected_text", lambda: "selected text")
            await pilot.press("ctrl+c")
            assert copied == ["selected text"]
            assert commands == [(("pbcopy",), "selected text")]
            monkeypatch.setattr(app.screen, "get_selected_text", lambda: None)
            await pilot.press("ctrl+c")
            assert copied == ["selected text"]
            assert len(commands) == 1
            assert app.stage == "target"

    asyncio.run(run())


def test_copy_falls_back_when_native_clipboard_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied: list[str] = []
    monkeypatch.setattr(App, "copy_to_clipboard", lambda self, text: copied.append(text))
    monkeypatch.setattr("dragonscan.tui.sys", SimpleNamespace(platform="darwin"))

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("clipboard unavailable")

    monkeypatch.setattr("dragonscan.tui.subprocess.run", unavailable)

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            app.copy_to_clipboard("sample")
            await pilot.pause()
            assert copied == ["sample"]

    asyncio.run(run())


def test_copy_uses_terminal_clipboard_on_other_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    copied: list[str] = []
    monkeypatch.setattr(App, "copy_to_clipboard", lambda self, text: copied.append(text))
    monkeypatch.setattr("dragonscan.tui.sys", SimpleNamespace(platform="linux"))
    app = ScanApp()
    app.copy_to_clipboard("sample")
    assert copied == ["sample"]


def test_agent_selector_keeps_native_keyboard_selection() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            app._end_splash()
            await pilot.press("right", "enter")
            assert app.focused is app.query_one("#agent", Select)
            assert app.query_one("#agent-detail").display
            await pilot.press("enter")
            assert app.stage == "target"
            assert app.query_one("#agent", Select).expanded
            await pilot.press("escape")
            assert app.stage == "target"
            assert not app.query_one("#agent", Select).expanded
            await pilot.press("enter", "down", "enter")
            assert app.stage == "target"
            assert not app.query_one("#agent", Select).expanded
            await pilot.press("tab", "enter")
            assert app.stage == "scope"

    asyncio.run(run())


def test_agent_mode_opens_and_chooses_from_keyboard() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._end_splash()
            await pilot.press("down")
            assert app.mode == "agent" and app.focused is app.query_one("#mode")
            await pilot.press("enter")
            assert app.stage == "target" and app.detail == "agent"
            selector = app.query_one("#agent", Select)
            assert app.focused is selector and not selector.expanded
            await pilot.press("enter")
            assert selector.expanded
            initial = selector.value
            await pilot.press("down", "enter")
            assert not selector.expanded and selector.value != initial
            await pilot.press("tab", "enter")
            assert app.stage == "scope"
            await pilot.press("enter")
            assert f"Target: {selector.value}" in str(app.query_one("#review", Static).render())

    asyncio.run(run())


def test_agent_menu_can_keep_initial_choice_or_cancel() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._end_splash()
            await pilot.press("right", "enter", "enter")
            selector = app.query_one("#agent", Select)
            initial = selector.value
            assert selector.expanded
            await pilot.press("escape")
            assert app.stage == "target" and app.detail == "agent"
            assert not selector.expanded and selector.value == initial
            await pilot.press("escape")
            assert app.detail is None and app.focused is app.query_one("#mode")
            assert not app.query_one("#agent-detail").display
            await pilot.press("enter", "enter", "enter")
            assert selector.value == initial
            await pilot.press("tab", "enter")
            assert app.stage == "scope"

    asyncio.run(run())


def test_form_inputs_have_readable_placeholders_and_clean_focus_borders() -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._end_splash()
            await pilot.press("right", "right", "enter")
            path = app.query_one("#path", Input)
            assert path.styles.border.top[0] == "solid"
            assert path.get_component_styles("input--placeholder").color.rgb == (216, 195, 165)
            await pilot.press("escape", "left", "enter", "tab", "enter")
            assert app.stage == "scope"
            for name in ("entries", "artifacts", "per-root", "depth"):
                field = app.query_one(f"#{name}", Input)
                assert field.styles.border.top[0] == "solid"
                assert field.get_component_styles("input--placeholder").color.rgb == (216, 195, 165)
                assert app.query_one(f"#{name}-label", Static).display
            assert app.query_one("#agent SelectCurrent").styles.border.top[0] == "solid"

    asyncio.run(run())


def test_confirm_screen_marks_explicit_scan_start_and_cannot_start_on_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run(size: tuple[int, int], use_mouse: bool) -> None:
        app = ScanApp()
        calls: list[tuple[object, ...]] = []
        monkeypatch.setattr(app, "_scan", lambda *args: calls.append(args))
        async with app.run_test(size=size) as pilot:
            app._end_splash()
            await pilot.press("enter", "enter")
            assert app.stage == "confirm" and not calls
            await pilot.pause()
            button = app.query_one("#start-scan", Button)
            assert button.display and app.focused is button
            assert button.region.bottom <= app.query_one("#confirm").region.bottom
            assert "Start local scan" in str(button.label)
            assert "Press Enter" in str(app.query_one("#scan-instruction", Static).render())
            await pilot.press("escape")
            assert app.stage == "scope" and not calls
            await pilot.press("enter")
            if use_mouse:
                await pilot.click("#start-scan")
            else:
                await pilot.press("enter")
            await pilot.pause()
            assert len(calls) == 1 and app.scanning
            assert not app.query_one("#scan-action").display
            assert "Scanning" in str(app.query_one("#navigation", Static).render())

    asyncio.run(run((80, 24), False))
    asyncio.run(run((120, 48), True))


@pytest.mark.parametrize("size", [(80, 24), (120, 48)])
@pytest.mark.parametrize(
    ("stage", "callback_name", "removed_widget"),
    [
        ("splash", "_tick", "#splash-progress"),
        ("confirm", "_tick", "#activity"),
        ("splash", "_end_splash", "#banner-meta"),
    ],
)
def test_timer_callbacks_stop_before_widgets_are_removed_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    size: tuple[int, int],
    stage: str,
    callback_name: str,
    removed_widget: str,
) -> None:
    async def run() -> None:
        app = ScanApp()
        close_all = app._close_all
        callback = getattr(app, callback_name)
        shutdown_checked = False

        async def close_with_pending_timer() -> None:
            nonlocal shutdown_checked
            try:
                # Exercise Textual's real shutdown boundary, without a timing race.
                assert not app.is_running
                await app.query_one(removed_widget).remove()
                frame = app._frame
                callback()
                assert app._frame == frame
                assert app.stage == stage
                shutdown_checked = True
            finally:
                await close_all()

        async with app.run_test(size=size):
            assert app.is_running
            app._show_stage(stage)
            app.scanning = stage == "confirm"
            frame = app._frame
            callback()
            if callback_name == "_tick":
                assert app._frame == (frame + 1) % 4
                assert str(app.query_one(removed_widget, Static).render())
            else:
                assert app.stage == "target"
                app._show_stage(stage)
            monkeypatch.setattr(app, "_close_all", close_with_pending_timer)
        assert shutdown_checked

    asyncio.run(run())


def test_scope_navigation_and_review_match_selected_mode(tmp_path: Path) -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._end_splash()
            await pilot.press("enter")
            assert app.stage == "scope"
            assert "Space  toggle" not in str(app.query_one("#navigation", Static).render())
            assert app.focused is app.query_one("#entries", Input)
            for field in ("artifacts", "per-root", "depth"):
                await pilot.press("tab")
                assert app.focused is app.query_one(f"#{field}", Input)
            await pilot.press("enter")
            assert app.stage == "confirm"
            review = str(app.query_one("#review", Static).render())
            assert "Limits: Defaults" in review
            assert "Unselected groups" not in review
            await pilot.press("escape", "escape")
            assert app.stage == "target"
            await pilot.press("right", "right", "enter")
            app.query_one("#path", Input).value = str(tmp_path)
            await pilot.press("enter")
            assert app.stage == "scope"
            app.query_one("#kinds", SelectionList).deselect("mcp")
            await pilot.press("enter")
            review = str(app.query_one("#review", Static).render())
            assert "Excluded file groups: mcp" in review
            assert "depth limit" not in review

    asyncio.run(run())


def test_results_focus_and_empty_report_are_explained(tmp_path: Path) -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            report = ScanReport(tmp_path, (), ())
            app._finish(report, evaluate(report), None)
            await pilot.pause()
            assert app.stage == "results"
            assert app.focused is app.query_one("#export-format", Select)
            assert "No findings" in str(app.query_one(".empty-results", Static).render())
            await pilot.press("ctrl+r")
            assert app.stage == "target"
            assert app.focused is app.query_one("#mode", Static)

    asyncio.run(run())


def test_results_keep_coverage_visible_for_complete_partial_and_failed_scans(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            complete = ScanReport(tmp_path, (), ())
            app._finish(complete, evaluate(complete), None)
            await pilot.pause()
            assert "COMPLETE" in str(app.query_one("#coverage", Static).render())
            assert "selected scope" in str(app.query_one("#coverage", Static).render())
            assert not app.query_one("#coverage", Static).has_class("failed")
            assert not app.query_one("#coverage", Static).has_class("partial")
            assert "No findings in analyzed content." in str(
                app.query_one(".empty-results", Static).render()
            )

            partial = ScanReport(
                tmp_path, (), (), diagnostics=(Diagnostic("coverage", "Depth limited"),)
            )
            app._finish(partial, evaluate(partial), None)
            await pilot.pause()
            assert "PARTIAL" in str(app.query_one("#coverage", Static).render())
            assert app.query_one("#coverage", Static).has_class("partial")
            assert "Review coverage and diagnostics" in str(
                app.query_one("#coverage", Static).render()
            )
            assert "coverage is PARTIAL" in str(app.query_one(".empty-results", Static).render())
            coverage_y = app.query_one("#coverage", Static).region.y
            app.set_focus(app.query_one("#export-path", Input))
            await pilot.pause()
            assert app.query_one("#coverage", Static).region.y == coverage_y
            app.query_one("#export-path", Input).value = str(tmp_path / "partial.json")
            app._export()
            assert "Saved:" in str(app.query_one("#status", Static).render())
            assert "PARTIAL" in str(app.query_one("#coverage", Static).render())

            failed = ScanReport(tmp_path, (), (), errors=("Could not load a file",))
            app._finish(failed, evaluate(failed), None)
            await pilot.pause()
            assert "FAILED" in str(app.query_one("#coverage", Static).render())
            assert app.query_one("#coverage", Static).has_class("failed")
            assert not app.query_one("#coverage", Static).has_class("partial")
            assert "coverage is FAILED" in str(app.query_one(".empty-results", Static).render())

    asyncio.run(run())


def test_results_severity_breakdown_uses_actual_findings(tmp_path: Path) -> None:
    finding = Finding(
        detection_id="TEST-001",
        category="test",
        title="Test finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        classification=Classification.SUSPICIOUS,
        artifact=tmp_path / "SKILL.md",
        explanation="Test explanation",
        evidence="Test evidence",
        remediation="Test remediation",
        detector="test",
    )

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            report = ScanReport(tmp_path, (), (finding, finding))
            app._finish(report, evaluate(report), None)
            await pilot.pause()
            summary = str(app.query_one("#summary", Static).render())
            assert "Findings: 2" in summary
            assert "HIGH 2" in summary
            assert "NONE" not in summary
            assert "COMPLETE" in str(app.query_one("#coverage", Static).render())

    asyncio.run(run())


async def _settle_results(pilot: Pilot[None]) -> None:
    # pause() drains messages, but not focus-triggered ancestor scroll animations.
    # Pilot snapshots mouse coordinates BEFORE its own pause; wait before targeting.
    await pilot.pause()
    await asyncio.wait_for(pilot.wait_for_scheduled_animations(), timeout=5)
    await pilot.pause()


async def _result_node_offset(pilot: Pilot[None], tree: Tree, node: TreeNode) -> tuple[int, int]:
    await _settle_results(pilot)
    tree.scroll_to_node(node, animate=False)
    await _settle_results(pilot)
    x = tree.content_region.x + 2
    y = tree.content_region.y + node.line - tree.scroll_offset.y
    hit, _ = pilot.app.get_widget_at(x, y)
    meta = pilot.app.screen.get_style_at(x, y).meta
    parent = pilot.app.query_one("#results-content")
    # Bounded geometry-only evidence if a native CI renderer targets a different row.
    trace = {
        "tree_region": tree.region,
        "content_region": tree.content_region,
        "scroll": tree.scroll_offset,
        "parent_scroll": parent.scroll_y,
        "parent_target": parent.scroll_target_y,
        "cursor_line": tree.cursor_line,
        "wanted_line": node.line,
        "point": (x, y),
        "hit_id": hit.id,
        "hit_line": meta.get("line"),
        "focused_id": pilot.app.focused.id if pilot.app.focused else None,
    }
    assert node.line >= 0 and hit is tree, trace
    assert tree.get_node_at_line(meta.get("line", -1)) is node, trace
    return x - tree.region.x, y - tree.region.y


@pytest.mark.parametrize("long_target", (False, True))
@pytest.mark.parametrize("size", ((80, 24), (120, 48)))
def test_results_tree_groups_shared_artifacts_and_updates_detail_on_selection(
    tmp_path: Path,
    long_target: bool,
    size: tuple[int, int],
) -> None:
    if long_target:
        tmp_path = tmp_path / ("nested-target-" * 20)
    shared = tmp_path / "shared" / "SKILL.md"
    local = tmp_path / "local" / "AGENTS.md"
    artifacts = tuple(
        Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN) for path in (shared, local)
    )
    findings = tuple(
        Finding(
            detection_id=identifier,
            category="test",
            title=title,
            severity=severity,
            confidence=confidence,
            classification=Classification.SUSPICIOUS,
            artifact=path,
            explanation="Why this matters",
            evidence="Evidence from the artifact",
            remediation="Review this file",
            detector="test",
            line=7,
        )
        for identifier, title, severity, confidence, path in (
            ("DRAGON-001", "Critical issue", Severity.CRITICAL, Confidence.HIGH, shared),
            ("DRAGON-002", "Low issue", Severity.LOW, Confidence.MEDIUM, shared),
            ("DRAGON-003", "Local issue", Severity.HIGH, Confidence.LOW, local),
        )
    )
    report = ScanReport(
        tmp_path,
        artifacts,
        findings,
        artifact_origins=(
            ArtifactOrigin(shared, "installed_agent", "Agent1", tmp_path, scanned_artifact=shared),
            ArtifactOrigin(shared, "installed_agent", "Agent2", tmp_path, scanned_artifact=shared),
            ArtifactOrigin(local, "explicit_target", scanned_artifact=local),
        ),
    )

    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            app._finish(report, evaluate(report), None)
            await _settle_results(pilot)
            tree = app.query_one("#findings-tree", Tree)
            assert [str(node.label) for node in tree.root.children] == [
                "Agent1",
                "Agent2",
                "Local target",
            ]
            assert app.focused is tree
            agent = tree.root.children[0]
            agent.expand()
            assert [str(node.label).split("  ")[0] for node in agent.children[:2]] == [
                "Critical",
                "Low",
            ]
            assert any("Scanned paths" in str(child.label) for child in agent.children)
            critical = agent.children[0]
            critical.expand()
            leaf = critical.children[0]
            assert "DRAGON-001" in str(leaf.label)
            # Expanded nodes get their visible line numbers during the next render.
            await _settle_results(pilot)
            tree.select_node(leaf)
            await _settle_results(pilot)
            assert tree.cursor_node is leaf
            detail = str(app.query_one("#finding-content", Static).render())
            assert all(
                phrase in detail
                for phrase in ("DRAGON-001", "CONFIDENCE", "High", "EVIDENCE", "Why this matters")
            ), detail
            assert str(shared) in detail
            assert await pilot.hover(tree, offset=await _result_node_offset(pilot, tree, agent))
            await _settle_results(pilot)
            assert str(app.query_one("#finding-content", Static).render()).startswith("Agent1")
            assert tree.cursor_node is leaf  # Hover previews without changing selection.
            assert await pilot.click(tree, offset=await _result_node_offset(pilot, tree, agent))
            await _settle_results(pilot)
            assert not agent.is_expanded
            assert await pilot.click(tree, offset=await _result_node_offset(pilot, tree, agent))
            await _settle_results(pilot)
            assert agent.is_expanded
            tree.move_cursor(leaf)
            await pilot.pause()
            assert "DRAGON-001" in str(app.query_one("#finding-content", Static).render())
            other = tree.root.children[1]
            other.expand()
            assert "DRAGON-001" in str(other.children[0].children[0].label)
            assert any("Scanned paths" in str(child.label) for child in other.children)
            local_group = tree.root.children[2]
            local_group.expand()
            assert "DRAGON-003" in str(local_group.children[0].children[0].label)
            assert app.query_one("#results-layout").region.width > 0
            assert app.query_one("#finding-pane").region.bottom <= app.query_one("#status").region.y
            if size == (80, 24):
                assert str(app.query_one("#brand", Static).render()) == "DRAGONSCAN"
            else:
                await pilot.resize_terminal(80, 24)
                await pilot.pause()
                assert app.query_one("#results-layout").has_class("stacked")
                assert "CONFIDENCE" in str(app.query_one("#finding-content", Static).render())

    asyncio.run(run())


@pytest.mark.parametrize("size", ((80, 24), (120, 48)))
def test_results_hover_keyboard_focus_scroll_resize_and_reentry(
    tmp_path: Path, size: tuple[int, int]
) -> None:
    path = tmp_path / "SKILL.md"  # Metadata only: never read or execute an artifact.
    finding = Finding(
        detection_id="DRAGON-001",
        category="test",
        title="Inert interaction fixture",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        classification=Classification.SUSPICIOUS,
        artifact=path,
        explanation="Test explanation",
        evidence="Test evidence",
        remediation="Test remediation",
        detector="test",
    )

    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            for entry in range(2):
                report = ScanReport(
                    tmp_path,
                    (Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN),),
                    (finding,),
                    artifact_origins=tuple(
                        ArtifactOrigin(
                            path,
                            "installed_agent",
                            f"Run{entry}-Agent{i}",
                            tmp_path,
                            scanned_artifact=path,
                        )
                        for i in range(12)
                    ),
                )
                app._finish(report, evaluate(report), None)
                await _settle_results(pilot)
                tree = app.query_one("#findings-tree", Tree)
                agent = tree.root.children[-1]
                agent.expand_all()
                await _settle_results(pilot)
                severity = agent.children[0]
                leaf = severity.children[0]
                tree.move_cursor(leaf)
                await _settle_results(pilot)
                assert tree.scroll_y > 0
                assert tree.cursor_node is leaf
                assert "DRAGON-001" in str(app.query_one("#finding-content", Static).render())

                # Real keyboard events, followed by hover, must not change the cursor.
                await pilot.press("up")
                await _settle_results(pilot)
                assert tree.cursor_node is severity
                assert str(app.query_one("#finding-content", Static).render()).startswith(
                    "Critical"
                )
                selector = app.query_one("#export-format", Select)
                app.set_focus(selector, scroll_visible=False)
                offset = await _result_node_offset(pilot, tree, leaf)
                assert await pilot.hover(tree, offset=offset)
                await _settle_results(pilot)
                assert app.focused is selector
                assert tree.cursor_node is severity
                assert "DRAGON-001" in str(app.query_one("#finding-content", Static).render())
                app.set_focus(tree, scroll_visible=False)
                await pilot.press("down")
                await _settle_results(pilot)
                assert tree.cursor_node is leaf

                # Resize in both directions, then target a scrolled, rendered row.
                resized = (120, 48) if app.size.width == 80 else (80, 24)
                await pilot.resize_terminal(*resized)
                offset = await _result_node_offset(pilot, tree, agent)
                assert await pilot.hover(tree, offset=offset)
                await _settle_results(pilot)
                assert str(app.query_one("#finding-content", Static).render()).startswith(
                    f"Run{entry}-Agent"
                )
                assert tree.cursor_node is leaf

                # Exercise the original race explicitly: pointer targeting must wait for
                # a real scheduled ancestor scroll, not merely an idle message queue.
                if app.size.width == 80:
                    parent = app.query_one("#results-content")
                    assert parent.max_scroll_y >= 2
                    parent.scroll_to(y=0, animate=False, immediate=True)
                    await _settle_results(pilot)
                    completed = asyncio.Event()
                    parent.scroll_to(y=2, on_complete=completed.set)
                    assert not completed.is_set()
                    offset = await _result_node_offset(pilot, tree, agent)
                    assert completed.is_set()
                    assert parent.scroll_y == parent.scroll_target_y
                    assert await pilot.hover(tree, offset=offset)
                    await _settle_results(pilot)
                    assert str(app.query_one("#finding-content", Static).render()).startswith(
                        f"Run{entry}-Agent"
                    )

                await pilot.press("ctrl+r")
                await _settle_results(pilot)
                assert app.stage == "target"

    asyncio.run(run())


def test_results_tree_keeps_agent_paths_without_findings_and_diagnostics(tmp_path: Path) -> None:
    path = tmp_path / "quiet" / "SKILL.md"
    report = ScanReport(
        tmp_path,
        (Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN),),
        (),
        artifact_origins=(
            ArtifactOrigin(path, "installed_agent", "Agent3", tmp_path, scanned_artifact=path),
        ),
        diagnostics=(Diagnostic("coverage", "Partial inspection"),),
    )

    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app._finish(report, evaluate(report), None)
            await pilot.pause()
            tree = app.query_one("#findings-tree", Tree)
            agent = tree.root.children[0]
            agent.expand()
            assert str(agent.label) == "Agent3"
            assert any("Scanned paths" in str(node.label) for node in agent.children)
            assert "No findings" in str(app.query_one(".empty-results", Static).render())
            assert any("Coverage and diagnostics" in str(node.label) for node in tree.root.children)

    asyncio.run(run())


def test_splash_dragon_is_visible_and_contained() -> None:
    async def run(size: tuple[int, int], compact: bool) -> None:
        app = ScanApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            panel = app.query_one("#splash-panel")
            logo = app.query_one("#splash-art", Static)
            dragon = app.query_one("#dragon-art", Static)
            assert panel.region.y >= 0
            assert panel.region.y + panel.region.height <= size[1]
            assert abs((panel.region.x + panel.region.width / 2) - size[0] / 2) <= 1
            assert dragon.display and dragon.region.height >= (
                size[1] - 12 if compact else len(BACKGROUND_DRAGON)
            )
            assert logo.region.y < dragon.region.y
            assert dragon.region.y + dragon.region.height <= panel.region.y + panel.region.height
            assert dragon.region.width >= max(map(len, BACKGROUND_DRAGON))

    asyncio.run(run((80, 24), True))
    asyncio.run(run((160, 48), False))
