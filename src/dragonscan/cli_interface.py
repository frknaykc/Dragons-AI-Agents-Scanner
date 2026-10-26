"""Line-oriented, local-only target selection for interactive terminals."""

import click

from dragonscan.installed_agents import SPECS


def choose_target(*, color: bool) -> tuple[str | None, bool, str | None] | None:
    """Return a confirmed target, or None if the operator cancels."""
    click.echo(
        click.style("╭─ DRAGONSCAN  /  AI AGENT SCANNER", fg="bright_yellow", bold=True),
        color=color,
    )
    click.echo(click.style("│  LOCAL  ·  STATIC  ·  NOTHING EXECUTED", fg="yellow"), color=color)
    click.echo(click.style("╰─ Choose a scan target", fg="bright_yellow"), color=color)
    for number, icon, label, detail in (
        (1, "▦", "All known local agents", "Known user-level roots"),
        (2, "◉", "One known agent", "Select a supported agent"),
        (3, "▤", "Specific file / directory", "Local path only"),
    ):
        key = click.style(f"[{number}]", fg="bright_white", bold=True)
        symbol = click.style(icon, fg="bright_yellow", bold=True)
        hint = click.style(detail, fg="yellow")
        click.echo(f"  {key}  {symbol}  {label}  ·  {hint}", color=color)
    choice = click.prompt("Target", type=click.Choice(["1", "2", "3"]), show_choices=False)
    path: str | None = None
    agent: str | None = None
    if choice == "2":
        click.echo("\n  Select an agent:", color=color)
        for index, spec in enumerate(SPECS, 1):
            click.echo(f"  [{index}]  ◉  {spec.kind}", color=color)
        selected = click.prompt(
            "Agent",
            type=click.Choice([str(n) for n in range(1, len(SPECS) + 1)]),
            show_choices=False,
        )
        agent = SPECS[int(selected) - 1].kind
    elif choice == "3":
        while path is None:
            entered = click.prompt("Local file or directory")
            if entered.strip():
                path = entered
            else:
                click.echo("Enter a local path.", err=True)

    target = "Known local agents" if choice == "1" else agent if choice == "2" else ascii(path)
    click.echo(click.style("\n╭─ READY TO SCAN", fg="bright_yellow", bold=True), color=color)
    click.echo(f"│  Target  {target}", color=color)
    click.echo(click.style("╰─ Static scan; no target code is executed", fg="yellow"), color=color)
    if not click.confirm("Start local scan?", default=False):
        click.echo("Scan cancelled.")
        return None
    return path, choice != "3", agent
