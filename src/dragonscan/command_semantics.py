"""Bounded static interpretation of supported command forms; never execute input."""

import base64
import binascii
import re
import shlex
from dataclasses import dataclass

_PYTHON_STDIN = re.compile(r"python(?:3(?:\.\d+)?)?\Z")
_SHELL_WRAPPER = re.compile(
    r"(?:sh|bash|zsh)\s+-(?:c|lc|cl)\s+(?P<quote>['\"])(?P<body>[^\n]{1,500})(?P=quote)\Z"
)


def shell_command_string(args: tuple[str, ...]) -> str | None:
    """Select code only from supported POSIX shell command-string invocations.

    Accept -c/-lc/-cl, optionally after a separate -l. Never search past
    operands, -- or unsupported prefixes. Later arguments are positional data.
    """
    index = 1 if args[:1] == ("-l",) else 0
    if len(args) <= index + 1 or args[index] not in {"-c", "-lc", "-cl"}:
        return None
    return args[index + 1]


POWERSHELL = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
POSIX_SHELL = frozenset({"sh", "bash", "zsh"})


@dataclass(frozen=True)
class ShellCommand:
    text: str
    encoded: bool = False


def selected_command(runtime: str, args: tuple[str, ...]) -> ShellCommand | None:
    """Select actual code by the runtime's argv contract, not by looking for flags."""
    if runtime in POSIX_SHELL:
        text = shell_command_string(args)
        return None if text is None else ShellCommand(text)
    if runtime in {"cmd", "cmd.exe"}:
        return (
            ShellCommand(" ".join(args[1:])) if len(args) > 1 and args[0].lower() == "/c" else None
        )
    if runtime not in POWERSHELL:
        return None
    index = 0
    while index < len(args) and args[index].lower() in {"-noprofile", "-noninteractive", "-nologo"}:
        index += 1
    if len(args) < index + 2:
        return None
    flag = args[index].lower()
    if flag in {"-c", "-command"}:
        return ShellCommand(" ".join(args[index + 1 :]))
    if (
        flag in {"-enc", "-encodedcommand", "-en", "-e"}
        and len(args) == index + 2
        and args[-1].strip()
    ):
        return ShellCommand(args[-1], encoded=True)
    return None


def has_control(text: str, runtime: str) -> bool:
    """Ignore literal operators inside quoted operands; never expand shell words."""
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif (
            char == ("`" if runtime in POWERSHELL else "^" if runtime.startswith("cmd") else "\\")
            and quote != "'"
        ):
            escaped = True
        elif quote and char == quote:
            quote = ""
        elif not quote and char in ('"' if runtime.startswith("cmd") else "'\""):
            quote = char
        elif not quote and (char == "|" or text.startswith("&&", index)):
            return True
        elif (
            quote != "'"
            and not runtime.startswith("cmd")
            and (text.startswith("$(", index) or (runtime in POSIX_SHELL and char == "`"))
        ):
            return True
    return False


# Narrow PowerShell grammar: match an entire literal command, not a substring.
_PS_URI = r"""(?:https?://[\w.-]+(?::\d+)?(?:/[\w./%-]*)?)"""
_PS_ARG = rf'''(?:'{_PS_URI}'|"{_PS_URI}"|{_PS_URI})'''
_PS_REST = rf"(?:Invoke-RestMethod|irm)\s+(?:-Uri\s+)?{_PS_ARG}"
_PS_WEB = rf"(?:Invoke-WebRequest|iwr)\s+(?:-Uri\s+)?{_PS_ARG}"
_PS_CONTENT = rf"(?:{_PS_REST}|\(\s*{_PS_WEB}\s*\)\.Content)"
_PS_SINK = r"(?:Invoke-Expression|iex)"
_PS_FLOW = re.compile(
    rf"(?:{_PS_CONTENT}\s*\|\s*{_PS_SINK}|{_PS_SINK}\s+\(\s*{_PS_CONTENT}\s*\))", re.I
)
_PS_PATH = r"\.[/\\][\w.-]+\.ps1"
_PS_WRITE_RUN = re.compile(
    rf"""{_PS_WEB}\s+-OutFile\s+(?P<q>['"]?)(?P<path>{_PS_PATH})(?P=q)"""
    rf"""[ \t]*(?:;|\n)\s*&\s+(?P<q2>['"]?)(?P<run>{_PS_PATH})(?P=q2)""",
    re.I,
)


def powershell_remote_execution(text: str) -> bool:
    if len(text) > 2000:
        return False
    text = text.strip()
    if _PS_FLOW.fullmatch(text):
        return True
    match = _PS_WRITE_RUN.fullmatch(text)
    return match is not None and match["path"] == match["run"]


def selected_powershell_execution(command: ShellCommand) -> bool:
    """A literal flag alone is not a relation. Decode at most one bounded UTF-16LE operand."""
    if not command.encoded:
        return powershell_remote_execution(command.text)
    # A 2000-code-unit command fits in at most 5336 base64 characters.
    if len(command.text) > 5336:
        return False
    try:
        text = base64.b64decode(command.text, validate=True).decode("utf-16le")
    except (ValueError, UnicodeError):
        return False
    return powershell_remote_execution(text)


def explicit_powershell_execution(command: str) -> bool:
    """Prose names the interpreter; require its command body as one quoted argument."""
    if len(command) > 2200:
        return False
    match = re.fullmatch(
        r"""((?:pwsh|powershell)(?:\.exe)?(?:\s+-[\w]+)+)\s+(['"])(.+)\2""", command, re.I
    )
    if not match or match[2] in match[3]:
        return False
    runtime, *prefix = match[1].lower().split()
    selected = selected_command(runtime, (*prefix, match[3]))
    return bool(selected and selected_powershell_execution(selected))


def remote_python_pipeline(command: str) -> bool:
    """Recognize a literal HTTP fetch whose stdout is Python's program input."""
    return _remote_stdin_pipeline(command, shell=False)


def remote_shell_pipeline(command: str) -> bool:
    """Recognize a literal HTTP fetch whose stdout is the shell's program input."""
    return _remote_stdin_pipeline(command, shell=True)


def _remote_stdin_pipeline(command: str, *, shell: bool) -> bool:
    """Require a literal stdout fetch and an interpreter that consumes program stdin."""
    command = command.strip()
    wrapper = _SHELL_WRAPPER.fullmatch(command)
    if wrapper is not None:
        command = wrapper["body"]
        if wrapper["quote"] in command:
            return False
    if len(command) > 500 or command.count("|") != 1:
        return False
    if any(char in command for char in "$`;&<>()\\\n"):
        return False
    fetch_text, interpreter_text = command.split("|")
    try:
        fetch = shlex.split(fetch_text)
        interpreter = shlex.split(interpreter_text)
    except ValueError:
        return False
    if not fetch or not interpreter:
        return False
    expected = "shell execution" if shell else "Python interpreter execution"
    if stdin_interpreter(interpreter) != expected:
        return False
    args = fetch[1:]
    urls = [arg for arg in args if re.fullmatch(r"https?://[^/\s]+(?:/\S*)?", arg)]
    if len(urls) != 1:
        return False
    options = [arg for arg in args if arg != urls[0]]
    if fetch[0] == "curl":
        return all(
            (arg.startswith("-") and not arg.startswith("--") and set(arg[1:]) <= set("fsSL"))
            or arg in {"--fail", "--silent", "--show-error", "--location"}
            for arg in options
        )
    if fetch[0] == "wget":
        # Bind -O to its actual next argument before removing the URL. Its
        # position among other supported options does not change stdout routing.
        options = []
        remaining = iter(args)
        for arg in remaining:
            if arg == "-O":
                if next(remaining, None) != "-":
                    return False
                options.append("-O-")
            elif arg != urls[0]:
                options.append(arg)
        return any(arg in {"-O-", "-qO-", "--output-document=-"} for arg in options) and all(
            arg in {"-q", "--quiet", "-O-", "-qO-", "--output-document=-"} for arg in options
        )
    return False


def literal_encoded_pipeline(command: str) -> str | None:
    """Recognize one literal source, one decoder and an interpreter reading stdin."""
    command = command.strip()
    if len(command) > 4200 or command.count("|") != 2:
        return None
    if any(char in command for char in "$`;&<>()\\\n"):
        return None
    try:
        source, decoder, interpreter = (shlex.split(part) for part in command.split("|"))
    except ValueError:
        return None
    if len(source) == 3 and source[:2] in (["printf", "%s"], ["echo", "-n"]):
        token = source[2]
    elif len(source) == 2 and source[0] in {"echo", "printf"}:
        token = source[1]
    else:
        return None
    if not 1 <= len(token) <= 4096:
        return None
    if decoder in (["base64", "-d"], ["base64", "-D"], ["base64", "--decode"]):
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            return None
    elif decoder == ["xxd", "-r", "-p"]:
        try:
            decoded = bytes.fromhex(token)
        except ValueError:
            return None
    else:
        return None
    if not decoded or len(decoded) > 4096 or not interpreter:
        return None
    return stdin_interpreter(interpreter)


def stdin_interpreter(interpreter: list[str]) -> str | None:
    """Only program stdin: never script operands, string commands or syntax checks."""
    if not interpreter:
        return None
    if interpreter in (["sh"], ["bash"], ["zsh"]) or (
        interpreter[0] in {"sh", "bash", "zsh"} and interpreter[1:] in (["-s"], ["-s", "--"])
    ):
        return "shell execution"
    if _PYTHON_STDIN.fullmatch(interpreter[0]) and interpreter[1:] in (
        [],
        ["-"],
        ["-u"],
        ["-u", "-"],
    ):
        return "Python interpreter execution"
    return None
