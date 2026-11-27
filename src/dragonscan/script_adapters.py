"""Whole-file subsets: scalar bindings followed by at most one terminal use.

Each adapter recognizes complete physical statements, not tokens found inside them.
Values carry only the line of the original CLI argument (or None for literals).
Unsupported syntax anywhere invalidates the entire analysis, including prior uses.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from dragonscan.models import Artifact, Document, Relationship, SourceRef

# Keep local variables distinct from builtins, reserved words and automatic variables.
# local_* is an open namespace for ordinary names; PowerShell is case insensitive.
_NAME = r"(?:cmd|command|tool|program|runner|choice|value|payload|code|arg|local_[A-Za-z0-9_]+)"
_PS_FLAGS = re.ASCII | re.IGNORECASE
_WORD = re.compile(r"[A-Za-z0-9_./-]+")
_SQ = re.compile(r"'[^']*'")
_DQ_SH = re.compile(r'"[^"$`\\]*"')
_DQ_PS = re.compile(r'"[^"$`]*"')
_JS_STRING = re.compile(r"""(?:'[^'\\]*'|"[^"\\]*")""")
_PARTIAL = "skill package script inventoried; program semantics unsupported by bounded adapter"
_Bindings = dict[str, int | None]


class _Unsupported(ValueError):
    pass


@dataclass(frozen=True)
class _Use:
    origin: int | None
    sink: str | None  # None: a display operation, not an execution sink.


def _bound(names: _Bindings, name: str) -> int | None:
    if name not in names:
        raise _Unsupported
    return names[name]


def _sh_value(expr: str, line: int, names: _Bindings) -> int | None:
    if _SQ.fullmatch(expr) or _DQ_SH.fullmatch(expr) or _WORD.fullmatch(expr):
        return None
    if expr.startswith('"') and expr.endswith('"'):
        expr = expr[1:-1]
    if re.fullmatch(r"\$[1-9]", expr):
        return line
    if ref := re.fullmatch(rf"\$({_NAME})", expr):
        return _bound(names, ref[1])
    raise _Unsupported


def _shell(statement: str, line: int, names: _Bindings) -> _Use | None:
    if binding := re.fullmatch(rf"({_NAME})=(.+)", statement):
        names[binding[1]] = _sh_value(binding[2], line, names)
        return None
    if call := re.fullmatch(r"(eval|(?:sh|bash)[ \t]+-c|echo)[ \t]+(.+)", statement):
        return _Use(
            _sh_value(call[2], line, names), None if call[1] == "echo" else "shell evaluation"
        )
    # A single double-quoted expansion selects a command, not a fixed command's argument.
    if re.fullmatch(rf'"\$(?:[1-9]|{_NAME})"', statement):
        return _Use(_sh_value(statement, line, names), "shell command selection")
    raise _Unsupported


def _ps_value(expr: str, line: int, names: _Bindings) -> int | None:
    if _SQ.fullmatch(expr) or _DQ_PS.fullmatch(expr):
        return None
    if re.fullmatch(r"\$args\[[0-9]\]", expr, _PS_FLAGS):
        return line
    if ref := re.fullmatch(rf"\$({_NAME})", expr, _PS_FLAGS):
        return _bound(names, ref[1].lower())
    raise _Unsupported


def _powershell(statement: str, line: int, names: _Bindings) -> _Use | None:
    if binding := re.fullmatch(rf"\$({_NAME})[ \t]*=[ \t]*(.+)", statement, _PS_FLAGS):
        names[binding[1].lower()] = _ps_value(binding[2], line, names)
        return None
    if call := re.fullmatch(r"(&|Invoke-Expression|Write-Output)[ \t]+(.+)", statement, _PS_FLAGS):
        sink = {"&": "PowerShell command selection", "invoke-expression": "PowerShell evaluation"}
        return _Use(_ps_value(call[2], line, names), sink.get(call[1].lower()))
    raise _Unsupported


def _js_value(expr: str, line: int, names: _Bindings) -> int | None:
    if _JS_STRING.fullmatch(expr):
        return None
    # argv[0] and argv[1] identify the executable and script, not caller arguments.
    if re.fullmatch(r"process\.argv\[[2-9]\]", expr):
        return line
    if re.fullmatch(_NAME, expr):
        return _bound(names, expr)
    raise _Unsupported


def _javascript(statement: str, line: int, names: _Bindings) -> _Use | None:
    statement = statement.removesuffix(";").rstrip(" \t")
    if binding := re.fullmatch(rf"(?:const|let)[ \t]+({_NAME})[ \t]*=[ \t]*(.+)", statement):
        if binding[1] in names:
            raise _Unsupported
        names[binding[1]] = _js_value(binding[2], line, names)
        return None
    if call := re.fullmatch(r"(eval|console\.log)\(([^\n]+)\)", statement):
        return _Use(
            _js_value(call[2].strip(" \t"), line, names),
            "JavaScript evaluation" if call[1] == "eval" else None,
        )
    raise _Unsupported


_Adapter = Callable[[str, int, _Bindings], _Use | None]
_ADAPTERS: dict[str, _Adapter] = {
    ".sh": _shell,
    ".bash": _shell,
    ".zsh": _shell,
    ".ps1": _powershell,
    ".js": _javascript,
    ".cjs": _javascript,
    ".mjs": _javascript,
}
_SHEBANGS: dict[_Adapter, set[str]] = {
    _shell: {
        f"#!{prefix}{sh}" for prefix in ("/bin/", "/usr/bin/env ") for sh in ("sh", "bash", "zsh")
    },
    _powershell: {"#!/usr/bin/env pwsh", "#!/usr/bin/pwsh"},
    _javascript: {"#!/usr/bin/env node", "#!/usr/bin/node"},
}


def parse_script_subset(artifact: Artifact, text: str) -> Document:
    """Statically recognize the declared language's bounded grammar; never open the path."""
    adapter = _ADAPTERS.get(artifact.path.suffix.lower())
    partial = Document(artifact, diagnostics=(_PARTIAL,))
    if adapter is None or len(text) > 64 * 1024:
        return partial
    text = text.replace("\r\n", "\n")
    # splitlines()/strip() would invent statement boundaries from vertical tabs etc.
    if re.search(r"[^\x20-\x7e\t\n]", text) or text.count("\n") > 512:
        return partial
    names: _Bindings = {}
    comment = "//" if adapter is _javascript else "#"
    terminal = False
    relationships: tuple[Relationship, ...] = ()
    for lineno, physical in enumerate(text.split("\n"), 1):
        if len(physical) > 2048:
            return partial
        statement = physical.strip(" \t")
        if lineno == 1 and physical.startswith("#!"):
            if physical not in _SHEBANGS[adapter]:
                return partial
            continue
        if adapter is _powershell and statement.lower().startswith("#requires"):
            return partial
        if not statement or statement.startswith(comment):
            continue
        if terminal:
            return partial
        try:
            use = adapter(statement, lineno, names)
        except _Unsupported:
            return partial
        if use is not None:
            terminal = True
            if use.origin is not None and use.sink is not None:
                location = SourceRef(artifact.path, artifact.source_format, use.origin, lineno)
                relationships = (
                    Relationship(
                        "code_execution_input", "command-line argument", location, use.sink
                    ),
                )
    return Document(artifact, relationships=relationships)
