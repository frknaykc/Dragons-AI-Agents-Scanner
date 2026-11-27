"""Bounded, non-executing model of a small straight-line Python subset.

Only direct input strings and positive literal sys.argv indices are sources. Stop
at the first unknown operation: it could change bindings, mutate an imported
module, or prevent later statements from running. Never resolve target imports.
"""

import ast
import io
import tokenize
import warnings
from dataclasses import dataclass

from dragonscan.models import Artifact, Document, Relationship, SourceRef

MAX_BYTES = 65_536
MAX_TOKENS = 8192
MAX_LINE_TOKENS = 192  # Bounds unparenthesized operator/attribute chains before ast.parse.
MAX_DEPTH = 32
MAX_AST_NODES = 4096

_MODULES = {"sys", "os", "subprocess"}
_PROCESS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
_MEMBERS = _PROCESS | {"os.system", "sys.argv"}
_DYNAMIC = {"eval", "exec"}


class _Limit(Exception):
    pass


class _Unsupported(Exception):
    pass


def _tree(text: str) -> ast.Module:
    if len(text) > MAX_BYTES or len(text.encode("utf-8")) > MAX_BYTES:
        raise _Limit
    # Match the AST parser's universal newlines, including CR-only source.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    depth = line_tokens = 0
    for count, token in enumerate(tokenize.generate_tokens(io.StringIO(text).readline), 1):
        if token.type == tokenize.NEWLINE:
            line_tokens = 0
        elif token.type not in (tokenize.COMMENT, tokenize.NL):
            line_tokens += 1
        if token.type == tokenize.INDENT or (token.type == tokenize.OP and token.string in "([{"):
            depth += 1
        elif token.type == tokenize.DEDENT or (token.type == tokenize.OP and token.string in ")]}"):
            depth -= 1
        if count > MAX_TOKENS or line_tokens > MAX_LINE_TOKENS or depth > MAX_DEPTH:
            raise _Limit
    # Parser warnings (e.g. invalid string escapes) must not expose target text.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(text)
    if any(i > MAX_AST_NODES for i, _ in enumerate(ast.walk(tree), 1)):
        raise _Limit
    return tree


@dataclass(frozen=True)
class _Source:
    label: str
    line: int


class _Prefix:
    def __init__(self, artifact: Artifact) -> None:
        self.artifact = artifact
        self.symbols = {name: name for name in {"input", *_DYNAMIC}}
        # Only known strings enter this table. None means a fixed string.
        self.strings: dict[str, _Source | None] = {}
        self.links: list[Relationship] = []
        self.dynamic_barrier = False

    def bind(self, name: str, symbol: str | None = None) -> None:
        self.symbols.pop(name, None)
        self.strings.pop(name, None)
        if symbol is not None:
            self.symbols[name] = symbol

    def symbol(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = self.symbols.get(node.value.id)
            if module in _MODULES:
                member = f"{module}.{node.attr}"
                if member in _MEMBERS:
                    return member
        return None

    def string(self, node: ast.expr) -> _Source | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return None
        if isinstance(node, ast.Name) and node.id in self.strings:
            return self.strings[node.id]
        if isinstance(node, ast.Call) and self.symbol(node.func) == "input":
            if not node.keywords and (
                not node.args
                or (
                    len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                )
            ):
                return _Source("input()", node.lineno)
        if isinstance(node, ast.Subscript) and self.symbol(node.value) == "sys.argv":
            index = node.slice
            if isinstance(index, ast.Constant) and type(index.value) is int and index.value >= 0:
                return _Source("sys.argv", node.lineno) if index.value else None
        raise _Unsupported

    def command(self, node: ast.expr) -> _Source | None:
        if isinstance(node, (ast.List, ast.Tuple)):
            if not node.elts:
                raise _Unsupported
            # Validate every element, but only argv[0] selects the executable.
            return [self.string(item) for item in node.elts][0]
        return self.string(node)

    def process_argument(self, call: ast.Call, sink: str) -> _Source | None:
        if len(call.args) > 1:
            raise _Unsupported
        args = call.args[0] if call.args else None
        executable = None
        seen: set[str] = set()
        for kw in call.keywords:
            if kw.arg is None or kw.arg in seen:
                raise _Unsupported
            seen.add(kw.arg)
            if kw.arg == "args" and args is None:
                args = kw.value
            elif kw.arg == "executable":
                executable = kw.value
            elif kw.arg == "shell" or (
                sink == "subprocess.run" and kw.arg in {"check", "capture_output"}
            ):
                if not isinstance(kw.value, ast.Constant) or type(kw.value.value) is not bool:
                    raise _Unsupported
            else:
                raise _Unsupported
        if args is None:
            raise _Unsupported
        source = self.command(args)
        # Executable overrides argv[0]. With shell=True both inputs can matter;
        # don't infer platform-specific semantics for that combination.
        if executable is not None:
            if any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in call.keywords
            ):
                raise _Unsupported
            return self.string(executable)
        return source

    def sink(self, call: ast.Call, name: str) -> None:
        if name in _PROCESS:
            source = self.process_argument(call, name)
        elif name in _DYNAMIC or name == "os.system":
            if len(call.args) != 1 or call.keywords:
                raise _Unsupported
            source = self.string(call.args[0])
            self.dynamic_barrier = name in _DYNAMIC
        else:
            raise _Unsupported
        if source:
            # For a nested multiline source the call can start before its argument.
            end = call.lineno if call.lineno >= source.line else (call.end_lineno or source.line)
            loc = SourceRef(self.artifact.path, self.artifact.source_format, source.line, end)
            self.links.append(Relationship("code_execution_input", source.label, loc, name))

    def statement(self, stmt: ast.stmt) -> None:
        if self.dynamic_barrier:
            raise _Unsupported
        if isinstance(stmt, ast.Pass):
            return
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name not in _MODULES:
                    raise _Unsupported
                self.bind(alias.asname or alias.name, alias.name)
            return
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                member = f"{stmt.module}.{alias.name}"
                if stmt.level or member not in _MEMBERS:
                    raise _Unsupported
                self.bind(alias.asname or alias.name, member)
            return
        target = None
        if isinstance(stmt, ast.Expr):
            value = stmt.value
        elif (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            target = stmt.targets[0].id
            value = stmt.value
        else:
            raise _Unsupported
        if isinstance(value, ast.Call) and (name := self.symbol(value.func)) and name != "input":
            self.sink(value, name)
            if target is not None:
                self.bind(target)
        elif isinstance(value, ast.Constant) and not isinstance(value.value, str):
            if target is not None:
                self.bind(target)
        else:
            source = self.string(value)
            if target is not None:
                self.bind(target)
                self.strings[target] = source


def parse_python_script(artifact: Artifact, text: str) -> Document:
    """Return normalized static facts only; diagnostics never include raw source."""
    try:
        tree = _tree(text)
    except (_Limit, RecursionError, OverflowError):
        return Document(artifact, diagnostics=("Python analysis partial: parser limit exceeded",))
    except (SyntaxError, tokenize.TokenError, ValueError):
        return Document(artifact, diagnostics=("Python analysis partial: invalid source syntax",))
    prefix = _Prefix(artifact)
    diagnostics: tuple[str, ...] = ()
    for stmt in tree.body:
        try:
            prefix.statement(stmt)
        except _Unsupported:
            diagnostics = (f"Python analysis partial: unsupported semantics at line {stmt.lineno}",)
            break
    return Document(artifact, relationships=tuple(prefix.links), diagnostics=diagnostics)
