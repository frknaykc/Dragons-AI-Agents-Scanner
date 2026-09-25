"""Bounded, inert analysis views for suspicious artifact text.

No view mutates a parsed document or supplies new graph/taint relationships.
"""

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, replace
from urllib.parse import unquote

from dragonscan.models import Confidence, Document, EvasionEvidence, McpServer, SourceRef

MAX_REGION = 4096
MAX_OUTPUT = 4096
MAX_REGIONS = 128
MAX_VIEWS = 64
MAX_DEPTH = 3
MAX_ATTEMPTS = 128
MAX_PER_REGION = 12
MAX_EXPANSION_RATIO = 8
_BIDI = frozenset(chr(i) for i in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
_INVISIBLE = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad")
# Deliberately small, inspectable mapping: token camouflage, not language transliteration.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "і": "i",
        "ӏ": "l",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
    }
)
_ENCODED = re.compile(r"(?<![\w/])(?:[0-9a-fA-F]{8,4096}|[A-Za-z0-9+/_-]{16,4096}={0,2})(?![\w/])")
_HEX_BYTES = re.compile(r"(?:0x[0-9a-fA-F]{2}[ \t,]*){4,128}")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
_CONCAT = re.compile(
    r"(?P<q>['\"])(?P<a>[A-Za-z0-9+/]{2,})\1\s*\+\s*(?P<r>['\"])(?P<b>[A-Za-z0-9+/]{2,})\3"
)
_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}|(?:\\u[0-9a-fA-F]{4}){2,}")
_ACTION = re.compile(
    r"\b(?:run|execute|read|send|upload|ignore|disable|download|fetch|write|override|encoded|base64)\b",
    re.I,
)
_SHELL = re.compile(r"\b(?:bash|sh|zsh|python|node|curl|wget|powershell)\b", re.I)
_PS_ENCODED = re.compile(
    r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|encodedcommand)\b", re.I
)
_SHELL_LITERALS = re.compile(
    r"(?P<q>['\"])(?P<a>[A-Za-z]{2,32})\1\s*(?P<r>['\"])(?P<b>[A-Za-z]{2,32})\3"
)
_HTML_METADATA = re.compile(
    r"\b(?:title|aria-label|data-instructions|content)\s*=\s*(['\"])([^'\"]{1,512})\1", re.I
)
_HTML_HIDDEN = re.compile(
    r"<\w+\b[^>]{0,512}(?:\bhidden\b|\bdisplay\s*:\s*none\b)[^>]{0,512}>", re.I
)
_SPACED_COMMAND = re.compile(r"\bc\s+u\s+r\s+l\b", re.I)
_BAD_ESCAPE = re.compile(
    r"\\(?:x(?![0-9A-Fa-f]{2})(?:[A-Z]{2}|[0-9A-Fa-f]\b)"
    r"|u(?![0-9A-Fa-f]{4})(?:[A-Z]{4}|[0-9A-Fa-f]{1,3}\b))"
)
_CONFIG_TEXT_KEYS = frozenset(
    {"description", "instructions", "instruction", "prompt", "systemprompt", "command", "script"}
)
_PRIVATE_KEYS = frozenset(
    {
        "env",
        "environment",
        "headers",
        "authorization",
        "token",
        "password",
        "secret",
        "api_key",
        "apikey",
        "registry",
        "url",
        "endpoint",
    }
)
_HEURISTIC = frozenset({"unicode-confusables", "token-fragmentation", "shell-lexical"})


@dataclass(frozen=True)
class AnalysisView:
    document: Document
    evidence: EvasionEvidence
    location: SourceRef
    text: str
    context: str


def _readable(value: bytes) -> str | None:
    if len(value) > MAX_OUTPUT:
        return None
    try:
        text = value.decode("utf-8")
    except UnicodeError:
        return None
    if not text or sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) < 0.95:
        return None
    return text


def _hex_bytes_match(match: re.Match[str]) -> str:
    raw = bytes.fromhex("".join(re.findall(r"0x([0-9a-fA-F]{2})", match.group())))
    decoded = _readable(raw)
    if decoded is None:
        return match.group()
    return decoded + (" " if match.group().endswith((" ", "\t", ",")) else "")


def _decode(text: str) -> str | None:
    def substitute(match: re.Match[str]) -> str:
        token = match.group()
        try:
            if len(token) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", token):
                decoded = _readable(bytes.fromhex(token))
            else:
                padded = token + "=" * (-len(token) % 4)
                if "-" in token or "_" in token:
                    raw = base64.b64decode(padded, altchars=b"-_", validate=True)
                else:
                    raw = base64.b64decode(padded, validate=True)
                decoded = _readable(raw)
                if decoded is None and _PS_ENCODED.search(text):
                    try:
                        decoded = _readable(raw.decode("utf-16-le").encode("utf-8"))
                    except UnicodeError:
                        pass
        except (ValueError, binascii.Error):
            return token
        if decoded is None or not (
            _ACTION.search(decoded)
            or _SHELL.search(decoded)
            or (len(decoded) >= 24 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", decoded))
        ):
            return token
        return decoded

    result = _HEX_BYTES.sub(_hex_bytes_match, text, count=4)
    result = _ENCODED.sub(substitute, result, count=4)
    return result if result != text else None


def _transform(text: str) -> tuple[tuple[str, str], ...]:
    results: list[tuple[str, str]] = []
    stripped = text.strip()
    if stripped.startswith("<!--") and stripped.endswith("-->"):
        results.append(("hidden-html", stripped[4:-3].strip()))
    elif _HTML_HIDDEN.match(stripped):
        inner = re.sub(r"<[^>]{1,512}>", " ", stripped).strip()
        if inner:
            results.append(("hidden-html", inner))
    elif stripped.startswith("<"):
        for match in _HTML_METADATA.finditer(stripped[:1024]):
            if _ACTION.search(match.group(2)):
                results.append(("hidden-html", match.group(2)))
                break
    cleaned = "".join(ch for ch in text if ch not in _BIDI | _INVISIBLE)
    if cleaned != text:
        results.append(("unicode-format-controls", cleaned))
    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        results.append(("unicode-nfkc", folded))
    mapped = text.translate(_CONFUSABLES)
    if mapped != text:
        results.append(("unicode-confusables", mapped))
    if text.count("%") >= 2:
        try:
            unquoted = _PERCENT.sub(
                lambda match: unquote(match.group(), encoding="utf-8", errors="strict"), text
            )
        except UnicodeError:
            unquoted = text
        if unquoted != text:
            results.append(("percent-encoding", unquoted))
    if text.count("&") >= 2:
        unescaped = html.unescape(text)
        if unescaped != text:
            results.append(("html-entities", unescaped))
    if text.count("\\") >= 2:

        def escapes(match: re.Match[str]) -> str:
            chunks = re.findall(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))", match.group())
            return "".join(chr(int(a or b, 16)) for a, b in chunks)

        unescaped = _ESCAPES.sub(escapes, text)
        if unescaped != text:
            results.append(("character-escapes", unescaped))
    joined = _CONCAT.sub(lambda m: m.group("a") + m.group("b"), text)
    if joined != text:
        results.append(("literal-concatenation", joined))
    adjacent = _SHELL_LITERALS.sub(lambda m: m.group("a") + m.group("b"), text)
    if adjacent != text:
        results.append(("literal-concatenation", adjacent))
    decoded = _decode(text)
    if decoded is not None:
        results.append(("encoded-payload", decoded))
    # Shell lexical obfuscation, not expansion or execution.
    shell = text.replace("${IFS}", " ").replace("$'\\t'", " ")
    shell = re.sub(r"(?<=\w)\\?\n(?=\w)", "", shell)
    shell = re.sub(r"(?<=\w)\\(?=\w)", "", shell)
    if shell != text:
        results.append(("shell-lexical", shell))
    if re.search(
        r"\b(?:run|execute)\b.{0,80}https?://[^\s|]{1,200}\s*\|\s*(?:bash|sh|zsh)\b", text, re.I
    ):
        spaced = _SPACED_COMMAND.sub("curl", text)
        if spaced != text:
            results.append(("token-fragmentation", spaced))
    return tuple((name, value) for name, value in results if len(value) <= MAX_OUTPUT)


def _excerpt(text: str, kind: str) -> str:
    # Do not echo payloads, URL credentials, paths, tokens, or control characters.
    points = ", ".join(f"U+{ord(ch):04X}" for ch in text if ch in _BIDI | _INVISIBLE)[:48]
    safe_words = {"run", "curl", "bash", "read", "send", "ignore", "previous", "instructions"}
    shape = re.sub(
        r"\w+|[^\w\s]",
        lambda m: (
            m.group()
            if m.group().lower() in safe_words
            else m.group()
            if m.group() in {"|", ".", ":", "-", "<", ">"}
            else "[text]"
        ),
        text[:80],
    )
    shape = "".join(ch if ch.isprintable() else " " for ch in shape)[:120]
    return f"{kind}: {len(text)} chars; shape {shape}" + (f"; controls {points}" if points else "")


def _regions(document: Document) -> tuple[tuple[str, int, str, SourceRef], ...]:
    regions: list[tuple[str, int, str, SourceRef]] = []
    for i, instruction in enumerate(document.instructions):
        if (
            _ACTION.search(instruction.text)
            or _SHELL.search(instruction.text)
            or _ENCODED.search(instruction.text[:MAX_REGION])
        ):
            regions.append(("instruction", i, instruction.text, instruction.location))
    for i, block in enumerate(document.blocks):
        if block.kind in {"code", "quote", "html"} and (
            _ACTION.search(block.text)
            or _SHELL.search(block.text)
            or _ENCODED.search(block.text[:MAX_REGION])
        ):
            regions.append((f"block-{block.kind}", i, block.text, block.location))
    if document.artifact.path.name == "package.json":
        for i, entry in enumerate(document.entries):
            if (
                len(entry.key_path) == 2
                and entry.key_path[0] == "scripts"
                and entry.key_path[1]
                in {"preinstall", "install", "postinstall", "prepare", "prepublish"}
                and isinstance(entry.value, str)
            ):
                regions.append(("lifecycle-script", i, entry.value, entry.location))
    for i, entry in enumerate(document.entries):
        if (
            entry.kind == "string"
            and isinstance(entry.value, str)
            and entry.key_path
            and str(entry.key_path[-1]).lower() in _CONFIG_TEXT_KEYS
            and not any(str(part).lower() in _PRIVATE_KEYS for part in entry.key_path)
            and not (entry.key_path[0] == "mcpServers")
            and not (
                document.artifact.path.name == "package.json" and entry.key_path[0] == "scripts"
            )
        ):
            regions.append(("config-entry", i, entry.value, entry.location))
    for i, server in enumerate(document.servers):
        regions.append(("mcp-command", i, server.command, server.location))
        for j, arg in enumerate(server.args[:8]):
            regions.append((f"mcp-arg:{j}", i, arg, server.location))
        for j, tool in enumerate(server.tools[:8]):
            for field in ("description", "instructions"):
                regions.append((f"mcp-tool:{j}:{field}", i, getattr(tool, field), tool.location))
        for group in ("resources", "prompts"):
            for j, item in enumerate(getattr(server, group)[:8]):
                regions.append((f"mcp-{group}:{j}:description", i, item.description, item.location))
    return tuple(regions)


def _document_view(document: Document, kind: str, index: int, value: str) -> Document:
    if kind in {"lifecycle-script", "config-entry"}:
        entry = replace(document.entries[index], value=value)
        return replace(
            document,
            entries=(entry,),
            instructions=(),
            blocks=(),
            servers=(),
            relationships=(),
            dependencies=(),
        )
    if kind == "instruction":
        instructions = list(document.instructions)
        instructions[index] = replace(instructions[index], text=value)
        return replace(
            document,
            instructions=tuple(instructions),
            servers=(),
            relationships=(),
            dependencies=(),
        )
    if kind.startswith("block-"):
        blocks = list(document.blocks)
        blocks[index] = replace(
            blocks[index],
            text=value,
            kind="quote" if blocks[index].kind == "html" else blocks[index].kind,
        )
        return replace(
            document,
            blocks=(blocks[index],),
            instructions=(),
            servers=(),
            relationships=(),
            dependencies=(),
        )
    servers = list(document.servers)
    server: McpServer = servers[index]
    if kind == "mcp-command":
        server = replace(server, command=value)
    elif kind.startswith("mcp-arg:"):
        args = list(server.args)
        args[int(kind.split(":")[1])] = value
        server = replace(server, args=tuple(args))
    elif kind.startswith("mcp-tool:"):
        _, position, field = kind.split(":")
        tools = list(server.tools)
        tool = tools[int(position)]
        tools[int(position)] = (
            replace(tool, instructions=value)
            if field == "instructions"
            else replace(tool, description=value)
        )
        server = replace(server, tools=tuple(tools))
    else:
        _, group, position, _ = kind.split(":")
        if group == "resources":
            resources = list(server.resources)
            resources[int(position)] = replace(resources[int(position)], description=value)
            server = replace(server, resources=tuple(resources))
        else:
            prompts = list(server.prompts)
            prompts[int(position)] = replace(prompts[int(position)], description=value)
            server = replace(server, prompts=tuple(prompts))
    servers[index] = server
    return replace(document, servers=(server,), instructions=(), relationships=(), dependencies=())


def views(document: Document) -> tuple[tuple[AnalysisView, ...], tuple[str, ...]]:
    """Explore each source field independently; truncation is explicit and non-fatal."""
    results: list[AnalysisView] = []
    diagnostics: list[str] = []
    regions = _regions(document)
    if len(regions) > MAX_REGIONS:
        diagnostics.append("evasion region limit exceeded; some regions were not analyzed")
    attempts = 0
    for kind, index, original, location in regions[:MAX_REGIONS]:
        if len(original) > MAX_REGION:
            diagnostics.append("evasion source region too large; region skipped")
            continue
        if _BAD_ESCAPE.search(original):
            diagnostics.append("evasion malformed escape sequence; region analyzed without it")
        seen = {original}
        region_attempts = 0
        queue: list[tuple[str, tuple[str, ...]]] = [(original, ())]
        for current, chain in queue:
            if len(chain) >= MAX_DEPTH:
                if _transform(current):
                    diagnostics.append("evasion transformation depth limit reached")
                continue
            for name, value in _transform(current):
                attempts += 1
                region_attempts += 1
                if (
                    attempts > MAX_ATTEMPTS
                    or region_attempts > MAX_PER_REGION
                    or len(results) >= MAX_VIEWS
                ):
                    diagnostics.append("evasion transform budget exceeded; analysis truncated")
                    return tuple(results), tuple(dict.fromkeys(diagnostics))
                if len(value) > MAX_EXPANSION_RATIO * max(1, len(original)):
                    diagnostics.append("evasion expansion limit reached; analysis truncated")
                    continue
                if value in seen:
                    continue
                seen.add(value)
                steps = (*chain, name)
                queue.append((value, steps))
                evidence = EvasionEvidence(
                    steps,
                    len(steps),
                    kind,
                    location.line,
                    location.end_line,
                    _excerpt(original, kind),
                    Confidence.LOW
                    if len(steps) > 1 or any(step in _HEURISTIC for step in steps)
                    else Confidence.MEDIUM,
                    _excerpt(value, "canonical"),
                )
                results.append(
                    AnalysisView(
                        _document_view(document, kind, index, value),
                        evidence,
                        location,
                        value,
                        kind,
                    )
                )
    return tuple(results), tuple(dict.fromkeys(diagnostics))
