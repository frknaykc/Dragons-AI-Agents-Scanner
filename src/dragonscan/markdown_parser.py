"""Non-executing Markdown parsing with block/inline structure and line ranges."""

import re
from dataclasses import replace
from pathlib import PurePosixPath

from markdown_it import MarkdownIt
from markdown_it.rules_inline import StateInline, html_inline

from dragonscan.models import (
    Artifact,
    ArtifactKind,
    ConfigEntry,
    Document,
    Instruction,
    MarkdownBlock,
    Relationship,
    SourceFormat,
    SourceRef,
    Span,
)
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url
from dragonscan.skill_package import DATA_SUFFIXES, SCRIPT_SUFFIXES

_URL = re.compile(r"https?://[^\s<>\[\]()]+", re.I)
_FILE_SUFFIXES = frozenset({".md", ".json", ".yaml", ".yml", ".toml"})
_LOAD_FILE = re.compile(
    r"^(?:(?:please|first|then)\s+)?(?:load|include|use|follow)\s+"
    r"(?P<path>(?:\.{1,2}/|[\w.-]+/)*[\w.-]+\.(?:md|json|yaml|yml|toml))\b",
    re.I,
)
_HTML_SOURCE = re.compile(r"^\s*<(?:!--|/?[A-Za-z][\w:-]*(?:\s|>|/))")
_PACKAGE_LOAD = re.compile(
    r"^(?:(?:please|first|then)\s+)?(?:load|include|use|follow)\s+"
    r"(?:\[[^\[\]\n]+\]\((?P<link>[^()\s]+)\)|`(?P<code>[^`\s]+)`|(?P<plain>[\w./-]+?))\.?$",
    re.I,
)
_MAX_TOKENS = 40_000

_RUN_SCRIPT = re.compile(
    r"^(?:(?:please|then)\s+)?(?:run|execute)\s+(?P<tick>`?)"
    r"(?:(?P<runtime>sh|bash|zsh|python3?|node|pwsh\s+-File)\s+)?"
    r"(?P<path>(?:[\w.-]+/)*[\w.-]+\.[\w]+)(?P=tick)\.?$",
    re.I,
)
_SCRIPT_RUNTIME = {
    "sh": {".sh"},
    "bash": {".sh", ".bash"},
    "zsh": {".sh", ".zsh"},
    "python": {".py"},
    "python3": {".py"},
    "node": {".js", ".cjs", ".mjs"},
    "pwsh -file": {".ps1"},
}


def _skill_metadata(
    artifact: Artifact, text: str
) -> tuple[str, tuple[ConfigEntry, ...], tuple[str, ...]]:
    # Reuse the bounded, duplicate/alias-rejecting data loader, not MCP/config normalization.
    from dragonscan.structured_parser import _entries, _load

    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return text, (), ()
    end = next((i for i, s in enumerate(lines[1:], 1) if s.strip() == "---"), None)
    if end is None:
        # Without an end delimiter even an apparent paragraph may be a YAML scalar.
        return "", (), ("unclosed skill frontmatter; body boundary unknown",)
    body = "\n" * (end + 1) + "".join(lines[end + 1 :])
    if end > 256 or sum(map(len, lines[:end])) > 32_768:
        return body, (), ("skill frontmatter size limit exceeded",)
    yaml_artifact = replace(artifact, source_format=SourceFormat.YAML)
    try:
        data, node = _load(yaml_artifact, "".join(lines[1:end]))
        if not isinstance(data, dict):
            raise ParseError("expected mapping")
        entries = tuple(
            replace(
                item,
                location=SourceRef(
                    artifact.path, SourceFormat.MARKDOWN, (item.location.line or 1) + 1
                ),
            )
            for item in _entries(yaml_artifact, data, node)
            if item.key_path[0]
            in {"name", "description", "compatibility", "allowed-tools", "metadata"}
        )
        if not all(
            isinstance(data.get(field), str) and data[field].strip()
            for field in ("name", "description")
        ) or any(
            field in data and not isinstance(data[field], expected)
            for field, expected in (
                ("compatibility", str),
                ("allowed-tools", str),
                ("metadata", dict),
            )
        ):
            return (
                body,
                entries,
                ("unsupported skill frontmatter field type or missing name/description",),
            )
        return body, entries, ()
    except ParseError as exc:
        if "duplicate YAML mapping key" in str(exc):
            return body, (), ("duplicate key in skill frontmatter",)
        return body, (), ("malformed skill frontmatter",)


def _reference(destination: str, location: SourceRef, package: bool = False) -> Relationship | None:
    url = safe_url(destination)
    if url is not None:
        return Relationship("references_url", url, location)
    if destination.startswith(("#", "//")) or ":" in destination.split("/")[0]:
        return None
    file_path = destination.split("?", 1)[0].split("#", 1)[0]
    suffix = PurePosixPath(file_path).suffix.lower()
    if suffix in _FILE_SUFFIXES or (package and suffix in SCRIPT_SUFFIXES | DATA_SUFFIXES):
        return Relationship("references_file", file_path, location)
    return None


def _html_comment(state: StateInline, silent: bool) -> bool:
    """Tokenize comments only, retaining their exact inline source offsets."""
    start = state.pos
    if not state.src.startswith("<!--", start) or not html_inline(state, silent):
        return False
    if not silent:
        state.tokens[-1].meta["source_offset"] = start
        state.tokens[-1].meta["quoted"] = bool(
            start
            and state.src[start - 1] in "\"'"
            and state.src[state.pos : state.pos + 1] == state.src[start - 1]
        )
    return True


def parse_markdown(artifact: Artifact, text: str) -> Document:
    cursor_rule = artifact.ecosystem == "Cursor" and artifact.path.suffix.lower() == ".mdc"
    frontmatter_end = 0
    frontmatter_diagnostics: tuple[str, ...] = ()
    frontmatter_entries: tuple[ConfigEntry, ...] = ()
    if artifact.kind == ArtifactKind.SKILL:
        text, frontmatter_entries, frontmatter_diagnostics = _skill_metadata(artifact, text)
    if cursor_rule:
        lines = text.splitlines()
        if not lines or lines[0].strip() != "---":
            return Document(artifact, diagnostics=("Cursor rule missing frontmatter; ignored",))
        frontmatter_end = next(
            (index for index, line in enumerate(lines[1:], 2) if line.strip() == "---"), 0
        )
        if not frontmatter_end:
            return Document(artifact, diagnostics=("Cursor rule frontmatter not closed; ignored",))
        from dragonscan.structured_parser import parse_structured

        try:
            metadata = parse_structured(
                Artifact(artifact.path, ArtifactKind.STRUCTURED_CONFIG, SourceFormat.YAML),
                "\n".join(lines[1 : frontmatter_end - 1]),
            )
            values = {entry.key_path: entry.value for entry in metadata.entries}
            if (
                not isinstance(values.get(("description",)), str)
                and not isinstance(values.get(("globs",)), str)
                and values.get(("alwaysApply",)) is not True
            ) or (("alwaysApply",) in values and type(values[("alwaysApply",)]) is not bool):
                frontmatter_diagnostics = ("unsupported Cursor rule frontmatter; ignored",)
            else:
                frontmatter_entries = tuple(
                    replace(
                        entry,
                        location=SourceRef(
                            artifact.path,
                            SourceFormat.MARKDOWN,
                            entry.location.line + 1 if entry.location.line is not None else None,
                        ),
                    )
                    for entry in metadata.entries
                    if entry.key_path in {("description",), ("globs",), ("alwaysApply",)}
                )
        except ParseError:
            frontmatter_diagnostics = ("malformed Cursor rule frontmatter; ignored",)
    parser = MarkdownIt("commonmark", {"html": True, "maxNesting": 64}).disable("html_block")
    parser.inline.ruler.at("html_inline", _html_comment)
    try:
        tokens = parser.parse(text)
    except (RecursionError, OverflowError, ValueError) as exc:
        raise ParseError("Markdown exceeds parser complexity limit") from exc
    if len(tokens) + sum(len(token.children or ()) for token in tokens) > _MAX_TOKENS:
        raise ParseError("Markdown exceeds token limit")
    blocks: list[MarkdownBlock] = []
    instructions: list[Instruction] = []
    relations: list[Relationship] = []
    container: list[str] = []
    for index, token in enumerate(tokens):
        if token.type in {
            "blockquote_open",
            "bullet_list_open",
            "ordered_list_open",
            "list_item_open",
        }:
            container.append(token.type)
        elif token.type in {
            "blockquote_close",
            "bullet_list_close",
            "ordered_list_close",
            "list_item_close",
        }:
            if container:
                container.pop()
        if token.type in {"fence", "code_block"}:
            start, end = token.map or [0, 0]
            blocks.append(
                MarkdownBlock(
                    "quote" if "blockquote_open" in container else "code",
                    token.content,
                    SourceRef(artifact.path, artifact.source_format, start + 1, end),
                    language=token.info.strip().split(None, 1)[0] if token.info.strip() else None,
                )
            )
            continue
        if token.type != "inline":
            continue
        start, end = token.map or [0, 0]
        location = SourceRef(artifact.path, artifact.source_format, start + 1, end)
        spans: list[Span] = []
        link: str | None = None
        comments: list[MarkdownBlock] = []
        comment_offset, comment_line = 0, start + 1
        for child in token.children or []:
            if child.type == "link_open":
                link = str(child.attrGet("href")) if child.attrGet("href") is not None else None
                if link:
                    relation = _reference(link, location, artifact.package_root is not None)
                    if relation is not None:
                        relations.append(relation)
            elif child.type == "link_close":
                link = None
            elif child.type in {"softbreak", "hardbreak"}:
                spans.append(Span("text", "\n", location))
            elif child.type == "html_inline":
                offset = child.meta["source_offset"]
                comment_line += token.content.count("\n", comment_offset, offset)
                comment_offset = offset
                comment_location = SourceRef(
                    artifact.path,
                    artifact.source_format,
                    comment_line,
                    comment_line + child.content.count("\n"),
                )
                comments.append(
                    MarkdownBlock(
                        "quote"
                        if "blockquote_open" in container or child.meta["quoted"]
                        else "html",
                        child.content,
                        comment_location,
                    )
                )
                # Do not join separate words or lose subsequent source line offsets.
                spans.append(Span("text", " " + "\n" * child.content.count("\n"), location))
            elif child.type in {"text", "code_inline"}:
                kind = "inline_code" if child.type == "code_inline" else "link" if link else "text"
                destination = (
                    safe_url(link) if link and link.startswith(("http://", "https://")) else link
                )
                spans.append(Span(kind, child.content, location, destination))
                if kind == "text":
                    for match in _URL.finditer(child.content):
                        relation = _reference(match.group().rstrip(".,;"), location)
                        if relation is not None:
                            relations.append(relation)
        is_quote = "blockquote_open" in container
        is_html = _HTML_SOURCE.match(token.content) is not None and not (
            comments and token.content.lstrip().startswith("<!--")
        )
        is_list = "list_item_open" in container
        is_heading = index > 0 and tokens[index - 1].type == "heading_open"
        kind = (
            "quote"
            if is_quote
            else "html"
            if is_html
            else "heading"
            if is_heading
            else "list_item"
            if is_list
            else "paragraph"
        )
        blocks.append(MarkdownBlock(kind, token.content, location, tuple(spans)))
        blocks.extend(comments)
        if artifact.package_root and kind in {"paragraph", "list_item"}:
            run = _RUN_SCRIPT.fullmatch(token.content.strip())
            if run:
                target = run["path"]
                suffix = PurePosixPath(target).suffix.lower()
                runtime = (run["runtime"] or "").lower()
                if (runtime and suffix in _SCRIPT_RUNTIME.get(runtime, set())) or (
                    not runtime and "/" in target and suffix in SCRIPT_SUFFIXES
                ):
                    relations.append(Relationship("runs_script", target, location))
        if not is_quote and not is_html:
            visible = "".join(
                span.text
                + (
                    f" {span.destination}"
                    if span.kind == "link"
                    and span.destination
                    and span.destination.startswith(("http://", "https://"))
                    else ""
                )
                for span in spans
                if span.kind != "inline_code"
            )
            leading_lines = visible[: len(visible) - len(visible.lstrip())].count("\n")
            visible = visible.strip()
            if visible:
                instruction_location = replace(location, line=start + 1 + leading_lines)
                instructions.append(
                    Instruction(visible, start + 1 + leading_lines, instruction_location)
                )
                # Only an explicit directive yields a load edge; a hyperlink alone is a reference.
                if artifact.package_root:
                    # Resolve the actual link destination, never its display text.
                    load = _PACKAGE_LOAD.fullmatch(token.content.strip())
                    target = (load["link"] or load["code"] or load["plain"]) if load else None
                else:
                    load = _LOAD_FILE.match(visible)
                    target = load["path"] if load else None
                if target:
                    relation = _reference(target, instruction_location)
                    if relation is not None and relation.kind == "references_file":
                        relations.append(
                            Relationship("loads_file", relation.target, instruction_location)
                        )
    if cursor_rule:
        blocks = [block for block in blocks if (block.location.line or 0) > frontmatter_end]
        instructions = [
            item for item in instructions if (item.location.line or 0) > frontmatter_end
        ]
        relations = [item for item in relations if (item.location.line or 0) > frontmatter_end]
    return Document(
        artifact,
        instructions=tuple(instructions),
        blocks=tuple(blocks),
        entries=frontmatter_entries,
        relationships=tuple(dict.fromkeys(relations)),
        diagnostics=frontmatter_diagnostics,
    )
