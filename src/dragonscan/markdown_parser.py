"""Non-executing Markdown parsing with block/inline structure and line ranges."""

import re
from dataclasses import replace
from pathlib import PurePosixPath

from markdown_it import MarkdownIt

from dragonscan.models import (
    Artifact,
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

_URL = re.compile(r"https?://[^\s<>\[\]()]+", re.I)
_FILE_SUFFIXES = frozenset({".md", ".json", ".yaml", ".yml", ".toml"})
_LOAD_FILE = re.compile(
    r"^(?:(?:please|first|then)\s+)?(?:load|include|use|follow)\s+"
    r"(?P<path>(?:\.{1,2}/|[\w.-]+/)*[\w.-]+\.(?:md|json|yaml|yml|toml))\b",
    re.I,
)
_HTML_SOURCE = re.compile(r"^\s*<(?:!--|/?[A-Za-z][\w:-]*(?:\s|>|/))")
_MAX_TOKENS = 40_000


def _reference(destination: str, location: SourceRef) -> Relationship | None:
    url = safe_url(destination)
    if url is not None:
        return Relationship("references_url", url, location)
    if destination.startswith(("#", "//")) or ":" in destination.split("/")[0]:
        return None
    file_path = destination.split("?", 1)[0].split("#", 1)[0]
    if PurePosixPath(file_path).suffix.lower() in _FILE_SUFFIXES:
        return Relationship("references_file", file_path, location)
    return None


def parse_markdown(artifact: Artifact, text: str) -> Document:
    cursor_rule = artifact.ecosystem == "Cursor" and artifact.path.suffix.lower() == ".mdc"
    frontmatter_end = 0
    frontmatter_diagnostics: tuple[str, ...] = ()
    frontmatter_entries: tuple[ConfigEntry, ...] = ()
    if cursor_rule:
        lines = text.splitlines()
        if not lines or lines[0].strip() != "---":
            return Document(artifact, diagnostics=("Cursor rule missing frontmatter; ignored",))
        frontmatter_end = next(
            (index for index, line in enumerate(lines[1:], 2) if line.strip() == "---"), 0
        )
        if not frontmatter_end:
            return Document(artifact, diagnostics=("Cursor rule frontmatter not closed; ignored",))
        from dragonscan.models import ArtifactKind
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
    parser = MarkdownIt("commonmark", {"html": False, "maxNesting": 64})
    try:
        tokens = parser.parse(text)
    except (RecursionError, OverflowError, ValueError) as exc:
        raise ParseError("Markdown exceeds parser complexity limit") from exc
    if len(tokens) > _MAX_TOKENS:
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
        for child in token.children or []:
            if child.type == "link_open":
                link = str(child.attrGet("href")) if child.attrGet("href") is not None else None
                if link:
                    relation = _reference(link, location)
                    if relation is not None:
                        relations.append(relation)
            elif child.type == "link_close":
                link = None
            elif child.type in {"softbreak", "hardbreak"}:
                spans.append(Span("text", "\n", location))
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
        is_html = _HTML_SOURCE.match(token.content) is not None
        is_list = "list_item_open" in container
        is_heading = index > 0 and tokens[index - 1].type == "heading_open"
        kind = (
            "html"
            if is_html
            else "heading"
            if is_heading
            else "quote"
            if is_quote
            else "list_item"
            if is_list
            else "paragraph"
        )
        blocks.append(MarkdownBlock(kind, token.content, location, tuple(spans)))
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
            ).strip()
            if visible:
                instructions.append(Instruction(visible, start + 1, location))
                # Only an explicit directive yields a load edge; a hyperlink alone is a reference.
                load = _LOAD_FILE.match(visible)
                if load is not None:
                    relation = _reference(load.group("path"), location)
                    if relation is not None and relation.kind == "references_file":
                        relations.append(Relationship("loads_file", relation.target, location))
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
