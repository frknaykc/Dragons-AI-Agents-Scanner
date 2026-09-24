"""Non-executing Markdown parsing with block/inline structure and line ranges."""

import re
from pathlib import PurePosixPath

from markdown_it import MarkdownIt

from dragonscan.models import (
    Artifact,
    Document,
    Instruction,
    MarkdownBlock,
    Relationship,
    SourceRef,
    Span,
)
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url

_URL = re.compile(r"https?://[^\s<>\[\]()]+", re.I)
_FILE_SUFFIXES = frozenset({".md", ".json", ".yaml", ".yml", ".toml"})
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
                    "code",
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
        is_list = "list_item_open" in container
        is_heading = index > 0 and tokens[index - 1].type == "heading_open"
        kind = (
            "heading"
            if is_heading
            else "quote"
            if is_quote
            else "list_item"
            if is_list
            else "paragraph"
        )
        blocks.append(MarkdownBlock(kind, token.content, location, tuple(spans)))
        if not is_quote:
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
    return Document(
        artifact,
        instructions=tuple(instructions),
        blocks=tuple(blocks),
        relationships=tuple(dict.fromkeys(relations)),
    )
