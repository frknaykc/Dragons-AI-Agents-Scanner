"""Static parser dispatch by source format, independent from CLI and detectors."""

from collections.abc import Callable
from dataclasses import replace

from dragonscan.dependencies import (
    parse_npmrc,
    parse_requirements,
    parse_yarn,
    runtime_dependencies,
)
from dragonscan.markdown_parser import parse_markdown
from dragonscan.models import Artifact, Document, SourceFormat
from dragonscan.parse_errors import ParseError
from dragonscan.structured_parser import parse_structured

Parser = Callable[[Artifact, str], Document]
PARSERS: dict[SourceFormat, Parser] = {
    SourceFormat.MARKDOWN: parse_markdown,
    SourceFormat.JSON: parse_structured,
    SourceFormat.YAML: parse_structured,
    SourceFormat.TOML: parse_structured,
}


def parse(artifact: Artifact, text: str, *, allow_bare_mcp: bool = True) -> Document:
    if artifact.source_format == SourceFormat.TEXT:
        name = artifact.path.name.lower()
        if name == ".npmrc":
            return parse_npmrc(artifact, text)
        if name == "yarn.lock":
            return parse_yarn(artifact, text)
        return parse_requirements(artifact, text)
    parser = PARSERS.get(artifact.source_format)
    if parser is None:
        raise ParseError("unsupported source format")
    document = (
        parse_structured(artifact, text, allow_bare_mcp=allow_bare_mcp)
        if artifact.source_format in {SourceFormat.JSON, SourceFormat.YAML, SourceFormat.TOML}
        else parser(artifact, text)
    )
    if document.servers or document.blocks:
        document = replace(
            document, dependencies=(*document.dependencies, *runtime_dependencies(document))
        )
    return document
