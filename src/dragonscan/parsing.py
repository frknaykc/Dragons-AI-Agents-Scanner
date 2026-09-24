"""Static parser dispatch by source format, independent from CLI and detectors."""

from collections.abc import Callable

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


def parse(artifact: Artifact, text: str) -> Document:
    parser = PARSERS.get(artifact.source_format)
    if parser is None:
        raise ParseError("unsupported source format")
    return parser(artifact, text)
