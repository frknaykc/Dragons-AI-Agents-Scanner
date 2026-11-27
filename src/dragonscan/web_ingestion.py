"""Offline web captures. Map inert, isolated text views back to the original evidence."""

import hashlib
import html
import re
import tempfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dragonscan.domain_evidence import EvidenceError, hostname, object_json
from dragonscan.loading import load_text_with_bytes
from dragonscan.models import Artifact, ArtifactKind, SourceFormat, Target
from dragonscan.scan_budget import ScanLimits
from dragonscan.scanner import Scanner

Location = dict[str, int | str]
_URL = re.compile(r"https?://[^\s<>\[\]()\"']+", re.I)
MAX_LINES = 8192
MAX_DOMAINS = 256
MAX_FINDINGS = 256
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_STYLE = re.compile(
    r"(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important\s*)?(?:;|$)", re.I
)


@dataclass
class View:
    lines: list[str] = field(default_factory=list)
    locations: list[Location] = field(default_factory=list)

    def add(self, text: str, where: Location) -> None:
        if len(self.lines) >= MAX_LINES or len(text) > 16384:
            raise EvidenceError("text view exceeds line or line-length limit")
        self.lines.append(text)
        self.locations.append(where)


@dataclass
class Capture:
    views: list[View] = field(default_factory=list)
    domains: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: set[str] = field(default_factory=set)

    def urls(self, text: str, where: Location) -> None:
        for match in _URL.finditer(text):
            try:
                host = hostname(urlsplit(match.group().rstrip(".,;!")).hostname)
            except ValueError:
                continue
            if len(self.domains) == MAX_DOMAINS:
                self.diagnostics.add("domain observation limit reached")
                return
            self.domains.append({"host": host, "location": where})


class _HTML(HTMLParser):
    def __init__(self, capture: Capture, view: View):
        super().__init__(convert_charrefs=False)
        self.capture = capture
        self.view = view
        self.stack: list[tuple[str, str]] = []
        self.new_block = True

    @property
    def context(self) -> str:
        return self.stack[-1][1] if self.stack else "text"

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.stack) >= 128:
            raise EvidenceError("HTML nesting limit reached")
        d = dict(attrs)
        line = self.getpos()[0]
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                self.capture.urls(value, {"line": line, "context": f"attribute:{key}"})
        context = self.context
        if context == "excluded" or tag in {"script", "style"}:
            context = "excluded"
        elif context == "quoted" or tag in {"blockquote", "code", "pre"}:
            context = "quoted"
        elif (
            context == "hidden"
            or tag == "template"
            or "hidden" in d
            or (d.get("aria-hidden") or "").lower() == "true"
            or _STYLE.search(d.get("style") or "")
        ):
            context = "hidden"
        if tag not in _VOID:
            self.stack.append((tag, context))
        if tag in {"p", "div", "li", "br", "hr", "table", "article", "section"}:
            self.new_block = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        if tag in {"p", "div", "li", "table", "article", "section"}:
            self.new_block = True

    def _text(self, data: str, context: str) -> None:
        if context == "excluded":
            return
        for offset, line in enumerate(data.split("\n")):
            if not line:
                continue
            where: Location = {"line": self.getpos()[0] + offset, "context": context}
            if self.view.locations and not self.new_block and self.view.locations[-1] == where:
                if len(self.view.lines[-1]) + len(line) > 16384:
                    raise EvidenceError("HTML text exceeds line-length limit")
                self.view.lines[-1] += line
            else:
                if self.view.locations and (
                    self.new_block or self.view.locations[-1].get("context") != context
                ):
                    self.view.add("", where)
                self.view.add("> " + line if context == "quoted" else line, where)
            self.new_block = False

    def handle_data(self, data: str) -> None:
        self._text(data, self.context)

    def handle_comment(self, data: str) -> None:
        self.new_block = True
        self._text(data, "comment")
        self.new_block = True

    def handle_entityref(self, name: str) -> None:
        self._text(
            html.unescape("&" + name + ";").replace("\n", " ").replace("\r", " "), self.context
        )

    def handle_charref(self, name: str) -> None:
        self.handle_entityref("#" + name)


def _views(kind: str, text: str) -> Capture:
    # Normalize real line endings once; the reported lines remain original-file coordinates.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    capture = Capture()
    if kind == "search":
        records = object_json(text).get("results")
        if not isinstance(records, list) or len(records) > 32:
            raise EvidenceError("expected a results array of at most 32 entries")
        for i, record in enumerate(records):
            if not isinstance(record, dict) or not any(
                k in record for k in ("url", "title", "snippet")
            ):
                raise EvidenceError("unsupported recorded search result")
            for key in ("url", "title", "snippet"):
                if key not in record:
                    continue
                field_text = record[key]
                if not isinstance(field_text, str) or any(
                    ord(c) < 32 and c not in "\n\r\t" or 0xD800 <= ord(c) <= 0xDFFF
                    for c in field_text
                ):
                    raise EvidenceError("expected a text search field")
                where: Location = {"pointer": f"/results/{i}/{key}"}
                capture.urls(field_text, where)
                if key != "url":
                    view = View()
                    for line in field_text.splitlines():
                        view.add(line, where)
                    capture.views.append(view)
        return capture
    view = View()
    capture.views.append(view)
    if kind == "html":
        parser = _HTML(capture, view)
        try:
            parser.feed(text)
            parser.close()
        except EvidenceError:
            raise
        except (AssertionError, RecursionError, ValueError):
            raise EvidenceError("unsupported HTML declaration or depth") from None
    else:
        for i, line in enumerate(text.splitlines(), 1):
            view.add(line, {"line": i, "context": "markdown"})
    for line, where in zip(view.lines, view.locations, strict=True):
        capture.urls(line, where)
    return capture


def inspect_web(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm"}:
        kind = "html"
    elif path.name.lower() in {"readme", "readme.md", "readme.markdown", "readme.txt"}:
        kind = "readme"
    elif suffix == ".json":
        kind = "search"
    else:
        raise EvidenceError("expected a local HTML file, README or recorded search JSON")
    text, raw = load_text_with_bytes(path)
    capture = _views(kind, text)
    findings: list[dict[str, Any]] = []
    # No user-controlled names/siblings enter discovery or graph resolution. Each field is
    # independent: one search result cannot complete another result's source-to-sink path.
    scanner = Scanner(limits=ScanLimits(max_findings=MAX_FINDINGS, max_artifacts=1))
    with tempfile.TemporaryDirectory(prefix="dragonscan-web-") as directory:
        projected = Path(directory) / "capture.md"
        art = Artifact(projected, ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN, "Web capture")
        for view in capture.views:
            if not view.lines:
                continue
            if len(findings) == MAX_FINDINGS:
                capture.diagnostics.add("finding limit reached")
                break
            projected.write_text("\n".join(view.lines), encoding="utf-8")
            report = scanner.scan(Target(projected), artifacts=(art,))
            if report.errors or any(d.incomplete for d in report.diagnostics):
                capture.diagnostics.add("scanner coverage incomplete for extracted text")
            for f in report.findings:
                if len(findings) >= MAX_FINDINGS:
                    capture.diagnostics.add("finding limit reached")
                    break
                where = (
                    view.locations[f.line - 1]
                    if f.line and 0 < f.line <= len(view.locations)
                    else {}
                )
                findings.append(
                    {
                        "id": f.detection_id,
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "location": where,
                    }
                )
    return {
        "source": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "kind": kind,
        "coverage": "partial" if capture.diagnostics else "complete",
        "diagnostics": sorted(capture.diagnostics),
        "domains": capture.domains,
        "findings": findings,
    }
