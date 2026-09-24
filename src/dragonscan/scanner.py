"""Scanner orchestration; independent from CLI and report format."""

from collections.abc import Sequence

from dragonscan.discovery import discover
from dragonscan.loading import LoadError, load_text
from dragonscan.models import Artifact, Finding, ScanReport, Target
from dragonscan.parse_errors import ParseError
from dragonscan.parsing import parse
from dragonscan.risk import summarize
from dragonscan.rules import BUILTIN_RULES, Rule


class Scanner:
    def __init__(self, rules: Sequence[Rule] = BUILTIN_RULES):
        identifiers = [rule.detection_id for rule in rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate rule ID")
        self.rules = tuple(rules)

    def scan(self, target: Target) -> ScanReport:
        artifacts = discover(target)
        normalized: list[Artifact] = []
        findings: list[Finding] = []
        errors: list[str] = []
        for artifact in artifacts:
            try:
                document = parse(artifact, load_text(artifact.path))
            except (LoadError, ParseError) as exc:
                errors.append(f"{artifact.path}: {exc}")
                normalized.append(artifact)
                continue
            normalized.append(document.artifact)
            for rule in self.rules:
                findings.extend(rule.detect(document))
        results = tuple(findings)
        risk, counts = summarize(results)
        return ScanReport(target.path, tuple(normalized), results, tuple(errors), risk, counts)


def scan(path: Target) -> ScanReport:
    return Scanner().scan(path)
