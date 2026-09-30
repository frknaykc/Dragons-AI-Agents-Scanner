"""Offline inventory of built-in detection IDs and explicitly asserted benchmark coverage.

Run: uv run --offline python -m scripts.coverage_inventory [manifest] --format json
No corpus artifacts are executed, scanned, or sent to a provider by this command.
"""

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any

from dragonscan.detectors import BUILTIN_DETECTORS, SourceSinkDetector
from dragonscan.rules import BUILTIN_RULES
from dragonscan.semantic import _CATEGORIES
from dragonscan.signatures import BUILTIN_SIGNATURES
from dragonscan.threat_intel import INTELLIGENCE_IDS
from dragonscan.vulnerability import VULNERABILITY_IDS

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "benchmarks/corpus/manifest.json"
_ID = re.compile(r"(?:DAAS|DRAGON-[A-Z]+)-\d{3}\Z", re.ASCII)
# Scanner emission sites not exposed as detector objects. These are source modules,
# not a maintained parallel list of detection IDs. Literal references in other
# modules are deliberately not treated as implementations.
_EMITTER_MODULES = ("correlation", "mcp_correlation", "flow", "supply_chain")


def _emitted_literals(module: str) -> set[str]:
    tree = ast.parse((ROOT / "src/dragonscan" / f"{module}.py").read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        # Follow actual finding construction rather than collecting IDs from
        # references, suppression lists or enrichment lookup tables.
        candidates: tuple[ast.expr, ...]
        if node.func.id == "emit" and node.args:
            candidates = (node.args[0],)
        elif node.func.id == "_finding" and len(node.args) > 1:
            candidates = (node.args[1],)
        elif node.func.id == "Finding":
            candidates = tuple(kw.value for kw in node.keywords if kw.arg == "detection_id")
        else:
            continue
        for candidate in candidates:
            for value in ast.walk(candidate):
                if (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and _ID.fullmatch(value.value)
                ):
                    emitted.add(value.value)
    return emitted


def builtin_registry() -> dict[str, str]:
    """Discover IDs from real rule/detector/signature metadata and scanner emitters."""
    sources: dict[str, str] = {}

    def add(identifier: str, origin: str) -> None:
        if identifier in sources and sources[identifier] != origin:
            raise ValueError(f"duplicate built-in ID: {identifier}")
        sources[identifier] = origin

    for rule in BUILTIN_RULES:
        add(rule.detection_id, "rule")
    for detector in BUILTIN_DETECTORS:
        add(detector.metadata.detection_id, "detector")
        if isinstance(detector, SourceSinkDetector):
            add(detector.access_metadata.detection_id, "detector")
    for signature in BUILTIN_SIGNATURES:
        add(signature.detection_id, "builtin_signature")
    for module in _EMITTER_MODULES:
        for identifier in sorted(_emitted_literals(module)):
            if identifier not in sources:
                add(identifier, f"scanner:{module}")
    for identifier, _title in _CATEGORIES.values():
        add(identifier, "semantic")
    for identifier in VULNERABILITY_IDS:
        add(identifier, "osv")
    for identifier in INTELLIGENCE_IDS:
        add(identifier, "threat_intel")
    return dict(sorted(sources.items()))


def _manifest_cases(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256_000:
        raise ValueError("invalid manifest file")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest key")
            result[key] = value
        return result

    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported manifest schema")
    cases = data.get("cases")
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        raise ValueError("invalid manifest cases")
    return cases


def _expected_findings(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Use only structured assertions; a bare expected ID is not an occurrence check."""
    findings = case.get("expected_findings", [])
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    return []


def inventory(manifest: Path | None = DEFAULT_MANIFEST) -> dict[str, Any]:
    registry = builtin_registry()
    cases = _manifest_cases(manifest)
    rows: dict[str, dict[str, Any]] = {}
    route_ids = set().union(
        *(_emitted_literals(module) for module in ("correlation", "mcp_correlation", "flow"))
    )
    for identifier, origin in registry.items():
        group = origin if origin in ("semantic", "osv", "threat_intel") else "default"
        rows[identifier] = {
            "implementation_exists": True,
            "implementation_origin": origin,
            "execution_group": group,
            "unit_positive": None,
            "unit_negative": None,
            "benchmark_positive": False,
            "benchmark_hard_negative": False,
            "development": False,
            "holdout": False,
            "occurrence_assertion": False,
            "source_sink_assertion": False,
            "graph_path_applicable": identifier in route_ids,
            "graph_path_assertion": False,
            "positive_cases": [],
            "hard_negative_cases": [],
        }
    for case in cases:
        name = case.get("id")
        split = case.get("split")
        expected = case.get("expected", [])
        if not isinstance(name, str) or split not in ("development", "holdout"):
            raise ValueError("invalid case metadata")
        if not isinstance(expected, list) or any(item not in rows for item in expected):
            raise ValueError("unknown expected ID")
        for identifier in expected:
            row = rows[identifier]
            row["benchmark_positive"] = True
            row[split] = True
            row["positive_cases"].append(name)
        # A benign case is not a per-ID hard negative. Only explicitly named
        # negative assertions count; never infer them from absence of findings.
        absent = case.get("expected_absent", [])
        if not isinstance(absent, list) or any(item not in rows for item in absent):
            raise ValueError("unknown hard-negative ID")
        for identifier in absent:
            rows[identifier]["benchmark_hard_negative"] = True
            rows[identifier]["hard_negative_cases"].append(name)
        for finding in _expected_findings(case):
            finding_id = finding.get("id", finding.get("detection_id"))
            if not isinstance(finding_id, str) or finding_id not in expected:
                raise ValueError("occurrence assertion without expected ID")
            row = rows[finding_id]
            # The occurrence itself must be located, not merely repeat the ID.
            row["occurrence_assertion"] |= any(
                finding.get(field) is not None for field in ("artifact", "line", "occurrence")
            )
            row["source_sink_assertion"] |= "source" in finding or "sink" in finding
            row["graph_path_assertion"] |= any(
                field in finding
                for field in ("path_edges", "path_nodes", "flow_edges", "flow_nodes")
            )
    for row in rows.values():
        row["positive_cases"].sort()
        row["hard_negative_cases"].sort()
    default = [i for i, row in rows.items() if row["execution_group"] == "default"]
    uncovered = [i for i in default if not rows[i]["benchmark_positive"]]
    return {
        "schema_version": 1,
        "manifest": str(manifest) if manifest is not None and manifest.exists() else None,
        "summary": {
            "built_in_ids": len(rows),
            "default_ids": len(default),
            "default_benchmark_positive": len(default) - len(uncovered),
            "default_uncovered_count": len(uncovered),
            "default_uncovered_ids": uncovered,
            "opt_in_ids": [i for i in rows if i not in default],
            "dynamic_signature_ids": (
                "not enumerable: user-supplied signature packs are runtime-defined"
            ),
        },
        "ids": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--format", choices=("json",), default="json")
    args = parser.parse_args()
    try:
        result = inventory(args.manifest)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
