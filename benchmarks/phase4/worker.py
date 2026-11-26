"""Isolated process for the Phase 4 experiment; never import or execute a target."""

import base64
import binascii
import importlib.metadata
import json
import platform
import resource
import sys
import time
from pathlib import Path

import yara_x

MAX_RULE_BYTES = 16_384
MAX_INPUT_BYTES = 1_048_576
MAX_ENVELOPE_BYTES = 1_400_000
REPEATS = 40


def limits() -> dict[str, object]:
    resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
    address_space = False
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        address_space = True
    # Darwin rejects the tested RLIMIT_AS/RLIMIT_DATA cap. Do not claim a memory sandbox.
    return {"cpu_seconds": 2, "address_space_bytes": 1024**3 if address_space else None}


def compile_rules(source: str) -> tuple[yara_x.Rules, float]:
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)
    start = time.perf_counter_ns()
    compiler.add_source(source)
    rules = compiler.build()
    return rules, (time.perf_counter_ns() - start) / 1e6


def main() -> None:
    active_limits = limits()
    raw = sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope limit")
    request = json.loads(raw)
    if request.get("operation") == "include_rejection":
        try:
            compile_rules('include "not-loaded.yar"\nrule test { condition: true }')
        except yara_x.CompileError:
            print(json.dumps({"includes_rejected": True, "limits": active_limits}))
            return
        raise AssertionError("includes were accepted")
    if request.get("operation") != "scan":
        raise ValueError("unknown operation")
    data = base64.b64decode(request["data"], validate=True)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input limit")
    source = Path(__file__).with_name("rules.yar").read_bytes()
    if len(source) > MAX_RULE_BYTES:
        raise ValueError("rule source limit")
    rules, compile_ms = compile_rules(source.decode("utf-8"))
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(1)
    scanner.max_matches_per_pattern(16)
    durations = []
    identifiers = set()
    locations: dict[str, list[dict[str, int]]] = {}
    for _ in range(REPEATS):
        start = time.perf_counter_ns()
        result = scanner.scan(data)
        durations.append((time.perf_counter_ns() - start) / 1e6)
        for match in result.matching_rules:
            identifiers.add(match.identifier)
            if match.identifier not in locations:
                locations[match.identifier] = [
                    {"offset": occurrence.offset, "length": occurrence.length}
                    for pattern in match.patterns
                    for occurrence in pattern.matches
                ][:16]
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(
        json.dumps(
            {
                "version": importlib.metadata.version("yara-x"),
                "platform": platform.system(),
                "rules": sorted(identifiers),
                "locations": locations,
                "compile_ms": compile_ms,
                "scan_ms": durations,
                "peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
                "limits": active_limits,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
        binascii.Error,
        yara_x.CompileError,
        yara_x.ScanError,
        yara_x.TimeoutError,
    ) as exc:
        print(json.dumps({"error_type": type(exc).__name__}))
        raise SystemExit(2) from None
