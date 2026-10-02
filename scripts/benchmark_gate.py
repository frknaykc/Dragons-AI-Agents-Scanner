"""Lock the offline development corpus regression (not a production accuracy claim)."""

import argparse
import json
from pathlib import Path


def check(result: dict[str, object]) -> bool:
    summary = result["summary"]
    correctness = result["correctness"]
    coverage = result["coverage"]
    if (
        not isinstance(summary, dict)
        or not isinstance(correctness, dict)
        or not isinstance(coverage, dict)
    ):
        return False
    return (
        result["status"] == "completed"
        and summary["evaluated_cases"] == 48
        and summary["failed_cases"] == 0
        and summary["tp"] == 50
        and summary["fp"] == 0
        and summary["fn"] == 0
        and correctness["failed"] == 0
        and coverage["total_rules"] == 46
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        result = json.loads(args.report.read_text(encoding="utf-8"))
        passed = check(result)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print("Benchmark v2 baseline: PASS" if passed else "Benchmark v2 baseline: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
