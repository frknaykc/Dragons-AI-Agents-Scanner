"""All sample programs are inert strings passed only to the static parser."""

from pathlib import Path
from unittest.mock import patch

import pytest

from dragonscan.models import Artifact, ArtifactKind, Relationship, SourceFormat, SourceRef
from dragonscan.python_script import parse_python_script

SCRIPT = Artifact(Path("scripts/example.py"), ArtifactKind.SCRIPT, SourceFormat.TEXT)


@pytest.mark.parametrize(
    ("program", "source", "sink", "first", "last"),
    [
        ("x = input('private-prompt')\ny = x\nresult = eval(y)", "input()", "eval", 1, 3),
        ("import sys as s\nexec(s.argv[2])", "sys.argv", "exec", 2, 2),
        (
            "from sys import argv as a\nfrom os import system as f\nf(a[1])",
            "sys.argv",
            "os.system",
            3,
            3,
        ),
        (
            "import subprocess as sp\nx = input()\nsp.run([x, 'private'])",
            "input()",
            "subprocess.run",
            2,
            3,
        ),
        ("from subprocess import Popen as f\nf(args=input())", "input()", "subprocess.Popen", 2, 2),
        (
            "import subprocess as sp\nsp.run(['fixed'], executable=input())",
            "input()",
            "subprocess.run",
            2,
            2,
        ),
        (
            "import subprocess\nsubprocess.run(input(), shell=True)",
            "input()",
            "subprocess.run",
            2,
            2,
        ),
    ],
)
def test_explicit_source_and_argument_only(
    program: str, source: str, sink: str, first: int, last: int
) -> None:
    doc = parse_python_script(SCRIPT, program)
    assert doc.relationships == (
        Relationship(
            "code_execution_input",
            source,
            SourceRef(SCRIPT.path, SCRIPT.source_format, first, last),
            sink,
        ),
    )
    assert "private" not in repr(doc)


@pytest.mark.parametrize(
    "program",
    [
        "# eval(input())\n'os.system(input())'",
        "x = input()\nx = 'fixed'\neval(x)",
        "input = 'other'\neval(input())",
        "eval = input\neval(input())",
        "from other import exec\nexec(input())",
        "os.system(input())",
        "import subprocess as sp\nsp = 42\nsp.run(input())",
        "import os as a\nimport os as b\na.system = fake\nb.system(input())",
        "import sys\nsys.argv[1] = 'fixed'\neval(sys.argv[1])",
        "import sys\neval(sys.argv[0])",
        "import sys\neval(sys.argv[False])",
        "eval([input()])",
        "import os\nos.system([input()])",
        "import subprocess\nsubprocess.run(['fixed', input()])",
        "import subprocess\nsubprocess.run([input()], executable='fixed')",
        "import subprocess\nsubprocess.run('fixed', input=input())",
        "eval('fixed', {'data':input()})",
        "if False:\n    eval(input())",
        "def f():\n    exec(input())",
        "import os\nraise RuntimeError\nos.system(input())",
    ],
)
def test_no_unsupported_or_unrelated_flow(program: str) -> None:
    assert not parse_python_script(SCRIPT, program).relationships


@pytest.mark.parametrize(
    "program",
    [
        "if flag:\n    eval(input())",
        "value = getattr(thing, 'private-name')()\neval(value)",
        "value = transform(input())\neval(value)",
        "from unknown import *\neval(input())",
        "eval(input(",
    ],
)
def test_unknowns_are_partial_without_raw_code(program: str) -> None:
    doc = parse_python_script(SCRIPT, program)
    assert not doc.relationships
    assert any("partial" in reason for reason in doc.diagnostics)
    assert "private-name" not in repr(doc)


@pytest.mark.parametrize(
    "program",
    ["#" + "é" * 33_000, "(" * 100 + "1" + ")" * 100, "not " * 600 + "x", "pass\n" * 9000],
    ids=["utf8-bytes", "nesting", "logical-line", "total-tokens"],
)
def test_preflight_bounds_reject_before_ast(program: str) -> None:
    with patch("dragonscan.python_script.ast.parse", side_effect=AssertionError("too late")):
        doc = parse_python_script(SCRIPT, program)
    assert not doc.relationships
    assert any("limit" in reason for reason in doc.diagnostics)


def test_ast_node_budget_rejects_whole_document() -> None:
    with patch("dragonscan.python_script.MAX_AST_NODES", 5):
        doc = parse_python_script(SCRIPT, "x = input()\neval(x)")
    assert not doc.relationships
    assert any("limit" in reason for reason in doc.diagnostics)


def test_comments_do_not_exhaust_logical_line_budget() -> None:
    doc = parse_python_script(SCRIPT, "# licence text\n" * 200 + "eval(input())")
    assert len(doc.relationships) == 1
    assert not doc.diagnostics


def test_partial_retains_only_proven_prefix() -> None:
    doc = parse_python_script(
        SCRIPT, "import os\nos.system(input())\nunknown()\nos.system(input())"
    )
    assert len(doc.relationships) == 1
    assert doc.relationships[0].location.line == 2
    assert any("partial" in reason for reason in doc.diagnostics)


def test_dynamic_code_is_a_binding_barrier() -> None:
    doc = parse_python_script(SCRIPT, "exec('eval = None')\neval(input())")
    assert not doc.relationships
    assert doc.diagnostics


@pytest.mark.parametrize("operation", ["call", "check_call", "check_output"])
def test_subprocess_wrappers(operation: str) -> None:
    doc = parse_python_script(SCRIPT, f"from subprocess import {operation} as f\nf((input(),))")
    assert [r.subject for r in doc.relationships] == [f"subprocess.{operation}"]
