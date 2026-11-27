"""In-memory script fragments only: no interpreter or fixture is invoked."""

from pathlib import Path

import pytest

from dragonscan.models import (
    Artifact,
    ArtifactKind,
    Document,
    Relationship,
    SourceFormat,
    SourceRef,
)
from dragonscan.script_adapters import parse_script_subset


def parse(suffix: str, text: str) -> Document:
    artifact = Artifact(Path(f"scripts/helper.{suffix}"), ArtifactKind.SCRIPT, SourceFormat.TEXT)
    return parse_script_subset(artifact, text)


@pytest.mark.parametrize(
    ("suffix", "text", "sink"),
    [
        ("sh", '# comment\ncmd="$1"\nvalue=$cmd\n"$value"', "shell command selection"),
        ("bash", '#!/bin/bash\ncmd=$1\nvalue=$cmd\nbash -c "$value"', "shell evaluation"),
        ("zsh", '#!/bin/zsh\ncmd=$1\nvalue=$cmd\neval "$value"', "shell evaluation"),
        ("ps1", "# note\n$cmd = $args[0]\n$value = $CMD\n& $value", "PowerShell command selection"),
        (
            "ps1",
            "# note\n$cmd = $args[0]\n$value = $cmd\nInvoke-Expression $value",
            "PowerShell evaluation",
        ),
        (
            "js",
            "// note\nconst cmd = process.argv[2];\nlet value = cmd;\neval(value);",
            "JavaScript evaluation",
        ),
        (
            "mjs",
            "// note\nconst cmd = process.argv[2];\nconst value = cmd;\neval(value);",
            "JavaScript evaluation",
        ),
        (
            "cjs",
            "// note\nconst cmd = process.argv[2];\nconst value = cmd;\neval(value);",
            "JavaScript evaluation",
        ),
    ],
)
def test_connected_source_preserves_exact_lines_with_only_normalized_labels(
    suffix: str, text: str, sink: str
) -> None:
    doc = parse(suffix, text.replace("\n", "\r\n"))
    assert not doc.diagnostics
    assert doc.relationships == (
        Relationship(
            "code_execution_input",
            "command-line argument",
            SourceRef(doc.artifact.path, SourceFormat.TEXT, 2, 4),
            sink,
        ),
    )


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        ("sh", '''cmd="$1"\ncmd='placeholder'\n"$cmd"'''),
        ("sh", '''cmd='$1'\n"$cmd"'''),
        ("sh", '''cmd="$1"\necho "$cmd"'''),
        ("sh", """# eval "$1"\necho 'eval "$1"' """),
        ("ps1", "$cmd = '$args[0]'\n& $cmd"),
        ("ps1", "$cmd = $args[0]\n$Cmd = 'placeholder'\n& $cmd"),
        ("ps1", "$cmd = $args[0]\nWrite-Output $cmd"),
        ("js", 'const cmd = process.argv[2];\nconst value = "placeholder";\neval(value);'),
        ("js", '// eval(process.argv[2]);\nconsole.log("eval(process.argv[2]);");'),
        ("js", "const cmd = process.argv[2];\nconsole.log(cmd);"),
    ],
)
def test_supported_but_no_input_reaches_executable_position(suffix: str, text: str) -> None:
    doc = parse(suffix, text)
    assert not doc.relationships
    assert not doc.diagnostics


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        ("sh", 'cat <<EOF\n"$1"\nEOF'),
        ("sh", 'note="start\n"$1"\nend"'),
        ("sh", 'eval() { :; }\neval "$1"'),
        ("sh", '"$1"\nif false; then :; fi'),
        ("sh", '#! /other/interpreter\n"$1"'),
        ("sh", '# comment\v"$1"'),
        ("sh", '# comment\u2028"$1"'),
        ("sh", 'cmd=$1\n"$cmd" extra'),
        ("sh", 'cmd=$1\n"$other"'),
        ("ps1", "@'\n& $args[0]\n'@"),
        ("ps1", "<#\n& $args[0]\n#>"),
        ("ps1", '$args = "sample"\n& $args[0]'),
        ("ps1", "function Invoke-Expression {}\nInvoke-Expression $args[0]"),
        ("ps1", "#requires -Version 99\n& $args[0]"),
        ("ps1", '$cmd = "$args[0]"\n& $cmd'),
        ("js", "/*\neval(process.argv[2]);\n*/"),
        ("js", "const value = `\neval(process.argv[2]);\n`;"),
        ("js", "const process = {};\neval(process.argv[2]);"),
        ("js", "const eval = custom;\neval(process.argv[2]);"),
        ("js", 'const cmd = process.argv[2];\nconst cmd = "placeholder";\neval(cmd);'),
        ("js", "eval(process.argv[2]);\nunknown();"),
        ("js", "eval(process.argv[2]); // extra syntax outside grammar"),
        ("js", "eval(process.argv[1]);"),
        ("js", "eval(other);"),
        ("ts", "eval(process.argv[2]);"),
        ("js", "// comment\n" * 5000 + "eval(process.argv[2]);"),
        ("js", "//" + "x" * 10000 + "\neval(process.argv[2]);"),
    ],
)
def test_unsupported_grammar_discards_all_evidence(suffix: str, text: str) -> None:
    doc = parse(suffix, text)
    assert doc.diagnostics
    assert not doc.relationships
