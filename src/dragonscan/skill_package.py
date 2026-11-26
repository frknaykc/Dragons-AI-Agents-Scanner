"""Static, bounded readers used only inside a selected skill package."""

import re
from pathlib import Path

from dragonscan.behavior import (
    literal_encoded_pipeline,
    remote_python_pipeline,
    remote_shell_pipeline,
)
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    Document,
    Relationship,
    SourceFormat,
    SourceRef,
)
from dragonscan.parse_errors import ParseError
from dragonscan.parse_helpers import safe_url

SCRIPT_SUFFIXES = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".ps1",
        ".cmd",
        ".bat",
        ".rb",
        ".pl",
    }
)
DATA_SUFFIXES = frozenset({".txt", ".json", ".yaml", ".yml", ".toml"})
BINARY_SUFFIXES = frozenset({".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".wasm", ".jar"})
PRIVATE_DIRS = frozenset(
    {"credentials", "secrets", "keystores", "keychains", "sessions", "history", "cache"}
)
_PRIVATE_NAME = re.compile(
    r"(?:^|[._-])(?:auth|secrets?|credentials?|keychain|keystore|tokens?|passwords?|id_rsa|id_ed25519)(?:[._-]|$)",
    re.I,
)


def private_member(name: str) -> bool:
    return name.startswith(".") or bool(_PRIVATE_NAME.search(name))


def package_member(path: Path) -> Artifact | None:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return Artifact(path, ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN)
    if suffix in SCRIPT_SUFFIXES:
        return Artifact(path, ArtifactKind.SCRIPT, SourceFormat.TEXT)
    if suffix in DATA_SUFFIXES:
        return Artifact(path, ArtifactKind.PACKAGE_DATA, SourceFormat.TEXT)
    return None


def one_endpoint(command: str) -> str | None:
    """Only call for an already-proven remote execution observation."""
    matches = re.findall(r"https?://[^\s<>|)'\"]+", command, re.I)
    if len(matches) != 1:
        return None
    try:
        return safe_url(matches[0])
    except ParseError:
        return None


def parse_script(artifact: Artifact, text: str) -> Document:
    # Recognize one literal top-level pipeline, not commands hidden in strings,
    # heredocs, branches, functions, unreachable statements or another language.
    if artifact.path.suffix.lower() in {".sh", ".bash", ".zsh"}:
        statement = None
        for line, physical in enumerate(text.splitlines(), 1):
            command = physical.strip()
            if not command or command.startswith("#"):
                continue
            if statement is not None:
                break
            statement = (line, command)
        else:
            if statement is None:
                return Document(artifact)
            line, command = statement
            location = SourceRef(artifact.path, artifact.source_format, line, line)
            sink = literal_encoded_pipeline(command)
            if sink:
                return Document(
                    artifact,
                    relationships=(
                        Relationship("decoded_program", "literal encoded input", location, sink),
                    ),
                )
            if remote_python_pipeline(command) or remote_shell_pipeline(command):
                sink = (
                    "Python interpreter execution"
                    if remote_python_pipeline(command)
                    else "shell execution"
                )
                endpoint = one_endpoint(command)
                if endpoint:
                    return Document(
                        artifact,
                        relationships=(Relationship("remote_program", endpoint, location, sink),),
                    )
    return Document(
        artifact, diagnostics=("skill package script inventoried; program semantics unsupported",)
    )
