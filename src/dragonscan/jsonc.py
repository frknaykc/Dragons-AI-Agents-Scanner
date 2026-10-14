"""Bounded, string-aware JSONC preprocessing for known Kilo config files only."""

import json
from typing import Any

from dragonscan.parse_errors import ParseError

MAX_JSONC_CHARS = 1_048_576


def clean_jsonc(text: str) -> str:
    """Mask comments/trailing commas without moving any surviving character or newline."""
    if len(text) > MAX_JSONC_CHARS:
        raise ParseError("JSONC exceeds parser size limit")
    chars = list(text)
    index = 0
    state = "normal"
    while index < len(chars):
        char = text[index]
        following = text[index + 1] if index + 1 < len(chars) else ""
        if state == "string":
            if char == "\\":
                index += 2  # The JSON decoder validates the escape and the closing quote.
                continue
            if char == '"':
                state = "normal"
        elif state == "line":
            if char in "\r\n":
                state = "normal"
            else:
                chars[index] = " "
        elif state == "block":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "normal"
                continue
            if char not in "\r\n":
                chars[index] = " "
        elif char == '"':
            state = "string"
        elif char == "/" and following in {"/", "*"}:
            chars[index] = chars[index + 1] = " "
            index += 2
            state = "line" if following == "/" else "block"
            continue
        index += 1
    if state == "block":
        raise ParseError("invalid JSONC: unterminated block comment")
    if state == "string":
        raise ParseError("invalid JSONC: unterminated string")
    index = 0
    in_string = False
    while index < len(chars):
        char = chars[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ",":
            cursor = index + 1
            while cursor < len(chars) and chars[cursor].isspace():
                cursor += 1
            if cursor < len(chars) and chars[cursor] in "]}":
                chars[index] = " "
        index += 1
    return "".join(chars)


def load_jsonc(text: str, unique_pairs: Any, reject_constant: Any) -> tuple[Any, str]:
    sanitized = clean_jsonc(text)
    if not sanitized.strip():
        raise ParseError("empty JSONC configuration")
    depth = 0
    in_string = False
    index = 0
    while index < len(sanitized):
        char = sanitized[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > 64:
                raise ParseError("JSONC exceeds parser nesting limit")
        elif char in "}]":
            depth -= 1
        index += 1
    try:
        data = json.loads(sanitized, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSONC at line {exc.lineno}") from exc
    return data, sanitized
