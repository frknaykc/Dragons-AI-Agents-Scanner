"""Conservative clause boundaries and authority directives; not a language classifier."""

import re
from collections.abc import Iterator

# Closed quotations can contain punctuation/conjunctions without ending their clause.
_QUOTES = r""""[^"\n]*"|(?<!\w)'[^'\n]*'|“[^“”\n]*”|‘[^‘’\n]*’|`[^`\n]+`"""
_BOUNDARIES = re.compile(
    rf"(?:{_QUOTES})|(?P<sep>(?<=[.!?])\s+|\n+|;[ \t]*|"
    r"(?:,[ \t]*)?\b(?:but|however|instead(?!\s+of\b)|ama|ancak|fakat)\b[, \t]+)",
    re.I,
)
_QUOTED = re.compile(_QUOTES)
_ROLES = r"(?:system|developer|sistem|geliştirici)"
_ROLE = re.compile(rf"^(?:\[{_ROLES}\]\s*:?|{_ROLES}\s*:)\s*", re.I)
_ELEVATE = re.compile(
    r"^(?:treat|use|obey) (?:this (?:message|text|instruction)|these instructions) "
    r"as (?:a |the )?(?:system|developer)(?:-level)? (?:message|instructions?|prompt|directive)\b",
    re.I,
)
_TR_ELEVATE = re.compile(
    r"^bu (?:mesajı|metni) (?:bir )?(?:sistem|geliştirici) talimatı olarak "
    r"(?:kabul et|kabul edin|uygula|uygulayın)[.!?]*$",
    re.I,
)
_PREFIX = r"(?:^|\b(?:and|then)\s+)(?:(?:please|always|you must|immediately|first)\s+)?"
_OVERRIDE = re.compile(
    _PREFIX + r"(?:ignore|disregard|override)\s+(?:(?:all|any|every|the)\s+)?"
    r"(?:previous|prior|system|user|developer|earlier)(?:\s+(?:safety|system|developer))?"
    r"\s+(?:instructions?|rules?|directives?|prompts?)\b",
    re.I,
)
_BYPASS = re.compile(
    _PREFIX + r"(?:disable|bypass|turn off)\s+(?:(?:all|the|your|agent)\s+)?"
    r"(?:(?:safety|security)\s+(?:checks?|controls?|safeguards?|protections?|polic(?:y|ies))|"
    r"(?:security|safety)(?=[.!?,;]|$)|guardrails?|protections?)\b",
    re.I,
)
_TR_OVERRIDE = re.compile(
    r"^(?:lütfen\s+)?(?:(?:tüm|bütün)\s+)?(?:önceki|sistem|geliştirici)\s+"
    r"(?:(?:tüm|güvenlik)\s+)?(?:talimatları|talimatlarını|yönergeleri|kuralları)\s+"
    r"(?:yok say(?:ın)?|görmezden gel(?:in)?)\b",
    re.I,
)
_TR_BYPASS = re.compile(
    r"^(?:lütfen\s+)?(?:güvenlik|emniyet)\s+"
    r"(?:kontrollerini|kurallarını|önlemlerini|denetimlerini)\s+"
    r"(?:devre dışı bırak(?:ın)?|kapat(?:ın)?|atla(?:yın)?)\b",
    re.I,
)
_END_TR = re.compile(r"^[.!?,;:\s]*$")
_DOCUMENTED = re.compile(
    r"^(?:(?:an? |the )?(?:example|documentation|guide|quote|örnek|alıntı|belge)\b|"
    r"(?:read|review|see|print|display|discuss) (?:the |this |an? )?"
    r"(?:example|documentation|quote|string)\b|(?:detect|warn about|describe how to)\b|>)",
    re.I,
)


def clauses(text: str) -> Iterator[tuple[str, int]]:
    start = 0
    for match in _BOUNDARIES.finditer(text):
        if match["sep"] is not None:
            yield text[start : match.start()], start
            start = match.end()
    yield text[start:], start


def documentation(text: str) -> bool:
    return bool(_DOCUMENTED.match(text) or _QUOTED.fullmatch(text.rstrip(".!?")))


def authority_actions(text: str) -> tuple[bool, bool]:
    """A role label alone is not an override. Bind an active verb to a control object."""
    text = _ROLE.sub("", text, count=1)
    if documentation(text) or re.match(r"(?:never|do not|don't|avoid|must not)\b", text, re.I):
        return False, False
    # Content in quotes is not an authority claim by the surrounding text.
    text = _QUOTED.sub(" [quoted] ", text)
    # A coordinated verb requires an imperative antecedent, not a passive description.
    coordinated = (
        re.match(
            r"^(?:read|use|follow|run|disable|ignore|bypass|obey|disregard|override)\b", text, re.I
        )
        is not None
    )
    tr_override = _TR_OVERRIDE.match(text)
    tr_bypass = _TR_BYPASS.match(text)
    return (
        bool(
            _ELEVATE.match(text)
            or _TR_ELEVATE.match(text)
            or (_OVERRIDE.search(text) if coordinated else _OVERRIDE.match(text))
            or (tr_override and _END_TR.match(text[tr_override.end() :]))
        ),
        bool(
            (_BYPASS.search(text) if coordinated else _BYPASS.match(text))
            or (tr_bypass and _END_TR.match(text[tr_bypass.end() :]))
        ),
    )
