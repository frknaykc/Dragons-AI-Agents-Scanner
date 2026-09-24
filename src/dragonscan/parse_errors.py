"""Controlled diagnostics for untrusted input; never include source text or secrets."""


class ParseError(ValueError):
    """A supported artifact contains invalid or excessively complex input."""
