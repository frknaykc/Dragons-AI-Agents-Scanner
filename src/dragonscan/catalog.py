"""IDs emitted by scan stages without rule, signature or provider metadata.

The offline inventory test compares these reservations with actual emitter sites.
Extension registration must not depend on reading package source at runtime.
"""

STAGE_IDS = frozenset(
    {
        "DRAGON-PATH-001",
        "DRAGON-PATH-002",
        "DRAGON-PATH-003",
        "DRAGON-PATH-004",
        "DRAGON-FLOW-001",
        "DRAGON-FLOW-002",
        "DRAGON-MCP-012",
        "DRAGON-SC-001",
        "DRAGON-SC-002",
        "DRAGON-SC-003",
        "DRAGON-SC-004",
        "DRAGON-SC-005",
        "DRAGON-SC-006",
        "DRAGON-SC-007",
    }
)
