"""Which intelligence evidence may contribute to policy (never grants launch permission)."""

from dragonscan.models import Finding

ACTIVE_INTEL_CONTEXTS = frozenset(
    {"mcp_endpoint", "remote_endpoint", "executable_command", "runtime_package", "mcp_package"}
)


def policy_eligible(finding: Finding) -> bool:
    if finding.signature and finding.signature.pack != "Dragons Built-in":
        return False  # Pack metadata is not publisher authentication.
    if finding.intelligence:
        if finding.intelligence.context not in ACTIVE_INTEL_CONTEXTS | {"artifact_hash"}:
            return False  # A mere declaration or documentation mention is not an action.
        return any(
            source.trust in {"authenticated", "authenticated_reviewed"}
            for source in finding.intelligence.sources
        )
    return True
