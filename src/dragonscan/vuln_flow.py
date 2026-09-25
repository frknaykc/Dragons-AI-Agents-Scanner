"""Opt-in OSV context for a proven, exact-version runtime execution route."""

from dragonscan.attack_graph import AttackGraph, node_id
from dragonscan.flow import FlowEngine, FlowKind
from dragonscan.models import Dependency, FlowEvidence, PathStep


def runtime_route(
    dependency: Dependency, graph: AttackGraph, advisory_id: str
) -> tuple[tuple[PathStep, ...], FlowEvidence | None]:
    """Never traverse affected_by or join another version's execution edge."""
    package = node_id("package", f"{dependency.ecosystem}:{dependency.name}")
    artifact = node_id("artifact", str(dependency.location.path))
    engine = FlowEngine(graph)
    if engine.blocked:
        return (), None
    installation = next(
        (
            edge
            for edge in graph.edges
            if edge.source == artifact
            and edge.target == package
            and edge.kind == "installs"
            and edge.location == dependency.location
            and edge.origin == "dependency_parser"
            and edge.resolution == "observed"
        ),
        None,
    )
    if installation is None:
        return (), None
    for execution in graph.edges:
        if (
            execution.source != package
            or execution.kind != "executes"
            or execution.location != dependency.location
            or execution.origin != "dependency_parser"
            or execution.resolution != "observed"
        ):
            continue
        for route in engine.paths(FlowKind.EXECUTION, package, execution.target):
            if route.edges != (execution,):
                continue
            steps = tuple(
                PathStep(
                    edge.kind,
                    engine.nodes[edge.source].label,
                    engine.nodes[edge.target].label,
                    edge.location.path,
                    edge.location.line,
                    edge.origin,
                    edge.confidence,
                )
                for edge in (installation, execution)
            )
            return steps, FlowEvidence(
                "exact_runtime_dependency",
                "process_execution",
                ("instruction artifact", "versioned package", "process command"),
                ("installs", "executes"),
                (dependency.location.path,),
                ("registry-to-runtime", "package-to-process"),
                ("runtime-execution",),
                (),
                (f"vulnerability:{advisory_id}",),
                route.confidence,
                (dependency.location,),
                f"{dependency.ecosystem}:{dependency.name}@{dependency.exact_version}",
                "process execution",
            )
    return (), None
