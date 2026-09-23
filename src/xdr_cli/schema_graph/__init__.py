"""Versioned semantic field graph for cross-table XDR correlation."""

from xdr_cli.schema_graph.artifact_metadata import nested_fields_from_artifact_metadata
from xdr_cli.schema_graph.catalog import exhaustive_probe_targets
from xdr_cli.schema_graph.correlate import correlate_inputs, load_artifact_input
from xdr_cli.schema_graph.discover import discover_nested_fields
from xdr_cli.schema_graph.effective import (
    EffectiveGraph,
    FieldAvailability,
    compose_effective_graph,
    merge_graphs,
)
from xdr_cli.schema_graph.loader import (
    GraphRegistry,
    load_packaged_graph,
    load_packaged_profile,
)
from xdr_cli.schema_graph.model import (
    GRAPH_SCHEMA_VERSION,
    FieldLocator,
    FieldRecord,
    Graph,
    InterpretationRecord,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    candidate_relationship_from_observation,
    empirical_relationship_from_observations,
)
from xdr_cli.schema_graph.normalize import normalize_value
from xdr_cli.schema_graph.opengraph import export_opengraph
from xdr_cli.schema_graph.overlay import (
    load_tenant_observations,
    load_tenant_overlay,
    publish_tenant_observations,
    publish_tenant_overlay,
)
from xdr_cli.schema_graph.probe import (
    aggregate_observation,
    compile_source_sampling_query,
    compile_target_probe_batches,
    compile_target_probe_query,
)
from xdr_cli.schema_graph.traversal import GraphPath, GraphStep, pivot, table_paths

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "FieldLocator",
    "FieldAvailability",
    "FieldRecord",
    "EffectiveGraph",
    "Graph",
    "GraphRegistry",
    "InterpretationRecord",
    "ObservationRecord",
    "RelationshipKind",
    "RelationshipRecord",
    "RelationshipStatus",
    "candidate_relationship_from_observation",
    "empirical_relationship_from_observations",
    "compose_effective_graph",
    "correlate_inputs",
    "discover_nested_fields",
    "exhaustive_probe_targets",
    "export_opengraph",
    "load_packaged_graph",
    "load_packaged_profile",
    "load_artifact_input",
    "load_tenant_observations",
    "load_tenant_overlay",
    "merge_graphs",
    "nested_fields_from_artifact_metadata",
    "normalize_value",
    "aggregate_observation",
    "compile_source_sampling_query",
    "compile_target_probe_batches",
    "compile_target_probe_query",
    "GraphPath",
    "GraphStep",
    "pivot",
    "publish_tenant_observations",
    "publish_tenant_overlay",
    "table_paths",
]
