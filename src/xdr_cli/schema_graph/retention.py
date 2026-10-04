"""Retire automatic discovery evidence without weakening explicit evidence pins."""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

AUTOMATIC_STAGES = frozenset({'local-overlap', 'local-validation', 'identifier-search'})


class MetadataIndex(defaultdict):
    def __init__(self):
        super().__init__(list)
        self.created_times = {}


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('evidence timestamp must be timezone-aware')
    return parsed


def index_result_metadata(results_root):
    """One directory traversal per locked publication/prune operation."""
    paths = MetadataIndex()
    for path in results_root.glob('*/*.meta.json'):
        paths[path.name.removesuffix('.meta.json')].append(path)
    return paths


def retired_observation(observation, cutoff, results_root, *, metadata_paths=None):
    if cutoff is None or observation.extra.get('evidence_stage') not in AUTOMATIC_STAGES:
        return False
    if metadata_paths is None:
        metadata_paths = index_result_metadata(results_root)
    for run in observation.evidence_run_ids:
        paths = metadata_paths.get(run, ())
        if len(paths) != 1:
            return True
        times = getattr(metadata_paths, 'created_times', {})
        try:
            if run not in times:
                meta = json.loads(paths[0].read_text())
                times[run] = timestamp(meta['created_at'])
            created = times[run]
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            # An invalid automatic reference is not a retention authority.
            # Explicit observations/proposals are handled separately, fail closed.
            times[run] = None
            return True
        if created is None or created < cutoff:
            return True
    return False


def retirement_cutoff(overlay_root: Path):
    from xdr_cli.schema_graph.evidence_cache import cached_evidence
    from xdr_cli.schema_graph.overlay import load_tenant_overlay_from_root

    value = cached_evidence(
        'discovery-retirement', str(overlay_root),
        lambda: load_tenant_overlay_from_root(overlay_root).metadata.get(
            'discovery_retired_before'
        ),
    )
    return timestamp(value) if value else None
