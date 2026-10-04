import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from xdr_cli.schema_graph.retention import retired_observation


def test_malformed_automatic_evidence_is_retired_without_crashing_publication(tmp_path):
    folder = tmp_path / '2026-01-01'
    folder.mkdir()
    (folder / 'run.meta.json').write_text('{')
    observation = SimpleNamespace(extra={'evidence_stage': 'local-overlap'},
                                  evidence_run_ids=('run',))
    assert retired_observation(observation, datetime.now(UTC), tmp_path)


def test_retirement_index_is_reused_for_all_observations(tmp_path, monkeypatch):
    from xdr_cli.schema_graph.retention import index_result_metadata

    folder = tmp_path / '2026-01-01'
    folder.mkdir()
    for n in range(20):
        (folder / f'run{n}.meta.json').write_text(json.dumps({
            'created_at': datetime.now(UTC).isoformat(),
        }))
    index = index_result_metadata(tmp_path)
    def unexpected_scan(*args, **kwargs):
        raise AssertionError('per-observation directory scan')
    monkeypatch.setattr(type(tmp_path), 'glob', unexpected_scan)
    for n in range(20):
        observation = SimpleNamespace(extra={'evidence_stage': 'local-overlap'},
                                      evidence_run_ids=(f'run{n}',))
        assert not retired_observation(observation, datetime.now(UTC) - timedelta(days=30),
                                       tmp_path, metadata_paths=index)
