"""Descriptive reader for the fixed event-contract evidence; no CTMC execution."""
import hashlib
import json
from pathlib import Path
import os

ROOT = Path(os.environ['HEPTA_EVENT_STUDY_DIR']).resolve()
EVIDENCE = ROOT / "evidence"
TOLERANCE = 2e-10


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def basis():
    return [(h, i) for h in range(7) for i in range(33)
            if ((h == 0 and i < 31) or (h == 1 and i == 31)
                or (h == 2 and i == 32) or (h == 3 and i != 32)
                or (h == 4 and i != 31) or h >= 5)]


def projection(joint, nodes):
    marginal = [0.0] * 33
    for value, (_, latent) in zip(joint, nodes):
        marginal[latent] += value
    return marginal


def max_error(left, right):
    assert len(left) == len(right)
    return max((abs(a - b) for a, b in zip(left, right)), default=0.0)


def revert_metadata(value):
    renames = {'current_endpoint_nonpositive_sign_score': 'submit_zero_utility',
               'current_endpoint_positive_sign_score': 'submit_one_utility'}
    extra = {'endpoint_score_target_tick', 'fixed_task_target_tick', 'consumable_as_submit_or_continuation_q'}
    if isinstance(value, dict):
        return {renames.get(key, key): revert_metadata(item) for key, item in value.items() if key not in extra}
    if isinstance(value, list):
        return [revert_metadata(item) for item in value]
    return value


def main():
    oracle_path = EVIDENCE / "ORACLE_INPUT_V2.json"
    final_path = EVIDENCE / "PROCESS_native_v2.stdout"
    initial_path = EVIDENCE / "NATIVE_RESULTS_INITIAL.json"
    oracle = json.loads(oracle_path.read_bytes())
    final = json.loads(final_path.read_bytes())
    initial = json.loads(initial_path.read_bytes())
    protocol = json.loads((ROOT / "PROTOCOL_FROZEN.json").read_bytes())
    seal = json.loads((ROOT / "QUALIFICATION_V2_SEAL.json").read_bytes())
    assert all(digest(ROOT / name) == value for name, value in seal['source_files'].items())
    assert digest(oracle_path) == seal['oracle_input_sha256']
    assert [m['fit'] for m in final['models']] == [11, 23, 37, 53, 71]
    assert final['status'] == 'PASS_FINITE_EVENT_CONTRACT_V2'
    assert not final['production_eligible'] and final['new_independent_financial_labels'] == 0
    nodes = basis()
    indices = {node: i for i, node in enumerate(nodes)}
    rows = []
    whole_error = marginal_error = decoder_error = mass_error = partition_error = 0.0
    tail_max = 0.0
    terms = []
    all_original_fields_equal = True
    for model, original, reference, pin in zip(final['models'], initial['models'], oracle['models'], protocol['inputs']):
        assert model['fit'] == original['fit'] == reference['fit'] == pin['fit']
        assert digest(Path(pin['checkpoint_path'])) == pin['checkpoint_gzip_sha256']
        assert model['source']['compressed_sha256'] == pin['checkpoint_gzip_sha256']
        assert model['source']['decoded_sha256'] == pin['checkpoint_decoded_sha256']
        assert all(model[field] for field in ['unknown_source_rejected', 'unknown_drive_generator_rejected',
                                             'financial_call_put_rejected', 'original_checkpoint_bytes_unchanged',
                                             'sensor_repair_joint_latent_byte_equal'])
        v1_compatible = revert_metadata(model)
        assert all(v1_compatible[k] == v for k, v in original.items())
        all_original_fields_equal &= all(v1_compatible[k] == v for k, v in original.items())
        assert [c['label'] for c in model['cases']] == ['WAIT_ONLY', 'TWO_LEGAL_READS']
        for case, expected_case in zip(model['cases'], reference['cases']):
            assert case['label'] == expected_case['label']
            assert len(case['steps']) == len(expected_case['steps']) == 6
            for actual, expected in zip(case['steps'], expected_case['steps']):
                assert actual['owner_state'] == expected['state']
                assert actual['endpoint_score_target_tick'] == actual['tick']
                assert actual['fixed_task_target_tick'] == 6
                assert actual['consumable_as_submit_or_continuation_q'] is False
                joint, decoder = actual['joint'], actual['decoder']
                assert len(joint) == 163 and all(value >= 0.0 for value in joint)
                whole_error = max(whole_error, max_error(joint, expected['joint']))
                marginal = projection(joint, nodes)
                marginal_error = max(marginal_error, max_error(marginal, expected['marginal']))
                decoder_error = max(decoder_error, max_error(list(decoder.values()),
                                    [expected['decoder'][name] for name in decoder]))
                mass_error = max(mass_error, abs(sum(joint) - 1.0))
                partition_error = max(partition_error, abs(decoder['first_lower'] + decoder['first_upper'] + decoder['no_outer_hit'] - 1.0))
                assert -TOLERANCE <= decoder['both_boundaries'] <= decoder['reset_seen'] + TOLERANCE
                ever_hit = decoder['first_lower'] + decoder['first_upper']
                boundary_now = marginal[31] + marginal[32]
                assert decoder['reset_seen'] <= ever_hit + TOLERANCE
                assert boundary_now <= ever_hit + TOLERANCE
                # The ablation erases past event tags at a reset, retaining the
                # entire current physical marginal. This is a decoder ablation,
                # not a retrained or quality-selected checkpoint.
                collapsed = [0.0] * 163
                for value, (history, latent) in zip(joint, nodes):
                    if history >= 3:
                        history = 0 if latent < 31 else (1 if latent == 31 else 2)
                    collapsed[indices[(history, latent)]] += value
                preserved_error = max_error(marginal, projection(collapsed, nodes))
                assert preserved_error <= TOLERANCE
                gap = 1.0 - decoder['endpoint_above_zero'] - decoder['endpoint_below_zero']
                assert abs(gap - decoder['endpoint_at_zero']) <= TOLERANCE
                assert abs(decoder['current_endpoint_nonpositive_sign_score'] + decoder['current_endpoint_positive_sign_score']) <= TOLERANCE
                tail_max = max(tail_max, actual['tail_bound'])
                terms.append(actual['terms'])
                rows.append({'fit': model['fit'], 'history': case['label'], 'tick': actual['tick'],
                             'first_outer_hit': ever_hit, 'current_boundary_occupancy': boundary_now,
                             'endpoint_for_first_hit_abs_error': ever_hit - boundary_now,
                             'reset_seen': decoder['reset_seen'], 'both_boundaries': decoder['both_boundaries'],
                             'reset_tag_drop_abs_error': decoder['reset_seen'],
                             'collapse_history_joint_L1': sum(abs(a - b) for a, b in zip(joint, collapsed)),
                             'collapse_history_endpoint_marginal_max_error': preserved_error,
                             'strict_complement_missing_zero_atom': decoder['endpoint_at_zero'],
                             'first_lower': decoder['first_lower'], 'first_upper': decoder['first_upper'],
                             'no_outer_hit': decoder['no_outer_hit'],
                             'observation_likelihood': actual['observation_likelihood']})
    assert len(rows) == 60
    assert max(whole_error, marginal_error, decoder_error, mass_error, partition_error) <= TOLERANCE
    assert tail_max <= 1e-15
    final_rows = [row for row in rows if row['tick'] == 6]
    def interval(field, selected):
        return {'min': min(row[field] for row in selected), 'max': max(row[field] for row in selected)}
    result = {
        'schema': 'hepta.event-history-descriptive-results.v2',
        'status': 'PASS_FINITE_EVENT_SEMANTICS_V2',
        'scope': 'five unchanged checkpoints, two original legal histories each; computational semantics, not new predictive or trading quality',
        'reader_sha256': digest(Path(__file__)),
        'qualification_seal_sha256': digest(ROOT / 'QUALIFICATION_V2_SEAL.json'),
        'input_sha256': digest(oracle_path), 'native_results_sha256': digest(final_path),
        'fixed_history_inputs': 10, 'fixed_intervals': 60,
        'new_statistically_independent_quality_samples': 0,
        'qualification_is_same_inputs_not_new_samples': True,
        'all_v1_original_numerical_payloads_unchanged': all_original_fields_equal,
        'v1_semantic_admission': 'SUPERSEDED_NUMERICAL_REFERENCE_ONLY',
        'current_endpoint_scores_are_submit_or_continuation_q': False,
        'contract_amendment_sha256': digest(ROOT / 'PROTOCOL_V2_AMENDMENT.json'),
        'whole_joint_max_abs_error': whole_error,
        'marginal_vs_source_stored_transition_max_abs_error': marginal_error,
        'decoder_max_abs_error': decoder_error,
        'normalization_max_abs_error': mass_error,
        'first_cause_partition_max_abs_error': partition_error,
        'generator_reconstruction_max_abs_error': max(m['generator_reconstruction_error'] for m in final['models']),
        'owner_history_reconstruction_max_abs_error': max(m['owner_history_reconstruction_error'] for m in final['models']),
        'omitted_poisson_tail_bound_max': tail_max,
        'uniformization_terms': {'min': min(terms), 'max': max(terms)},
        'range_over_all_60_intervals': {field: interval(field, rows) for field in [
            'endpoint_for_first_hit_abs_error', 'reset_tag_drop_abs_error',
            'strict_complement_missing_zero_atom', 'collapse_history_joint_L1']},
        'range_at_fixed_deadline_10_histories': {field: interval(field, final_rows) for field in [
            'endpoint_for_first_hit_abs_error', 'reset_tag_drop_abs_error',
            'strict_complement_missing_zero_atom', 'both_boundaries']},
        'all_60_ablation_rows': rows,
        'financial_call_put_contract': 'UNSUPPORTED_NO_SOURCE_BINDING',
        'continuous_diffusion_certified': False,
        'production_eligible': False,
        'new_financial_labels': 0,
        'new_training_or_weight_edit': False,
        'general_NDU': 'KEEP_ORIGINAL_AND_STOP_UNPRICED_UNVALIDATED_FINANCIAL_ACTIONS'
    }
    with (EVIDENCE / 'RESULTS_V2.json').open('x') as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'all_60_ablation_rows'}, indent=2))


if __name__ == '__main__':
    main()
