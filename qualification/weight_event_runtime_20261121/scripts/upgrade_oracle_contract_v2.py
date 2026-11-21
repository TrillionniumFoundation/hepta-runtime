"""Upgrade metadata only; preserve every original numerical reference payload."""
from pathlib import Path
import os
import hashlib
import json

ROOT = Path(os.environ['HEPTA_EVENT_STUDY_DIR']).resolve()
RENAMES = {
    'submit_zero_utility': 'current_endpoint_nonpositive_sign_score',
    'submit_one_utility': 'current_endpoint_positive_sign_score',
}
CONTRACT = 'CURRENT_JOINT_ENDPOINT_ONLY_NOT_DEADLINE_SUBMIT_OR_CONTINUATION_Q'


def renamed(value, mapping):
    if isinstance(value, dict):
        return {mapping.get(key, key): renamed(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [renamed(item, mapping) for item in value]
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def main():
    source_path = ROOT / 'evidence/ORACLE_INPUT.json'
    amendment_path = ROOT / 'PROTOCOL_V2_AMENDMENT.json'
    original = json.loads(source_path.read_bytes())
    amendment = json.loads(amendment_path.read_bytes())
    assert original['schema'] == 'hepta.event-history-oracle.v1'
    assert original['profile'] == 'finite-checkpoint-renewal-history-163-f64-v1'
    current = renamed(original, RENAMES)
    current['schema'] = amendment['oracle_schema']
    current['profile'] = amendment['profile']
    current['endpoint_score_contract'] = CONTRACT
    current['contract_amendment_sha256'] = sha(amendment_path.read_bytes())
    for model in current['models']:
        for case in model['cases']:
            for step in case['steps']:
                step['endpoint_score_target_tick'] = step['state']['tick']
                step['fixed_task_target_tick'] = model['public']['deadline']
                step['consumable_as_submit_or_continuation_q'] = False
    restored = renamed(current, {v: k for k, v in RENAMES.items()})
    restored['schema'] = original['schema']
    restored['profile'] = original['profile']
    del restored['endpoint_score_contract'], restored['contract_amendment_sha256']
    for model in restored['models']:
        for case in model['cases']:
            for step in case['steps']:
                del step['endpoint_score_target_tick'], step['fixed_task_target_tick'], step['consumable_as_submit_or_continuation_q']
    assert canonical(restored) == canonical(original)
    target = ROOT / 'evidence/ORACLE_INPUT_V2.json'
    with target.open('x') as handle:
        json.dump(current, handle, indent=2, allow_nan=False)
        handle.write('\n')
    receipt = {
        'schema': 'hepta.event-oracle-contract-upgrade.v2',
        'source_input_sha256': sha(source_path.read_bytes()),
        'v2_input_sha256': sha(target.read_bytes()),
        'amendment_sha256': sha(amendment_path.read_bytes()),
        'script_sha256': sha(Path(__file__).read_bytes()),
        'all_original_numerical_payloads_and_owner_states_unchanged': True,
        'new_expm_or_training': False,
        'new_statistical_samples': 0,
        'v1_cache_entries_automatically_reused': False,
        'v1_semantic_admission': 'SUPERSEDED_NUMERICAL_REFERENCE_ONLY'
    }
    with (ROOT / 'evidence/ORACLE_CONTRACT_UPGRADE_V2.json').open('x') as handle:
        json.dump(receipt, handle, indent=2)
        handle.write('\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
