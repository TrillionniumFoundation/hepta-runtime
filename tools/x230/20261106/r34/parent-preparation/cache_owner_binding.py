R34_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r33")
R34_CACHE_OWNER_CLOSURE = {
    "path": str(ROOT / "cache-owner-closure-inputs.json"), "bytes": 4503,
    "sha256": "94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9",
}


def r34_relative_identity(value):
    relative = Path(value["path"])
    need(not relative.is_absolute() and ".." not in relative.parts, "unsafe R34 frozen member")
    return {**value, "path": str(ROOT / relative)}


def bind_r34_chain_and_cache_owner(preparation, build_inputs, bind):
    """Bind R24-plus-R34 source and the rejected, closed R33 cache owner separately."""
    def document(identity):
        return json.loads(bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1])
    expected_input = r34_relative_identity(build_inputs["candidate_input"])
    expected_manifest = r34_relative_identity(build_inputs["candidate_manifest"])
    need(preparation["frozen_candidate_input"] == expected_input
         and preparation["frozen_candidate_manifest"] == expected_manifest
         and preparation["source_materialization"]
         == "accepted R24 source copy plus the frozen R34 patch; R33 supplies build cache only",
         "R34 source provenance differs")
    candidate, patch = r34_frozen_candidate(build_inputs, bind)
    need(preparation["candidate_patch"] == patch, "frozen four-file patch differs")
    closure_id = R34_CACHE_OWNER_CLOSURE
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "actual R33 cache-owner receipt differs")
    owner = r34_cache_owner_closed(document(closure_id), build_inputs["qualification_harness_sha256"], bind)
    need(preparation["cache_owner_closure"] == owner, "preparer and parent owner-closure results differ")
    return {"source_baseline_commit": R34_BASELINE_COMMIT,
        "frozen_candidate_input": expected_input, "frozen_candidate_manifest": expected_manifest,
        "candidate_patch": patch, "changed_paths": sorted(R34_CHANGED_PATHS),
        "cache_owner_closure": closure_id, "cache_owner_proof": owner,
        "r33_source_used_as_baseline": False, "r33_performance_adopted": False,
        "cache_deletion_scope": "the preparer itself deleted zero files; independent prune-01 failed with zero deletions and prune-02 deleted exactly two rebuildable files",
        "current_machine_idle_claimed": False, "original_auditors_reexecuted": False}


def r34_owner_native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False


def r34_owner_closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def r34_owner_completed_qualification(value, source, harness):
    assert value['schema'] == 'hepta-x230-composed-qualification/v1'
    assert value['qualified'] is True and value.get('finished_utc') and not value.get('error')
    assert value['source'] == str(source) and value['jobs'] == 2
    assert value['automatic_test_retries'] == 0 and value['service_changes'] is False
    assert [row['name'] for row in value['stages']] == R34_QUALIFICATION_STAGES
    assert all(row['returncode'] == 0 for row in value['stages'])
    assert value['source_tested'] == value['source_after'] == qualification_projection(source_inputs(source))
    assert value['harness_before'] == value['harness_after'] == harness


def r34_owner_native_streams(value, terminal):
    """Bind a complete original single-page native read to its terminal byte counts."""
    assert value['job_id'] == terminal['job_id'] and value['audit_recorded'] is True
    result = {}
    for name in ('stdout', 'stderr'):
        channel = value[name]
        raw = bytes.fromhex(channel['bytes_hex'])
        assert channel['offset'] == 0 and channel['eof'] is True
        assert channel['size'] == channel['next_offset'] == len(raw)
        assert len(raw) == terminal['log_bytes'][name]['stored']
        assert channel['text'] == raw.decode('utf-8', errors='replace')
        result[name] = raw
    return result


def r34_frozen_candidate(manifest, bind):
    def read_bound(identity):
        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]
    assert manifest['schema'] == 'hepta-r34-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['git_parent'] == R34_BASELINE_COMMIT
    assert manifest['candidate_catalog_git_blob'] == '04968ea30cb3b08d4790d8b3f18fc62f69e3dab8'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 53074,
        'sha256': '7336fe6abeca46e5f8ebc05e8a75e292a507aad1575565331a850e7cbb8f9c70'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/manifest.json', 'bytes': 3999,
        'sha256': '22c24ee1f14d1c267d2b88d14919b2fd6c35035af342f56a4c486ce776b1f90c'}
    candidate = json.loads(read_bound(r34_relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(r34_relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-x230-r34-candidate-manifest/v1'
    assert frozen['baseline_commit'] == R34_BASELINE_COMMIT and frozen['compile_input_count'] == 220
    assert set(frozen['changed_paths']) == R34_CHANGED_PATHS
    seen = set()
    for identity in frozen['files']:
        name = identity['path']
        assert name not in seen
        seen.add(name)
        read_bound(r34_relative_identity({**identity, 'path': 'candidate/' + name}))
    assert len(seen) == 21
    assert candidate['schema'] == 'hepta-x230-r34-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == R34_BASELINE_COMMIT
    assert candidate['patch_path'] == 'candidate.patch'
    assert candidate['patch_sha256'] == '1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0'
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert set(candidate['changed_paths']) == R34_CHANGED_PATHS
    assert len(candidate['new_test_functions']) == len(set(candidate['new_test_functions'])) == 8
    for label, field in (('baseline_map_artifact', 'baseline_compile_inputs'),
                         ('candidate_map_artifact', 'candidate_compile_inputs')):
        identity = candidate[label]
        assert json.loads(read_bound(r34_relative_identity({**identity, 'path': 'candidate/' + identity['path']}))) == candidate[field]
    patch = next(value for value in frozen['files'] if value['path'] == 'candidate.patch')
    assert patch['sha256'] == candidate['patch_sha256']
    return candidate, r34_relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def r34_cache_owner_closed(value, harness, bind):
    def read_bound(identity):
        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]
    assert value['schema'] == 'hepta-x230-r34-cache-owner-closure/v1'
    assert value['cache_owner'] == str(R34_CACHE_OWNER)
    assert value['cache_path'] == str(R34_CACHE_OWNER / 'target-build')
    assert value['sealed'] is True
    assert value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r33_observation_performance_passed'] is False
    assert value['r33_lifecycle_abba_executed'] is False
    identities = value['inputs']
    paths = {
        'qualification_report': 'qualification-01/report.json',
        'qualification_native': 'qualification-terminal-status-01.json',
        'qualification_preparation': 'preparation.json',
        'exact_ci_report': 'rust-ci-01/report.json',
        'exact_ci_native': 'rust-ci-native-01.json',
        'observation_parent': 'campaign-01/report.json',
        'observation_native': 'observation-holder-native-01.json',
        'observation_holder_read': 'observation-holder-read-01.json',
        'observation_report': 'campaign-01/native-observation/report.json',
        'observation_summary': 'campaign-01/summary.json',
        'lifecycle_materializer_native': 'lifecycle-materialization-native-01.json',
        'lifecycle_materializer_read': 'lifecycle-materialization-read-01.json',
    }
    assert set(identities) == set(paths)
    for label, relative in paths.items():
        assert identities[label]['path'] == str(R34_CACHE_OWNER / relative)
    assert value['postflight_receipt'] == {
        'path': 'owner-closure-provenance/observation-postflight-01.json', 'bytes': 4873,
        'sha256': '975c0a362e8faecf24eb6fdaa9a6ee57557a2776b94e7d54dc814d8b8104861f'}
    postflight = json.loads(read_bound(r34_relative_identity(value['postflight_receipt'])))
    assert postflight['schema'] == 'hepta-r33-rejected-observation-owner-postflight/v1'
    assert postflight['cache_path'] == value['cache_path']
    assert postflight['current_source_matches_qualified_map'] is True and postflight['compiler_input_count'] == 220
    assert postflight['observation_workflow_closed'] is True and postflight['original_owned_agent_reaped'] is True
    assert postflight['observation_gate_passed'] is False and postflight['performance_gates_passed'] is False
    assert postflight['candidate_adopted'] is False and postflight['normal_lifecycle_started'] is False
    assert postflight['rejection_reasons'] == ['C8 regression gate']
    for label, relative in paths.items():
        assert postflight['originals'][relative] == identities[label]
    receipts = {label: json.loads(read_bound(identity)) for label, identity in identities.items()}
    assert value['qualification_job_id'] == '1a1ae8ce865-fc05-603f'
    r34_owner_native_terminal(receipts['qualification_native'], value['qualification_job_id'])
    qualified = receipts['qualification_report']
    r34_owner_completed_qualification(qualified, R34_CACHE_OWNER / 'source', harness)
    preparation = receipts['qualification_preparation']
    assert preparation['schema'] == 'hepta-x230-r33-preparation/v1'
    assert preparation['passed'] is True and preparation['qualification_returncode'] == 0
    assert preparation['qualification_started'] is True
    assert preparation['automatic_retries'] == 0 and preparation['production_services_modified'] is False
    assert preparation['qualification_report_sha256'] == identities['qualification_report']['sha256']
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == R34_BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']

    assert value['exact_ci_job_id'] == '1a1aeb583b3-fc05-6176'
    r34_owner_native_terminal(receipts['exact_ci_native'], value['exact_ci_job_id'])
    ci = receipts['exact_ci_report']
    assert ci['schema'] == 'hepta-r33-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == value['qualification_job_id']
    r34_owner_closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    assert ci['nextest_output_audit']['verified'] is True
    assert {name: ci['nextest_output_audit'][name] for name in
            ('passed', 'failed', 'ignored', 'selected', 'retries')} == {
                'passed': 1649, 'failed': 0, 'ignored': 34, 'selected': 1683, 'retries': 0}

    assert value['observation_holder_job_id'] == '1a1aecd302a-fc05-6294'
    assert postflight['original_observation_job_id'] == value['observation_holder_job_id']
    r34_owner_native_terminal(receipts['observation_native'], value['observation_holder_job_id'])
    holder_raw = r34_owner_native_streams(receipts['observation_holder_read'], receipts['observation_native'])
    assert holder_raw['stderr'] == b''
    holder_rows = [json.loads(line) for line in holder_raw['stdout'].splitlines()]
    assert len(holder_rows) == 2 and holder_rows[0]['phase'] == 'owned_agent_ready'
    assert holder_rows[0]['identity_count'] == 5
    holder_completion = holder_rows[1]
    assert holder_completion['passed'] is True and holder_completion['remote_returncode'] == 0
    assert holder_completion['owned_agent_reaped'] is True
    parent = receipts['observation_parent']
    assert holder_rows[0]['remote_script_sha256'] == parent['launcher_sha256']
    assert parent['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert parent['passed'] is True and parent.get('finished_utc') and not parent.get('error')
    assert parent['observation_gate_passed'] is False
    assert parent['rejection_reasons'] == ['C8 regression gate']
    assert parent['correctness_stages_completed'] is True and parent['measurement_attribution_valid'] is True
    assert parent['source_inputs_unchanged'] is True and parent['inputs_unchanged'] is True
    assert parent['compiler_monitor']['passed'] is True
    r34_owner_closed_stages(parent['stages'], ['native-observation', 'native-audit', 'native-boundary',
                                    'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    assert parent['stages'][0]['output_bindings'] == [identities['observation_report']]
    assert parent['summary'] == identities['observation_summary']
    observation = receipts['observation_report']
    assert observation['passed'] is True and observation.get('finished_unix')
    assert [row['version'] for row in observation['rounds']] == list('ABBA')
    for row in observation['rounds']:
        assert row['passed'] is True
        assert [cell['concurrency'] for cell in row['cells']] == [1, 8, 16]
        assert all(cell['calls'] == cell['successes'] == 192 for cell in row['cells'])
        for label in ('shutdown', 'restart_shutdown'):
            closed = row[label]
            assert closed['exit_code'] == 0 and closed['shutdown_method'] == 'stdin_eof'
            assert not closed['observed_descendant_survivors'] and closed['reader_error'] is None
            assert closed['transport_capture']['reader_eof'] is True and closed['unmatched_responses'] == 0
            assert closed['resources']['sampler_error'] is None
    summary = receipts['observation_summary']
    assert summary['correctness_verified'] is True and summary['evidence_verified'] is True
    assert summary['observation_gate_passed'] is False and summary['performance_gates_passed'] is False
    assert summary['rejection_reasons'] == ['C8 regression gate']

    assert value['lifecycle_materializer_job_id'] == '1a1aed5c50a-fc05-6301'
    assert postflight['original_lifecycle_materializer_job_id'] == value['lifecycle_materializer_job_id']
    lifecycle_native = receipts['lifecycle_materializer_native']
    r34_owner_native_terminal(lifecycle_native, value['lifecycle_materializer_job_id'], 'failed', 1)
    lifecycle_read = receipts['lifecycle_materializer_read']
    raw = r34_owner_native_streams(lifecycle_read, lifecycle_native)
    assert raw['stderr'].endswith(b'RuntimeError: normal observation campaign did not close and pass\n')
    assert raw['stdout'] == b''
    assert postflight['normal_lifecycle_paths_absent'] == [
        'lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01']
    for name in ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01'):
        assert not os.path.lexists(R34_CACHE_OWNER / name), 'unreviewed lifecycle output exists: ' + name
    return {'inputs': identities, 'qualification_and_exact_ci_succeeded': True,
            'observation_parent_completed': True, 'observation_controllers_closed': True,
            'observation_holder_owned_agent_reaped': True,
            'observation_performance_passed': False, 'rejection_reasons': ['C8 regression gate'],
            'lifecycle_materializer_rejected_before_abba': True,
            'original_auditors_reexecuted': False, 'r33_adoption_claimed': False}

