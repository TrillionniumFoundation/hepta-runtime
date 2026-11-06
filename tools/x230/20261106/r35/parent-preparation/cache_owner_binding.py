R35_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r34")
R35_CACHE_OWNER_CLOSURE = {
    "path": str(ROOT / "cache-owner-closure-inputs.json"), "bytes": 5378,
    "sha256": "2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47",
}


def r35_relative_identity(value):
    relative = Path(value["path"])
    need(not relative.is_absolute() and ".." not in relative.parts, "unsafe R35 frozen member")
    return {**value, "path": str(ROOT / relative)}


def bind_r35_chain_and_cache_owner(preparation, build_inputs, bind):
    """Bind R24-plus-R35 source and the rejected, closed R34 cache owner separately."""
    def document(identity):
        return json.loads(bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1])
    expected_input = r35_relative_identity(build_inputs["candidate_input"])
    expected_manifest = r35_relative_identity(build_inputs["candidate_manifest"])
    need(preparation["frozen_candidate_input"] == expected_input
         and preparation["frozen_candidate_manifest"] == expected_manifest
         and preparation["source_materialization"]
         == "accepted R24 source copy plus the frozen R35 patch; R34 supplies build cache only",
         "R35 source provenance differs")
    candidate, patch = r35_frozen_candidate(build_inputs, bind)
    need(preparation["candidate_patch"] == patch, "frozen three-file patch differs")
    closure_id = R35_CACHE_OWNER_CLOSURE
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "actual R34 cache-owner receipt differs")
    owner = r35_cache_owner_closed(document(closure_id), build_inputs["qualification_harness_sha256"], bind)
    need(preparation["cache_owner_closure"] == owner, "preparer and parent owner-closure results differ")
    return {"source_baseline_commit": R35_BASELINE_COMMIT,
        "frozen_candidate_input": expected_input, "frozen_candidate_manifest": expected_manifest,
        "candidate_patch": patch, "changed_paths": sorted(R35_CHANGED_PATHS),
        "cache_owner_closure": closure_id, "cache_owner_proof": owner,
        "r34_source_used_as_baseline": False, "r34_performance_adopted": False,
        "cache_deletion_scope": "the R35 preparer deletes zero files and transfers only the closed R34 build cache by rename",
        "current_machine_idle_claimed": False, "original_auditors_reexecuted": False}


def r35_owner_native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False


def r35_owner_closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def r35_owner_completed_qualification(value, source, harness):
    assert value['schema'] == 'hepta-x230-composed-qualification/v1'
    assert value['qualified'] is True and value.get('finished_utc') and not value.get('error')
    assert value['source'] == str(source) and value['jobs'] == 2
    assert value['automatic_test_retries'] == 0 and value['service_changes'] is False
    assert [row['name'] for row in value['stages']] == R35_QUALIFICATION_STAGES
    assert all(row['returncode'] == 0 for row in value['stages'])
    assert value['source_tested'] == value['source_after'] == qualification_projection(source_inputs(source))
    assert value['harness_before'] == value['harness_after'] == harness


def r35_owner_native_streams(value, terminal):
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


def r35_frozen_candidate(manifest, bind):
    def read_bound(identity):
        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]
    assert manifest['schema'] == 'hepta-r35-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['git_parent'] == R35_BASELINE_COMMIT
    assert manifest['candidate_catalog_git_blob'] == '4251bcdfb0e5897eaba2ebf3f507f0729e2e3667'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 53380,
        'sha256': '7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/manifest.json', 'bytes': 5225,
        'sha256': 'e5f4338e3581ecc4560269a417941b4802a8b58307eb60eea6e04dd7a4f5102b'}
    candidate = json.loads(read_bound(r35_relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(r35_relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-x230-r35-source-package/v1'
    assert frozen['baseline_commit'] == R35_BASELINE_COMMIT and frozen['compile_input_count'] == 220
    assert set(frozen['changed_compile_paths']) == R35_CHANGED_PATHS
    seen = set()
    for identity in frozen['files']:
        name = identity['path']
        assert name not in seen
        seen.add(name)
        read_bound(r35_relative_identity({**identity, 'path': 'candidate/' + name}))
    assert len(seen) == 28 and frozen['file_count_excluding_manifest'] == 28
    assert candidate['schema'] == 'hepta-x230-r35-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == R35_BASELINE_COMMIT
    assert candidate['patch_path'] == 'candidate.patch'
    assert candidate['patch_sha256'] == '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a'
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert set(candidate['changed_paths']) == R35_CHANGED_PATHS
    assert candidate['new_test_functions'] == []
    for label, field in (('baseline_map_artifact', 'baseline_compile_inputs'),
                         ('candidate_map_artifact', 'candidate_compile_inputs')):
        identity = candidate[label]
        assert json.loads(read_bound(r35_relative_identity({**identity, 'path': 'candidate/' + identity['path']}))) == candidate[field]
    patch = next(value for value in frozen['files'] if value['path'] == 'candidate.patch')
    assert patch['sha256'] == candidate['patch_sha256']
    return candidate, r35_relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def r35_cache_owner_closed(value, harness, bind):
    def read_bound(identity):
        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]
    assert value['schema'] == 'hepta-x230-r35-cache-owner-closure/v1'
    assert value['cache_owner'] == str(R35_CACHE_OWNER)
    assert value['cache_path'] == str(R35_CACHE_OWNER / 'target-build')
    assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r34_observation_performance_passed'] is False
    assert value['r34_lifecycle_abba_executed'] is False
    assert value['lifecycle_materialization_started'] is False
    assert value['lifecycle_materializer_job_id'] is None
    assert value['capacity_build_or_campaign_started_by_coordinator'] is False
    identities = value['inputs']
    paths = {
        'qualification_report': 'qualification-01/report.json',
        'qualification_native': 'qualification-terminal-status-01.json',
        'qualification_preparation': 'preparation.json',
        'qualification_map': 'qualification-01/source-map.json',
        'exact_ci_report': 'rust-ci-01/report.json',
        'exact_ci_native': 'rust-ci-native-01.json',
        'exact_ci_read': 'rust-ci-native-read-01.json',
        'observation_parent': 'campaign-01/report.json',
        'observation_native': 'observation-holder-native-01.json',
        'observation_holder_read': 'observation-holder-read-01.json',
        'observation_holder_report': 'observation-holder-report-01.json',
        'observation_report': 'campaign-01/native-observation/report.json',
        'observation_audit': 'campaign-01/native-observation/independent-summary.json',
        'compiler_monitor_audit': 'campaign-01/compiler-monitor.audit.json',
        'observation_summary': 'campaign-01/summary.json',
    }
    assert set(identities) == set(paths)
    for label, relative in paths.items():
        assert identities[label]['path'] == str(R35_CACHE_OWNER / relative)
    assert value['postflight_receipt'] == {
        'path': 'owner-closure-provenance/observation-postflight-01.json', 'bytes': 5064,
        'sha256': '17a371b24de733c7e412afdcf31a1fdad1745bbe2b560177e010816ee5193cc1'}
    postflight = json.loads(read_bound(r35_relative_identity(value['postflight_receipt'])))
    assert postflight['schema'] == 'hepta-r34-rejected-observation-owner-postflight/v1'
    assert postflight['accepted_baseline_commit'] == R35_BASELINE_COMMIT
    assert postflight['cache_path'] == value['cache_path']
    assert postflight['cache_moved'] is False and postflight['cache_deleted'] is False
    assert postflight['current_source_matches_qualified_map'] is True and postflight['compiler_input_count'] == 220
    assert postflight['observation_workflow_closed'] is True and postflight['original_owned_agent_reaped'] is True
    assert postflight['observation_gate_passed'] is False and postflight['performance_gates_passed'] is False
    assert postflight['candidate_adopted'] is False and postflight['normal_lifecycle_started'] is False
    assert postflight['lifecycle_materialization_started'] is False
    assert postflight['original_lifecycle_materializer_job_id'] is None
    assert postflight['capacity_build_or_campaign_started_by_coordinator'] is False
    assert postflight['tests_benchmarks_or_auditors_reexecuted'] is False
    assert postflight['rejection_reasons'] == ['C8 regression gate']
    assert set(postflight['originals']) == set(paths.values())
    for label, relative in paths.items():
        assert postflight['originals'][relative] == identities[label]
    receipts = {label: json.loads(read_bound(identity)) for label, identity in identities.items()}
    assert value['qualification_job_id'] == '1a1aef7882f-fc05-6499'
    r35_owner_native_terminal(receipts['qualification_native'], value['qualification_job_id'])
    qualified = receipts['qualification_report']
    r35_owner_completed_qualification(qualified, R35_CACHE_OWNER / 'source', harness)
    assert qualified['source_tested'] == receipts['qualification_map']
    preparation = receipts['qualification_preparation']
    assert preparation['schema'] == 'hepta-x230-r34-preparation/v1'
    assert preparation['passed'] is True and preparation['qualification_returncode'] == 0
    assert preparation['qualification_started'] is True
    assert preparation['automatic_retries'] == 0 and preparation['production_services_modified'] is False
    assert preparation['qualification_report_sha256'] == identities['qualification_report']['sha256']
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == R35_BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']

    assert value['exact_ci_job_id'] == '1a1af1ebf1d-fc05-65f2'
    r35_owner_native_terminal(receipts['exact_ci_native'], value['exact_ci_job_id'])
    assert r35_owner_native_streams(receipts['exact_ci_read'], receipts['exact_ci_native'])['stderr'] == b''
    ci = receipts['exact_ci_report']
    assert ci['schema'] == 'hepta-r34-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == value['qualification_job_id']
    r35_owner_closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    assert ci['nextest_output_audit']['verified'] is True
    # These are completed R34 owner counts, never predicted R35 counts.
    assert {name: ci['nextest_output_audit'][name] for name in
            ('passed', 'failed', 'ignored', 'selected', 'retries')} == {
                'passed': 1653, 'failed': 0, 'ignored': 34, 'selected': 1687, 'retries': 0}

    assert value['observation_holder_job_id'] == '1a1af308953-fc05-6698'
    assert postflight['original_observation_job_id'] == value['observation_holder_job_id']
    r35_owner_native_terminal(receipts['observation_native'], value['observation_holder_job_id'])
    holder_raw = r35_owner_native_streams(receipts['observation_holder_read'], receipts['observation_native'])
    assert holder_raw['stderr'] == b''
    holder_rows = [json.loads(line) for line in holder_raw['stdout'].splitlines()]
    assert len(holder_rows) == 2 and holder_rows[0]['phase'] == 'owned_agent_ready'
    assert holder_rows[0]['identity_count'] == 5
    holder_completion = holder_rows[1]
    assert holder_completion['passed'] is True and holder_completion['remote_returncode'] == 0
    assert holder_completion['owned_agent_reaped'] is True
    parent = receipts['observation_parent']
    assert holder_rows[0]['remote_script_sha256'] == parent['launcher_sha256']
    holder_report = receipts['observation_holder_report']
    assert holder_report['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder_report['passed'] is True and holder_report['remote_returncode'] == 0
    assert holder_report.get('finished_utc') and not holder_report.get('error')
    assert holder_report['remote_script_sha256'] == parent['launcher_sha256']
    assert holder_report['owned_agent_reaped'] is True
    assert holder_report['owned_agent_directory_absent_after_context'] is True
    assert holder_report['owned_agent_socket_absent_after_context'] is True
    assert holder_report['automatic_ssh_retries'] == 0 and holder_report['services_modified'] is False
    assert parent['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert parent['passed'] is True and parent.get('finished_utc') and not parent.get('error')
    assert parent['observation_gate_passed'] is False
    assert parent['rejection_reasons'] == ['C8 regression gate']
    assert parent['correctness_stages_completed'] is True and parent['measurement_attribution_valid'] is True
    assert parent['source_inputs_unchanged'] is True and parent['inputs_unchanged'] is True
    assert parent['compiler_monitor']['passed'] is True
    assert parent['compiler_monitor']['independent_audit'] == identities['compiler_monitor_audit']
    monitor = receipts['compiler_monitor_audit']
    assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
    assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
    assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
    assert monitor['validation']['validated_sample_count'] == 301
    assert monitor['ledger'] == parent['compiler_monitor']['ledger']
    r35_owner_closed_stages(parent['stages'], ['native-observation', 'native-audit', 'native-boundary',
                                    'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    assert parent['stages'][0]['output_bindings'] == [identities['observation_report']]
    assert parent['stages'][1]['output_bindings'] == [identities['observation_audit']]
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
    audit = receipts['observation_audit']
    assert audit['schema'] == 'hepta-native-observation-independent-analysis/v3' and audit['verified'] is True
    assert audit['original_bytes'] == identities['observation_report']['bytes']
    assert audit['original_sha256'] == identities['observation_report']['sha256']
    assert {name: audit[name] for name in ('measured_calls', 'warmup_calls', 'preflight_restart_calls',
                                          'total_calls', 'failed_calls')} == {
        'measured_calls': 2304, 'warmup_calls': 288, 'preflight_restart_calls': 72,
        'total_calls': 2664, 'failed_calls': 0}
    summary = receipts['observation_summary']
    assert summary['schema'] == 'hepta-r25-observation-gates/v1'
    assert summary['correctness_verified'] is True and summary['evidence_verified'] is True
    assert summary['observation_gate_passed'] is False and summary['performance_gates_passed'] is False
    assert summary['rejection_reasons'] == ['C8 regression gate']

    assert postflight['normal_lifecycle_paths_absent'] == [
        'lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01']
    for name in ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01',
                 'lifecycle-materialization-native-01.json', 'lifecycle-materialization-read-01.json'):
        assert not os.path.lexists(R35_CACHE_OWNER / name), 'unreviewed lifecycle output exists: ' + name
    return {'inputs': identities, 'qualification_and_exact_ci_succeeded': True,
            'observation_parent_completed': True, 'observation_controllers_closed': True,
            'observation_holder_owned_agent_reaped': True,
            'observation_performance_passed': False, 'rejection_reasons': ['C8 regression gate'],
            'lifecycle_materialization_started': False, 'lifecycle_materializer_job_id': None,
            'normal_lifecycle_started': False,
            'normal_lifecycle_disposition': postflight['normal_lifecycle_disposition'],
            'capacity_build_or_campaign_started_by_coordinator': False,
            'original_auditors_reexecuted': False, 'r34_adoption_claimed': False}

