R36_CACHE_OWNER = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')


R36_OWNER_JOBS = {'qualification':'1a1b0cc0f51-fc05-7301','exact_ci':'1a1b0f08c41-fc05-7434','ordinary':'1a1b1014af6-fc05-74d2','ordinary_postflight':'1a1b1217f3f-fc05-7616'}


R36_OWNER_PATHS = {
    'qualification_report': R36_CACHE_OWNER / 'qualification-01/report.json',
    'qualification_preparation': R36_CACHE_OWNER / 'preparation.json',
    'qualification_native': R36_CACHE_OWNER / 'qualification-terminal-status-01.json',
    'qualification_read': R36_CACHE_OWNER / 'qualification-native-read-01.json',
    'qualification_summary': R36_CACHE_OWNER / 'qualification-01/isolated-tests/summary.json',
    'qualification_map': R36_CACHE_OWNER / 'qualification-01/source-map.json',
    'exact_ci_report': R36_CACHE_OWNER / 'rust-ci-01/report.json',
    'exact_ci_audit': R36_CACHE_OWNER / 'rust-ci-01/nextest-output-audit.json',
    'exact_ci_native': R36_CACHE_OWNER / 'rust-ci-native-01.json',
    'exact_ci_read': R36_CACHE_OWNER / 'rust-ci-native-read-01.json',
    'ordinary_report': R36_CACHE_OWNER / 'ordinary-01/report.json',
    'ordinary_native': R36_CACHE_OWNER / 'ordinary-native-01.json',
    'ordinary_read': R36_CACHE_OWNER / 'ordinary-native-read-01-000.json',
    'ordinary_map': R36_CACHE_OWNER / 'ordinary-01/source-map.json',
    'ordinary_postflight_report': R36_CACHE_OWNER / 'ordinary-postflight-01.json',
    'ordinary_postflight_native': R36_CACHE_OWNER / 'ordinary-postflight-native-01.json',
    'ordinary_postflight_read': R36_CACHE_OWNER / 'ordinary-postflight-native-read-01-000.json',
    'c1_first_parent': R36_CACHE_OWNER / 'c1-campaign-01/report.json',
    'c1_first_monitor_audit': R36_CACHE_OWNER / 'c1-campaign-01/compiler-monitor.audit.json',
    'c1_recovery_parent': R36_CACHE_OWNER / 'c1-campaign-02/report.json',
    'c1_recovery_monitor_audit': R36_CACHE_OWNER / 'c1-campaign-02/compiler-monitor.audit.json',
    'c1_recovery_report': R36_CACHE_OWNER / 'c1-observation-02/report.json',
    'c1_first_native': ROOT / 'owner-closure-provenance/c1-first-native.json',
    'c1_first_read': ROOT / 'owner-closure-provenance/c1-first-read.json',
    'c1_first_holder': ROOT / 'owner-closure-provenance/c1-first-holder.json',
    'c1_recovery_native': ROOT / 'owner-closure-provenance/c1-recovery-native.json',
    'c1_recovery_read': ROOT / 'owner-closure-provenance/c1-recovery-read.json',
    'c1_recovery_holder': ROOT / 'owner-closure-provenance/c1-recovery-holder.json',
}


R36_ORIGINAL_MISSING_PATHS = (
    R36_CACHE_OWNER / 'c1-observation-01/report.json',
    R36_CACHE_OWNER / 'c1-observation-01/independent-summary.json',
    R36_CACHE_OWNER / 'c1-adapter-evidence-01/adapter-report.json',
    R36_CACHE_OWNER / 'c1-campaign-01/summary.json',
)


def r36_relative_identity(value):
    relative = Path(value['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    return {**value, 'path': str(ROOT / relative)}


def r36_owner_native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False


def r36_owner_closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def r36_owner_native_streams(value, terminal):
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


def r36_validate_owner_documents(doc, closure, owner_source, harness):
    """Current D2 owners only; no recursive replay of historical binders."""
    ids = closure['inputs']
    assert len(owner_source) == 222
    q = doc['qualification_report']
    assert q['schema'] == 'hepta-x230-composed-qualification/v1' and q['qualified'] is True
    assert q['source'] == str(R36_CACHE_OWNER / 'source') and q['jobs'] == 2
    assert q['source_tested'] == q['source_after'] == doc['qualification_map'] == owner_source
    assert q['harness_before'] == q['harness_after'] == harness
    assert [row['name'] for row in q['stages']] == R36_QUALIFICATION_STAGES and all(row['returncode'] == 0 for row in q['stages'])
    assert q['automatic_test_retries'] == 0 and q['service_changes'] is False and q.get('finished_utc')
    prep = doc['qualification_preparation']
    assert prep['schema'] == 'hepta-x230-d2-preparation/v1' and prep['passed'] is True
    assert prep['qualification_started'] is True and prep['qualification_returncode'] == 0 and not prep.get('error')
    assert prep['source_after_qualification'] == owner_source
    assert prep['qualification_report_sha256'] == ids['qualification_report']['sha256']
    summary = doc['qualification_summary']
    assert summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
    assert summary['failed'] == summary['retries'] == 0 and summary['enumeration_errors'] == []
    counts = {key: summary[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    assert summary['source_manifest_path'] == str(R36_CACHE_OWNER / 'qualification-01/source-map.json')
    assert summary['source_manifest_sha256'] == ids['qualification_map']['sha256']
    for prefix, job_key in (('qualification', 'qualification'), ('exact_ci', 'exact_ci'),
                            ('ordinary', 'ordinary'), ('ordinary_postflight', 'ordinary_postflight')):
        terminal = doc[prefix + '_native']
        r36_owner_native_terminal(terminal, R36_OWNER_JOBS[job_key])
        r36_owner_native_streams(doc[prefix + '_read'], terminal)

    ci = doc['exact_ci_report']
    assert ci['schema'] == 'hepta-d2-external-rust-ci/v1' and ci['passed'] is True
    assert ci['original_qualification_job_id'] == R36_OWNER_JOBS['qualification']
    assert ci['source_inputs_unchanged'] is True and ci['owned_children_closed'] is True
    assert ci['automatic_retries'] == 0 and ci['production_services_modified'] is False and ci.get('finished_utc')
    r36_owner_closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    ci_audit = doc['exact_ci_audit']
    assert ci['nextest_output_audit'] == ci_audit and ci_audit['verified'] is True
    assert {key: ci_audit[key] for key in counts} == counts
    assert ci['structured_inventory']['verified'] is True
    assert ci['structured_inventory']['case_inventory_sha256'] == ci_audit['case_inventory_sha256']
    ci_last = json.loads(r36_owner_native_streams(doc['exact_ci_read'], doc['exact_ci_native'])['stdout'].splitlines()[-1])
    assert ci_last['passed'] is True and ci_last['report'] == ids['exact_ci_report']

    ordinary = doc['ordinary_report']
    assert ordinary['schema'] == 'hepta-x230-composed-qualification/v1' and ordinary['qualified'] is True
    assert ordinary['source'] == str(R36_CACHE_OWNER / 'source') and ordinary['jobs'] == 2
    assert ordinary['automatic_test_retries'] == 0 and ordinary['service_changes'] is False
    assert ordinary['source_input'] == ordinary['source_tested'] == ordinary['source_after'] == owner_source
    assert ordinary['harness_before'] == ordinary['harness_after'] == harness
    ordinary_names = ['clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
    assert [row['name'] for row in ordinary['stages']] == ordinary_names
    assert all(row['returncode'] == 0 for row in ordinary['stages']) and ordinary.get('finished_utc')
    post = doc['ordinary_postflight_report']
    assert post['schema'] == 'hepta-d2-ordinary-supplement-postflight/v1' and post['passed'] is True
    assert post['ordinary_five_stages_passed'] is True and post['source_maps_unchanged'] is True
    assert post['compiler_input_count'] == 222 and post['original_qualification_harness_count'] == 19
    assert post['original_job_id'] == R36_OWNER_JOBS['ordinary']
    assert post['original_q_job_id'] == R36_OWNER_JOBS['qualification']
    assert post['original_exact_ci_job_id'] == R36_OWNER_JOBS['exact_ci']
    assert post['automatic_retries'] == 0 and post['new_compile_or_workload_started'] is False
    assert post['original_auditors_reexecuted'] is False and post['ordinary_package_features'] == []
    assert post['dependency_defaults_changed'] is False and post['performance_acceptance_claim'] is False
    assert post['qualified_feature_programs_before'] == post['qualified_feature_programs_after']
    assert post['report'] == ids['ordinary_report']
    assert post['native_terminal'] == ids['ordinary_native'] and post['native_read_pages'] == [ids['ordinary_read']]
    assert post['qualification_source_map'] == ids['qualification_map']
    assert post['ordinary_source_map'] == ids['ordinary_map'] and doc['ordinary_map'] == owner_source
    assert [row['name'] for row in post['stages']] == ordinary_names
    assert all(row['returncode'] == 0 for row in post['stages'])
    assert post['tests']['failed'] == post['tests']['retries'] == 0
    receipt = json.loads(r36_owner_native_streams(doc['ordinary_postflight_read'], doc['ordinary_postflight_native'])['stdout'])
    assert receipt['verified'] is True and receipt['compiler_or_workload_started'] is False
    assert receipt['original_job_id'] == R36_OWNER_JOBS['ordinary'] and receipt['report'] == ids['ordinary_postflight_report']
    assert set(q['binaries']) == set(ordinary['binaries']) == set(post['ordinary_programs']) == {
        'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
    for name in q['binaries']:
        feature = post['qualified_feature_programs_after'][name]
        standard = post['ordinary_programs'][name]
        assert feature['path'] == str(R36_CACHE_OWNER / 'qualification-01' / name)
        assert standard['path'] == str(R36_CACHE_OWNER / 'ordinary-01' / name)
        assert q['binaries'][name] == {key: feature[key] for key in ('path', 'sha256')}
        assert ordinary['binaries'][name] == {key: standard[key] for key in ('path', 'sha256')}

    first = r36_validate_c1_owner(doc, closure, 'first', '01')
    assert first['parent']['passed'] is False and first['exit_code'] == 1
    assert first['parent']['stages'] == []
    assert first['parent']['inputs_unchanged'] is False
    assert first['parent']['source_inputs_unchanged'] is False
    assert first['parent']['error'] == {
        'type': 'FileNotFoundError',
        'reason': "[Errno 2] No such file or directory: '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json'"}
    assert 'quiescence' not in first['parent']
    assert ids['c1_first_parent']['bytes'] == 396721
    assert ids['c1_first_parent']['sha256'] == '433c88277580f00736096927d3d7cab4e46c65d229f0b8f6a6140490eaf5f990'

    recovery = r36_validate_c1_owner(doc, closure, 'recovery', '02')
    parent = recovery['parent']
    for key in ('inputs_unchanged', 'source_inputs_unchanged', 'baseline_source_inputs_unchanged',
                'qualified_source_maps_match_current_inputs'):
        assert parent[key] is True
    assert parent['quiescence']['passed'] is True and parent['quiescence']['seconds_planned'] == 90
    names = [row['name'] for row in parent['stages']]
    assert names in (['native-observation'], ['native-observation', 'native-audit'])
    for row in parent['stages']:
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True
        if 'timed_out' in row:
            assert row['timed_out'] is False
        else:
            assert row['passed'] is True and row['returncode'] == 0 and 'error' not in row
    assert ids['c1_recovery_report'] in parent['stages'][0]['output_bindings']
    workload = doc['c1_recovery_report']
    assert workload['automatic_rpc_retries'] == 0
    assert workload['effect_starts'] == workload['remote_mutation_tool_calls'] == 0
    assert workload['binary_hashes_unchanged'] is True and workload['source_originals_unchanged'] is True
    assert workload['order'] == 'ABBA' and len(workload['rounds']) == 4
    assert workload['binary_sha256'] == {
        arm: post['qualified_feature_programs_after']['hepta-runtime']['sha256'] for arm in ('A', 'B')}
    births = set()
    for index, row in enumerate(workload['rounds']):
        assert row['index'] == index and row['version'] == 'ABBA'[index]
        for start_key, end_key in (('startup', 'shutdown'), ('restart_startup', 'restart_shutdown')):
            start, end = row[start_key], row[end_key]
            identity = (start['pid'], start['birth_ticks'])
            assert identity not in births
            births.add(identity)
            assert end['exit_code'] == 0 and end['observed_descendant_survivors'] == []
            assert end['reader_error'] is None and end['unmatched_responses'] == 0
            assert end['shutdown_method'] == 'stdin_eof' and end['transport_capture']['reader_eof'] is True
    assert len(births) == 8
    assert type(parent['diagnostic_evidence_passed']) is bool
    assert closure['c1_recovery_diagnostic_evidence_passed'] == parent['diagnostic_evidence_passed']
    return {'closed': True, 'source_input_count': 222, 'qualification_counts': counts,
            'ordinary_counts': post['tests'], 'original_jobs': closure['jobs'],
            'c1_original_first_attempt_failed_before_workload': True,
            'c1_original_first_source_recheck_completed': False,
            'c1_recovery_controllers_closed': len(births),
            'c1_recovery_workflow_passed': parent['passed'],
            'c1_recovery_diagnostic_evidence_passed': parent['diagnostic_evidence_passed'],
            'historical_auditors_reexecuted': False, 'candidate_adopted': False,
            'current_machine_idle_claimed': False, 'future_live_cache_process_scan_required': True,
            'retained_release_programs': {**{v['path']: v for v in post['qualified_feature_programs_after'].values()},
                                          **{v['path']: v for v in post['ordinary_programs'].values()}},
            'historical_owner_evidence_only': True, 'cache_reused': False,
            'cache_transferred_by_rename': False, 'ownership_transfer_applicable': False,
            'original_inputs': ids}


def r36_validate_c1_owner(doc, closure, prefix, attempt):
    parent = doc['c1_' + prefix + '_parent']
    native = doc['c1_' + prefix + '_native']
    holder = doc['c1_' + prefix + '_holder']
    monitor = doc['c1_' + prefix + '_monitor_audit']
    job_id = closure['jobs']['c1_' + prefix + '_holder']
    code = native['exit_code']
    assert type(code) is int and code in (0, 1)
    r36_owner_native_terminal(native, job_id, 'succeeded' if code == 0 else 'failed', code)
    raw = r36_owner_native_streams(doc['c1_' + prefix + '_read'], native)
    assert raw['stderr'] == b''
    assert parent['schema'] == 'hepta-d2-c1-campaign-control/v1' and parent['attempt'] == attempt
    assert parent['passed'] is (code == 0) and parent.get('finished_utc')
    assert parent['candidate_adopted'] is False and parent['performance_acceptance_claim'] is False
    assert parent['automatic_retries'] == 0 and parent['production_services_modified'] is False
    assert parent['normal_lifecycle_started'] is False and parent['capacity_workload_started'] is False
    assert parent['compiler_monitor']['passed'] is True
    assert parent['compiler_monitor']['independent_audit'] == closure['inputs']['c1_' + prefix + '_monitor_audit']
    assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
    assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
    assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
    assert monitor['ledger'] == parent['compiler_monitor']['ledger']
    assert holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder['passed'] is (code == 0) and holder['remote_returncode'] == code
    assert holder['automatic_ssh_retries'] == 0 and holder['services_modified'] is False
    assert holder['owned_agent_reaped'] is True and type(holder['owned_agent_returncode']) is int
    assert holder['owned_agent_directory_absent_after_context'] is True
    assert holder['owned_agent_socket_absent_after_context'] is True and holder.get('finished_utc')
    assert holder['remote_script_sha256'] == parent['launcher_sha256']
    return {'parent': parent, 'exit_code': code}


def r36_frozen_candidate(manifest, bind):
    def read_bound(identity, maximum=8 * 1024 * 1024):
        return bind(identity["path"], identity, maximum=maximum, retain=True)[1]
    assert manifest['schema'] == 'hepta-r36-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['git_parent'] == R36_BASELINE_COMMIT
    assert manifest['candidate_catalog_git_blob'] == 'c140350897adc751682e7eacd6e1874325d86538'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 52381,
        'sha256': '02171769738c0d21c2b94c75bce1ecc8ef301b6c55b06087e57f8b02106d50b0'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/package-manifest.json', 'bytes': 2760,
        'sha256': '637d573634f63fdca168d1c73201466fe601f2158c54e0c5835f205be843c73f'}
    candidate = json.loads(read_bound(r36_relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(r36_relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-r36-source-draft-package/v1'
    assert frozen['revision'] == 'lazy-scratch-draft-03'
    assert frozen['baseline_commit'] == R36_BASELINE_COMMIT
    expected_files = {
        'baseline/src/mcp/runtime/ssh_observation_profile.rs',
        'baseline/src/mcp/runtime/ssh_observation_reference_tests.rs',
        'source/src/mcp/runtime/ssh_observation_profile.rs',
        'source/src/mcp/runtime/ssh_observation_reference_tests.rs',
        'baseline-source-map.json', 'candidate-source-map.json', 'candidate.patch',
        'draft02-to-draft03.patch', 'input.json', 'static-review.json', 'README.md'}
    assert set(frozen['files']) == expected_files and len(expected_files) == 11
    for name, identity in frozen['files'].items():
        read_bound(r36_relative_identity({**identity, 'path': 'candidate/' + name}))
    assert candidate['schema'] == 'hepta-x230-r36-candidate-draft/v1'
    assert candidate['revision'] == 'lazy-scratch-draft-03'
    assert candidate['baseline_commit'] == candidate['git_parent'] == R36_BASELINE_COMMIT
    assert candidate['patch_sha256'] == 'fc0d76fda9d8fb921443f6031a80a1bff3dd765284fc54bd08055c613abb04d0'
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert set(candidate['changed_paths']) == R36_CHANGED_PATHS
    assert candidate['new_test_functions'] == [
        'shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths',
        'shared_verification_buffer_keeps_mismatch_cancellation_precedence']
    assert candidate['qualification'] is None and candidate['exact_ci'] is None
    assert candidate['performance'] is None and candidate['adopted'] is False
    for name, field in (('baseline-source-map.json', 'baseline_compile_inputs'),
                        ('candidate-source-map.json', 'candidate_compile_inputs')):
        identity = frozen['files'][name]
        assert json.loads(read_bound(r36_relative_identity({**identity, 'path': 'candidate/' + name}))) == candidate[field]
        assert len(candidate[field]) == 220
    patch = frozen['files']['candidate.patch']
    assert patch == candidate['patch'] and patch['sha256'] == candidate['patch_sha256']
    return candidate, r36_relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def bind_r36_chain_and_cache_owner(preparation, build_inputs, bind):
    """Rebind completed D2 evidence without reading or transferring a build cache."""
    seal = require_r36_preparation_seal()
    closure_id, raw = bind(ROOT / "cache-owner-closure-inputs.json",
                           seal["owner_closure_input"], retain=True)
    closure = json.loads(raw)
    need(build_inputs["owner_closure_input_sha256"] == closure_id["sha256"]
         and preparation["cache_owner_closure_input"] == closure_id,
         "R36 preparation binds another original cache-owner closure")
    need(closure["schema"] == "hepta-r36-d2-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["owner_root"] == str(R36_CACHE_OWNER)
         and closure["build_mode"] == "cold-only" and closure["cache_path"] is None
         and closure["historical_cache_path"] == str(R36_CACHE_OWNER / "target-build")
         and closure["cold_target_path"] == str(ROOT / "target-build")
         and closure["cache_reused"] is False and closure["ownership_transfer_applicable"] is False
         and closure["historical_auditors_to_execute"] == 0
         and closure["candidate_adopted"] is False
         and closure["qualification_or_measurement_still_running"] is False
         and set(closure["inputs"]) == set(R36_OWNER_PATHS),
         "R36 completed cache-owner input set differs")
    for label, path in R36_OWNER_PATHS.items():
        need(closure["inputs"][label]["path"] == str(path),
             "R36 owner evidence path differs: " + label)
    need(set(closure["jobs"]) == set(R36_OWNER_JOBS) | {"c1_first_holder", "c1_recovery_holder"}
         and all(closure["jobs"][key] == value for key, value in R36_OWNER_JOBS.items()),
         "R36 cache-owner original jobs differ")
    documents = {}
    for label, pin in closure["inputs"].items():
        _, data = bind(pin["path"], pin, retain=True, maximum=8 * 1024 * 1024)
        documents[label] = json.loads(data)
    current = qualification_projection(source_inputs(R36_CACHE_OWNER / "source"))
    owner = r36_validate_owner_documents(documents, closure, current,
                                         build_inputs["qualification_harness_sha256"])
    need(preparation["cache_owner_closure"] == owner,
         "completed R36 preparation and rebound D2 owner evidence disagree")
    need(closure["original_missing_paths"] == [str(path) for path in R36_ORIGINAL_MISSING_PATHS]
         and all(not os.path.lexists(path) for path in R36_ORIGINAL_MISSING_PATHS),
         "the preserved original D2 failure acquired synthetic results")
    for pin in owner["retained_release_programs"].values():
        bind(pin["path"], pin, maximum=64 * 1024 * 1024)
    # The D2 originals are historical evidence. No old cache is accepted,
    # opened, transferred, or reconstructed by this cold-only consumer.
    return owner


