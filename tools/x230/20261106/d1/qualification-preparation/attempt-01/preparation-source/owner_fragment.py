def closed_outcomes(rows, names, codes, absent='owned_process_absent', require_passed=True):
    """Check original failed-gate custody without converting rejection to success."""
    assert [row['name'] for row in rows] == names and len(rows) == len(codes)
    for row, code in zip(rows, codes):
        assert row['returncode'] == code
        if require_passed:
            assert row['passed'] is (code == 0)
        assert row['waited_and_reaped'] is True and row[absent] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def cache_owner_closed(value, harness):
    assert value['schema'] == 'hepta-d1-r35-cache-owner-closure/v1'
    assert value['cache_owner'] == str(CACHE_OWNER) and value['cache_path'] == str(CACHE_OWNER / 'target-build')
    assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r35_observation_performance_passed'] is True
    assert value['r35_normal_lifecycle_executed'] is True and value['r35_normal_lifecycle_adopted'] is False
    bindings = value['postflight']
    assert bindings['job_id'] == OWNER_POSTFLIGHT_JOB
    assert bindings['report']['path'] == str(CACHE_OWNER / 'lifecycle-owner-postflight-01.json')
    assert bindings['native']['path'] == str(CACHE_OWNER / 'lifecycle-owner-postflight-native-01.json')
    assert [row['path'] for row in bindings['read_pages']] == [
        str(CACHE_OWNER / ('lifecycle-owner-postflight-read-01-%03d.json' % number)) for number in range(3)]
    postflight = postflight_bytes(read_bound(bindings['report']), read_bound(bindings['native']),
                                 [read_bound(row) for row in bindings['read_pages']], bindings['report'])
    read_bound(postflight['postflight_script'])
    assert postflight['qualification_harness_sha256'] == harness
    assert value['inputs'] == postflight['originals']
    # The 150 original artifacts include the failed LC receipts and their
    # original logs. Recheck their bytes; never rerun a benchmark or auditor.
    originals = {name: read_bound(identity) for name, identity in value['inputs'].items()}
    def receipt(name):
        return json.loads(originals[name])

    qualified = receipt('qualification-01/report.json')
    completed_qualification(qualified, CACHE_OWNER / 'source', harness)
    assert qualified['source_tested'] == receipt('qualification-01/source-map.json')
    assert len(qualified['source_tested']) == 220
    assert sum(name.endswith('.py') for name in qualified['source_tested']) == 17
    preparation = receipt('preparation.json')
    assert preparation['schema'] == 'hepta-x230-r35-preparation/v1'
    assert preparation['passed'] is True and preparation['qualification_started'] is True
    assert preparation['qualification_returncode'] == 0 and preparation['automatic_retries'] == 0
    assert preparation['production_services_modified'] is False
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']
    assert preparation['qualification_report_sha256'] == value['inputs']['qualification-01/report.json']['sha256']
    qnative = receipt('qualification-terminal-status-01.json')
    native_terminal(qnative, OWNER_JOBS['qualification'])
    assert native_streams(receipt('qualification-native-read-01.json'), qnative)['stderr'] == b''
    summary = receipt('qualification-01/isolated-tests/summary.json')
    assert summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
    assert summary['enumeration_errors'] == [] and {key: summary[key] for key in OWNER_COUNTS} == OWNER_COUNTS

    cinative = receipt('rust-ci-native-01.json')
    native_terminal(cinative, OWNER_JOBS['exact_ci'])
    assert native_streams(receipt('rust-ci-native-read-01.json'), cinative)['stderr'] == b''
    ci = receipt('rust-ci-01/report.json')
    assert ci['schema'] == 'hepta-r35-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == OWNER_JOBS['qualification']
    closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    ciaudit = receipt('rust-ci-01/nextest-output-audit.json')
    assert ci['nextest_output_audit'] == ciaudit and ciaudit['verified'] is True
    assert {key: ciaudit[key] for key in OWNER_COUNTS} == OWNER_COUNTS

    for prefix, job, state, code in (
        ('observation', OWNER_JOBS['observation'], 'succeeded', 0),
        ('lifecycle', OWNER_JOBS['normal_lifecycle'], 'failed', 1),
    ):
        terminal = receipt(prefix + '-holder-native-01.json')
        native_terminal(terminal, job, state, code)
        streams = native_streams(receipt(prefix + '-holder-read-01.json'), terminal)
        assert streams['stderr'] == b''
        rows = [json.loads(row) for row in streams['stdout'].splitlines()]
        assert len(rows) == 2 and rows[0]['phase'] == 'owned_agent_ready' and rows[0]['identity_count'] == 5
        assert rows[1]['passed'] is (code == 0) and rows[1]['remote_returncode'] == code
        assert rows[1]['owned_agent_reaped'] is True
        holder = receipt(prefix + '-holder-report-01.json')
        assert holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
        assert holder['passed'] is (code == 0) and holder['remote_returncode'] == code
        assert holder.get('finished_utc')
        assert holder['owned_agent_reaped'] is True and holder['owned_agent_directory_absent_after_context'] is True
        assert holder['owned_agent_socket_absent_after_context'] is True
        assert holder['automatic_ssh_retries'] == 0 and holder['services_modified'] is False
        directory = 'campaign-01' if prefix == 'observation' else 'lifecycle-campaign-01'
        parent = receipt(directory + '/report.json')
        assert holder['remote_script_sha256'] == rows[0]['remote_script_sha256'] == parent['launcher_sha256']
        assert parent['source_inputs_unchanged'] is True and parent['baseline_source_inputs_unchanged'] is True
        assert parent['inputs_unchanged'] is True and parent['measurement_attribution_valid'] is True
        monitor = receipt(directory + '/compiler-monitor.audit.json')
        assert parent['compiler_monitor']['passed'] is True
        assert parent['compiler_monitor']['independent_audit'] == value['inputs'][directory + '/compiler-monitor.audit.json']
        assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
        assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
        assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
        assert monitor['ledger'] == parent['compiler_monitor']['ledger']

    obs = receipt('campaign-01/report.json')
    assert obs['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert obs['passed'] is True and obs.get('finished_utc') and not obs.get('error')
    assert obs['observation_gate_passed'] is True and obs['rejection_reasons'] == []
    assert obs['correctness_stages_completed'] is True
    closed_stages(obs['stages'], ['native-observation', 'native-audit', 'native-boundary',
                                 'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    obs_gates = receipt('campaign-01/summary.json')
    assert obs_gates['schema'] == 'hepta-r25-observation-gates/v1'
    assert all(obs_gates[key] is True for key in ('correctness_verified', 'evidence_verified',
                                                'observation_gate_passed', 'performance_gates_passed'))
    assert obs_gates['rejection_reasons'] == []
    obs_raw = receipt('campaign-01/native-observation/report.json')
    obs_audit = receipt('campaign-01/native-observation/independent-summary.json')
    assert obs_raw['passed'] is True and [row['version'] for row in obs_raw['rounds']] == list('ABBA')
    assert obs_audit['verified'] is True and obs_audit['original_sha256'] == value['inputs']['campaign-01/native-observation/report.json']['sha256']
    assert obs_audit['failed_calls'] == 0 and obs_audit['measured_calls'] == 2304

    materialized = receipt('lifecycle-materialization-native-01.json')
    native_terminal(materialized, OWNER_JOBS['lifecycle_materialization'])
    assert native_streams(receipt('lifecycle-materialization-read-01.json'), materialized)['stderr'] == b''
    lc = receipt('lifecycle-campaign-01/report.json')
    assert lc['schema'] == 'hepta-r35-normal-lifecycle-campaign-control/v1'
    assert lc['passed'] is False and lc['adoption_passed'] is False and lc.get('finished_utc') and lc.get('error')
    assert lc['automatic_retries'] == 0 and lc['production_services_modified'] is False
    assert not lc.get('finalization_error') and lc['open_blockers'] == []
    closed_outcomes(lc['stages'], ['lifecycle-tool-tests', 'normal-lifecycle-abba'], [0, 1])
    normal = receipt('lifecycle-abba-01/report.json')
    assert normal['schema'] == 'hepta-r25-lifecycle-abba-control/v1'
    assert normal['passed'] is False and normal['order'] == 'ABBA' and normal['automatic_retries'] == 0
    assert normal['inputs_unchanged'] is True and normal.get('finished_realtime_ns')
    closed_outcomes(normal['stages'], ['canary-0-A', 'audit-0-A', 'canary-1-B', 'audit-1-B',
        'canary-2-B', 'audit-2-B', 'canary-3-A', 'audit-3-A', 'summary', 'normal-lifecycle-gates'],
        [0] * 9 + [1], 'proc_absent', require_passed=False)
    index = receipt('lifecycle-abba-01/round-index.json')
    assert index['schema'] == 'hepta-r25-lifecycle-round-index/v1' and index['closed'] is True
    assert index['order'] == 'ABBA' and index['round_count'] == len(index['rounds']) == 4
    assert index['rounds'] == normal['rounds'] and index['automatic_retries'] == 0
    gates = receipt('lifecycle-abba-01/gates.json')
    assert gates['schema'] == 'hepta-r25-lifecycle-gates/v1' and gates['verified'] is True and gates['passed'] is False
    assert gates['normal_lifecycle_descriptive_verified'] is True and gates['automatic_retries'] == 0
    failed = [{'comparison': name, 'gate': gate, 'adoption_required': row['adoption_required']}
              for name, row in gates['comparisons'].items() for gate, passed in row['gates'].items() if passed is False]
    assert failed == postflight['normal_lifecycle_all_reported_false_flags']
    assert [row for row in failed if row['adoption_required'] is True] == postflight['normal_lifecycle_required_failed_flags']
    for number, arm in enumerate('ABBA'):
        directory = 'lifecycle-abba-01/round-%d-%s' % (number, arm)
        report, audit = receipt(directory + '/report.json'), receipt(directory + '/independent-summary.json')
        assert report['passed'] is True and report['automatic_rpc_retries'] == 0 and audit['verified'] is True
        assert audit['source_sha256'] == value['inputs'][directory + '/report.json']['sha256']
        for key in ('shutdown', 'after_cancel_shutdown'):
            row = report[key]
            assert row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
            assert row['observed_descendant_survivors'] == [] and row['reader_error'] is None
            assert row['transport_capture']['reader_eof'] is True and row['unmatched_responses'] == 0
            assert row.get('resources', {}).get('sampler_error') is None
    cache = CACHE_OWNER / 'target-build'
    assert (cache.stat().st_dev, cache.stat().st_ino) == (postflight['cache_directory_identity']['device'],
                                                     postflight['cache_directory_identity']['inode'])
    for name, identity in postflight['retained_release_programs'].items():
        assert identity['path'] == qualified['binaries'][name]['path']
        assert identity['sha256'] == qualified['binaries'][name]['sha256']
        read_bound(identity, 16 * 1024 * 1024)
    return {'inputs': value['inputs'], 'postflight': bindings,
            'qualification_and_exact_ci_succeeded': True, 'observation_performance_passed': True,
            'normal_lifecycle_executed': True, 'normal_lifecycle_workflow_closed': True,
            'normal_lifecycle_controllers_closed': True, 'normal_lifecycle_performance_passed': False,
            'original_required_failed_flags': postflight['normal_lifecycle_required_failed_flags'],
            'owned_agents_reaped': True, 'original_auditors_reexecuted': False, 'r35_adoption_claimed': False}
