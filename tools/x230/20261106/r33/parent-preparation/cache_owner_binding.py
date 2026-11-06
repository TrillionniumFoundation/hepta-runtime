R33_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261105-r31")
R33_CACHE_OWNER_CLOSURE = {
    "path": str(ROOT / "cache-owner-closure-inputs.json"),
    "bytes": 3918,
    "sha256": "d10e468c67c21691fd6cb77d080aa589430c30c61accb12482004d4b10cf0353",
}


def bind_r33_chain_and_cache_owner(preparation, build_inputs, bind):
    """Rebind the frozen two-file chain and the closed, rejected R31 owner."""
    def relative(identity):
        name = Path(identity["path"])
        need(not name.is_absolute() and ".." not in name.parts,
             "unsafe frozen R33 chain path")
        return dict(identity, path=str(ROOT / name))

    def document(identity):
        actual, raw = bind(identity["path"], identity, retain=True)
        return actual, json.loads(raw)

    chain_id, chain = document(relative(build_inputs["source_chain_proof"]))
    need(preparation["source_chain_proof"] == chain_id
         and chain["schema"] == "hepta-r33-r24-combined-chain/v1"
         and chain["accepted_baseline_commit"] == R33_BASELINE_COMMIT
         and chain["direct_patch_base_is_accepted_r24"] is True
         and set(chain["changed_paths"]) == R33_CHANGED_PATHS
         and chain["exact_original_patch_chain_matches_final_files"] is True
         and chain["exact_combined_patch_matches_final_files"] is True
         and relative(chain["combined_patch"]) == preparation["combined_patch"],
         "the original R24 to R32 to R33 chain differs")
    original_names = {"r32/candidate.patch", "r32/input.json", "r32/manifest.json",
                      "r33/candidate.patch", "r33/baseline-overlay.patch",
                      "r33/input.json", "r33/manifest.json"}
    need(set(chain["originals"]) == original_names and set(chain["source_files"]) == R33_CHANGED_PATHS,
         "the frozen two-file chain inventory differs")
    originals = {}
    for name, identity in chain["originals"].items():
        need(identity["path"] == "chain/" + name, "chain original path differs")
        originals[name] = bind(relative(identity)["path"], relative(identity))
    for name, identity in chain["source_files"].items():
        need(identity["path"] == "source-files/" + name
             and identity["sha256"] == build_inputs["candidate_compile_inputs"][name],
             "frozen source-chain identity differs from the reviewed pre-format input")
    closure_id, closure = document(R33_CACHE_OWNER_CLOSURE)
    need(preparation["cache_owner_closure_input"] == closure_id,
         "preparation did not use the frozen original cache-owner closure inputs")
    need(closure["current_machine_idle_claimed"] is False,
         "cache owner closure cannot claim current whole-machine idleness")
    owner_proof = r33_cache_owner_closed(closure, build_inputs["qualification_harness_sha256"], bind)
    need(preparation["cache_owner_closure"] == owner_proof,
         "original cache-owner closure no longer matches the preparation receipt")
    return {"source_chain": chain_id, "original_chain_inputs": originals,
            "cache_owner_closure_input": closure_id, "cache_owner_evidence": owner_proof["inputs"],
            "cache_owner_closed": True, "r31_observation_performance_passed": False,
            "r31_lifecycle_abba_executed": False, "r31_adoption_claimed": False,
            "current_machine_idle_claimed": False, "original_auditors_reexecuted": False}


def r33_owner_native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False


def r33_owner_closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def r33_owner_completed_qualification(value, source, harness):
    assert value['schema'] == 'hepta-x230-composed-qualification/v1'
    assert value['qualified'] is True and value.get('finished_utc') and not value.get('error')
    assert value['source'] == str(source) and value['jobs'] == 2
    assert value['automatic_test_retries'] == 0 and value['service_changes'] is False
    assert [row['name'] for row in value['stages']] == R33_QUALIFICATION_STAGES
    assert all(row['returncode'] == 0 for row in value['stages'])
    assert value['source_tested'] == value['source_after'] == qualification_projection(source_inputs(source))
    assert value['harness_before'] == value['harness_after'] == harness


def r33_cache_owner_closed(value, harness, bind):
    assert value['schema'] == 'hepta-x230-r33-cache-owner-closure/v1'
    assert value['cache_owner'] == str(R33_CACHE_OWNER)
    assert value['cache_path'] == str(R33_CACHE_OWNER / 'target-build')
    assert value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r31_observation_performance_passed'] is False
    assert value['r31_lifecycle_abba_executed'] is False
    identities = value['inputs']
    paths = {
        'qualification_report': 'qualification-01/report.json',
        'qualification_native': 'qualification-terminal-status-01.json',
        'qualification_preparation': 'preparation-02.json',
        'exact_ci_report': 'rust-ci-02/report.json',
        'exact_ci_native': 'rust-ci-native-02.json',
        'observation_parent': 'campaign-02/report.json',
        'observation_native': 'observation-holder-native-02.json',
        'observation_report': 'campaign-02/native-observation/report.json',
        'observation_summary': 'campaign-02/summary.json',
        'lifecycle_materializer_native': 'lifecycle-materialization-native-01.json',
        'lifecycle_materializer_read': 'lifecycle-materialization-read-01.json',
    }
    assert set(identities) == set(paths)
    for label, relative in paths.items():
        assert identities[label]['path'] == str(R33_CACHE_OWNER / relative)
    receipts = {label: json.loads(bind(identity['path'], identity, retain=True)[1]) for label, identity in identities.items()}
    assert value['qualification_job_id'] == '1a1ae1c32b8-fc05-5d7a'
    r33_owner_native_terminal(receipts['qualification_native'], value['qualification_job_id'])
    qualified = receipts['qualification_report']
    r33_owner_completed_qualification(qualified, R33_CACHE_OWNER / 'source', harness)
    preparation = receipts['qualification_preparation']
    assert preparation['passed'] is True and preparation['qualification_returncode'] == 0
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == R33_BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']

    assert value['exact_ci_job_id'] == '1a1ae572e9e-fc05-5f26'
    r33_owner_native_terminal(receipts['exact_ci_native'], value['exact_ci_job_id'])
    ci = receipts['exact_ci_report']
    assert ci['schema'] == 'hepta-r31-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == value['qualification_job_id']
    r33_owner_closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    assert ci['nextest_output_audit']['verified'] is True
    assert ci['nextest_output_audit']['failed'] == ci['nextest_output_audit']['retries'] == 0

    assert value['observation_holder_job_id'] == '1a1ae66710c-fc05-5f6e'
    r33_owner_native_terminal(receipts['observation_native'], value['observation_holder_job_id'])
    parent = receipts['observation_parent']
    assert parent['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert parent['passed'] is True and parent.get('finished_utc') and not parent.get('error')
    assert parent['observation_gate_passed'] is False
    assert parent['rejection_reasons'] == ['C1 regression gate']
    assert parent['correctness_stages_completed'] is True and parent['measurement_attribution_valid'] is True
    assert parent['source_inputs_unchanged'] is True and parent['inputs_unchanged'] is True
    assert parent['compiler_monitor']['passed'] is True
    r33_owner_closed_stages(parent['stages'], ['native-observation', 'native-audit', 'native-boundary',
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
    assert summary['rejection_reasons'] == ['C1 regression gate']

    assert value['lifecycle_materializer_job_id'] == '1a1ae6ce842-fc05-5f8b'
    lifecycle_native = receipts['lifecycle_materializer_native']
    r33_owner_native_terminal(lifecycle_native, value['lifecycle_materializer_job_id'], 'failed', 1)
    lifecycle_read = receipts['lifecycle_materializer_read']
    assert lifecycle_read['job_id'] == value['lifecycle_materializer_job_id'] and lifecycle_read['audit_recorded'] is True
    raw = {name: bytes.fromhex(lifecycle_read[name]['bytes_hex']) for name in ('stdout', 'stderr')}
    for name in raw:
        assert len(raw[name]) == lifecycle_native['log_bytes'][name]['stored']
    assert raw['stderr'].endswith(b'RuntimeError: normal observation campaign did not close and pass\n')
    preserved = json.loads(raw['stdout'])
    assert preserved['phase'] == 'observation_originals_preserved'
    assert preserved['report_sha256'] == identities['observation_parent']['sha256']
    for name in ('lifecycle-inputs-02.json', 'lifecycle-campaign-02', 'lifecycle-abba-02'):
        assert not os.path.lexists(R33_CACHE_OWNER / name), 'unreviewed lifecycle output exists: ' + name
    return {'inputs': identities, 'qualification_and_exact_ci_succeeded': True,
            'observation_parent_completed': True, 'observation_controllers_closed': True,
            'observation_performance_passed': False, 'rejection_reasons': ['C1 regression gate'],
            'lifecycle_materializer_rejected_before_abba': True,
            'original_auditors_reexecuted': False, 'r31_adoption_claimed': False}

