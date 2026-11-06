def frozen_candidate(manifest):
    assert manifest['schema'] == 'hepta-d1-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['source_construction_parent'] == BASELINE_COMMIT
    assert manifest['published_candidate_commit'] == '5d3fecbeb1d67c288917598f55932e64c878f1e5'
    assert manifest['published_candidate_parent'] == '86155fbf3b89e5a77e2a4aadebd2128c663fe50b'
    assert manifest['candidate_catalog_git_blob'] == 'e100bf52d1b6d4c28113a17bd777c67d98c144e0'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 53222,
        'sha256': 'd2c45351d8a11a1f472c06e68689c43e8ab821ee3c93428057de401644fb59cc'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/package-manifest.json', 'bytes': 10557,
        'sha256': '3f5944705884d1e071f28978fc7ffb911875bf2a93a9c719b2cbe076bbb78fe0'}
    candidate = json.loads(read_bound(relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-r24-phase-cost-preparation-package/v1'
    assert frozen['revision'] == candidate['revision'] == 'recovery-02'
    assert frozen['baseline_commit'] == BASELINE_COMMIT and frozen['diagnostic_name'] == 'D1'
    assert frozen['performance_acceptance_claim'] is False
    assert frozen['original_qualifier_all_features'] is True and frozen['original_qualifier_changed'] is False
    assert frozen['ordinary_original_package_feature_set'] == []
    assert frozen['candidate_package_feature_set'] == ['phase-cost-diagnostics']
    seen, files = set(), {}
    for identity in frozen['files']:
        name = identity['path']
        assert name not in seen
        seen.add(name)
        files[name] = read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))
    assert len(seen) == frozen['file_count'] == 38
    assert candidate['schema'] == 'hepta-r24-phase-cost-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['baseline_count'] == 220 and candidate['candidate_count'] == 222
    assert candidate['patch_sha256'] == '3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523'
    assert candidate['patch_bytes'] == 64987 and len(files['candidate.patch']) == candidate['patch_bytes']
    assert set(candidate['changed_paths']) == CHANGED and set(candidate['added_paths']) == ADDED
    assert candidate['nondefault_feature'] == 'phase-cost-diagnostics' and candidate['feature_platform'] == 'linux'
    assert candidate['dependency_changes'] == [] and candidate['release_profile_changes'] == []
    assert candidate['runtime_gate_changes'] == [] and candidate['acceptance_threshold_changes'] == []
    assert candidate['original_remote_python_changed'] is False and candidate['performance_acceptance_claim'] is False
    assert set(candidate['new_test_functions']) == NEW_TESTS
    for field in ('actual_qualification', 'actual_formatted_source_map', 'actual_default_build',
                  'actual_feature_build', 'actual_elf', 'actual_native_jobs', 'actual_measurements'):
        assert candidate[field] is None
    baseline = json.loads(files['baseline-source-map.json'])
    expected = json.loads(files['candidate-source-map.json'])
    assert baseline == candidate['baseline_compile_inputs'] and expected == candidate['candidate_compile_inputs']
    assert len(baseline) == 220 and len(expected) == 222
    assert set(expected) - set(baseline) == ADDED and not set(baseline) - set(expected)
    assert {name for name in expected if expected[name] != baseline.get(name)} == CHANGED
    for name in CHANGED:
        assert hashlib.sha256(files['source/' + name]).hexdigest() == expected[name]
    old_cargo = tomllib.loads((BASE / 'source/Cargo.toml').read_text())
    new_cargo = tomllib.loads(files['source/Cargo.toml'].decode('utf-8'))
    assert old_cargo.get('features', {}) == {} and new_cargo['features'] == {'phase-cost-diagnostics': []}
    assert {k: v for k, v in new_cargo.items() if k != 'features'} == old_cargo
    assert manifest['qualification_rule']['original_all_features'] is True
    assert manifest['qualification_rule']['diagnostic_environment'] == 'absent'
    assert manifest['qualification_rule']['ordinary_supplemental_run_by_this_preparer'] is False
    patch = frozen['candidate_patch']
    assert patch['sha256'] == candidate['patch_sha256'] and patch['bytes'] == candidate['patch_bytes']
    return candidate, relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def native_stream_pages(pages, terminal):
    """Verify original read pages; never replace them with a fabricated single page."""
    assert isinstance(pages, list) and 1 <= len(pages) <= 16
    offsets = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for index, page in enumerate(pages):
        assert page['job_id'] == terminal['job_id'] and page['audit_recorded'] is True
        for name in ('stdout', 'stderr'):
            channel = page[name]
            raw = bytes.fromhex(channel['bytes_hex'])
            total = terminal['log_bytes'][name]['stored']
            assert type(total) is int and 0 <= total <= 256 * 1024
            assert type(channel['offset']) is int and channel['offset'] == offsets[name]
            assert channel['size'] == total and len(raw) <= 16384
            assert channel['next_offset'] == channel['offset'] + len(raw) <= total
            assert channel['text'] == raw.decode('utf-8', errors='replace')
            assert channel['eof'] is (channel['next_offset'] == total)
            # A stream already at EOF may recur as an empty EOF on later calls.
            # A pending stream must make progress, with no gaps or overlaps.
            assert raw or offsets[name] == total
            if index + 1 == len(pages):
                assert channel['eof'] is True
            offsets[name] = channel['next_offset']
            chunks[name].append(raw)
    assert all(offsets[name] == terminal['log_bytes'][name]['stored'] for name in offsets)
    return {name: b''.join(parts) for name, parts in chunks.items()}


def postflight_bytes(report_raw, terminal_raw, page_raws, receipt_identity):
    """Validate actual successful postflight custody without reading any host file."""
    report, terminal = json.loads(report_raw), json.loads(terminal_raw)
    native_terminal(terminal, OWNER_POSTFLIGHT_JOB)
    assert terminal['audit_recorded'] is True
    assert terminal['log_bytes']['stdout'] == {'seen': 46206, 'stored': 46206}
    assert terminal['log_bytes']['stderr'] == {'seen': 0, 'stored': 0}
    assert len(page_raws) == 3
    pages = [json.loads(raw) for raw in page_raws]
    assert [page['stdout']['offset'] for page in pages] == [0, 16384, 32768]
    streams = native_stream_pages(pages, terminal)
    assert streams['stderr'] == b'' and streams['stdout'].endswith(b'\n')
    assert hashlib.sha256(streams['stdout']).hexdigest() == '7820315a573794b9f6789d04ff71283cae1510fffb15d719da886b960a29b0fd'
    rows = streams['stdout'].splitlines()
    assert len(rows) == 1
    original_receipt = {'path': str(CACHE_OWNER / 'lifecycle-owner-postflight-01.json'),
                        'bytes': len(report_raw), 'sha256': hashlib.sha256(report_raw).hexdigest()}
    assert receipt_identity['bytes'] == original_receipt['bytes']
    assert receipt_identity['sha256'] == original_receipt['sha256']
    assert json.loads(rows[0]) == {'receipt': original_receipt, **report}
    assert report['schema'] == 'hepta-r35-rejected-lifecycle-owner-postflight/v1'
    assert report['postflight_job_id_from_supervisor'] == OWNER_POSTFLIGHT_JOB
    assert report['postflight_script'] == {
        'path': str(CACHE_OWNER / 'postflight_r35_lifecycle_owner_01.py'), 'bytes': 46387,
        'sha256': '6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e'}
    assert report['accepted_baseline_commit'] == BASELINE_COMMIT
    assert report['cache_owner'] == str(CACHE_OWNER) and report['cache_path'] == str(CACHE_OWNER / 'target-build')
    for name in ('cache_moved', 'cache_deleted', 'candidate_adopted', 'current_machine_idle_claimed',
                 'tests_benchmarks_or_auditors_reexecuted', 'archive_member_verifier_reexecuted',
                 'original_observation_postflight_modified'):
        assert report[name] is False
    for name in ('future_preparer_must_check_cache_referencing_processes', 'current_source_matches_qualified_map',
                 'qualification_harness_matches_original', 'source_harness_and_retained_programs_rechecked_before_output',
                 'qualification_completed', 'exact_ci_closed', 'observation_workflow_closed', 'observation_gate_passed',
                 'observation_performance_passed', 'lifecycle_materialization_started', 'normal_lifecycle_started',
                 'normal_lifecycle_workflow_closed', 'normal_lifecycle_controllers_closed', 'normal_lifecycle_gate_verified',
                 'lifecycle_archive_whole_file_identity_rechecked'):
        assert report[name] is True
    assert report['compiler_input_count'] == 220 and report['embedded_python_input_count'] == 17
    assert report['qualification_harness_count'] == 19 and report['retained_release_program_count'] == 3
    assert report['qualification_counts'] == report['exact_ci_counts'] == OWNER_COUNTS
    assert report['observation_rejection_reasons'] == [] and report['new_workloads_started'] == 0
    assert report['normal_lifecycle_reported_workflow_passed'] is False
    assert report['normal_lifecycle_reported_adoption_passed'] is False and report['normal_lifecycle_gate_passed'] is False
    assert report['normal_lifecycle_rounds'] == 4 and report['normal_lifecycle_standard_shutdown_count'] == 8
    assert len(report['normal_lifecycle_shutdowns']) == 8
    assert report['normal_lifecycle_required_failed_flags'] == [
        {'comparison': 'concurrent_cancel', 'gate': 'throughput', 'adoption_required': True}]
    fields = {'qualification': 'original_qualification_job_id', 'exact_ci': 'original_exact_ci_job_id',
              'observation': 'original_observation_job_id', 'lifecycle_materialization': 'original_lifecycle_materializer_job_id',
              'normal_lifecycle': 'original_normal_lifecycle_job_id'}
    assert all(report[field] == OWNER_JOBS[name] for name, field in fields.items())
    for name, state, code in (('observation_holder', 'succeeded', 0), ('lifecycle_holder', 'failed', 1)):
        row = report[name]
        key = 'observation' if name == 'observation_holder' else 'normal_lifecycle'
        assert row['job_id'] == OWNER_JOBS[key] and row['state'] == state and row['exit_code'] == code
        assert all(row[field] is True for field in ('complete_native_bytes_verified', 'owned_agent_reaped',
                   'owned_agent_directory_absent', 'owned_agent_socket_absent'))
    assert isinstance(report['originals'], dict) and len(report['originals']) == 150
    for name, identity in report['originals'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert identity['path'] == str(CACHE_OWNER / relative)
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    return report
