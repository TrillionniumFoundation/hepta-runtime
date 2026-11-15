# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Pure original receipt functions embedded by the builder; never executed during preparation.

def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original R35 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original R35 native job identity required')
    need(ACTUAL.get('outcome') in {'passed', 'failed'} and type(ACTUAL.get('files')) is dict
         and set(ACTUAL['files']) == set(FUTURE_PATHS), 'actual qualification outcome/file inventory is unbound')
    for name, pin in ACTUAL['files'].items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual receipt pin: ' + name)
    need(all(ACTUAL['files'][name] is not None for name in
         ('preparation.json', 'qualification-terminal-status-01.json', 'qualification-native-read-01.json')),
         'actual preparation and complete original native receipts required')
    if ACTUAL['outcome'] == 'passed':
        need(all(pin is not None for pin in ACTUAL['files'].values()), 'successful qualification is missing raw evidence')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == {'passed', 'failed', 'ignored', 'selected', 'retries'}
             and all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored'], 'actual full test counts required')
        binaries = ACTUAL.get('qualified_binary_sha256')
        need(type(binaries) is dict and set(binaries) == BINARY_NAMES
             and all(type(v) is str and len(v) == 64 and set(v) <= set('0123456789abcdef')
                     for v in binaries.values()), 'actual retained runtime identities required')
    return ACTUAL



def original_streams(value, terminal):
    need(value.get('job_id') == terminal['job_id'] and value.get('audit_recorded') is True,
         'native read does not identify the original terminal')
    result = {}
    for name in ('stdout', 'stderr'):
        row = value[name]
        raw = bytes.fromhex(row['bytes_hex'])
        need(row['offset'] == 0 and row['eof'] is True
             and row['next_offset'] == row['size'] == len(raw) == terminal['log_bytes'][name]['stored']
             and row['text'] == raw.decode('utf-8', errors='replace'), 'incomplete original native stream: ' + name)
        result[name] = raw
    return result



def installation_summary(data):
    """Reconcile already completed installation receipts without running an installer."""
    prefix = 'installation-originals-01/'
    read = lambda name: json.loads(data[prefix + name])
    pin = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    history = read('installation-history-01.json')
    need(history['schema'] == 'hepta-r35-installation-history/v1'
         and history['failed_or_unknown_install_is_not_a_qualification_retry'] is True
         and history['cause_of_original_transport_failure_established'] is False,
         'installation history does not retain the unknown outcome')
    selected = set()
    for row in history['files']:
        name = row['path'] if row['path'] == 'qualification-package-install-02.json' else prefix + row['path']
        need(name in PINNED and name not in selected
             and {'bytes': len(data[name]), 'sha256': sha(data[name])}
             == {key: row[key] for key in ('bytes', 'sha256')},
             'installation history original differs: ' + name)
        selected.add(name)
    need(len(selected) == 14 and {name for name in data if name.startswith(prefix)}
         == (selected - {'qualification-package-install-02.json'}) | {prefix + 'installation-history-01.json'},
         'installation history has missing or extra selected originals')

    unknown = read('installation-original-start-01.json')
    original_job = '1a1af5e240e-fc05-67f8'
    need(unknown['audit_recorded'] is True and unknown['reused'] is False
         and unknown['job']['id'] == original_job and unknown['job']['launch_state'] == 'launch_unknown'
         and unknown['launch']['job_id'] == original_job and unknown['launch']['outcome'] == 'unknown'
         and unknown['launch']['state'] == 'launch_unknown'
         and unknown['launch']['status_authoritative'] is False
         and unknown['launch']['automatic_retry'] is False,
         'original launch_unknown response was replaced by a terminal result')
    need(history['original_install']['job_id'] == original_job
         and history['original_install']['launch_state'] == 'launch_unknown'
         and history['original_install']['native_terminal_result_available'] is False,
         'unavailable original native terminal was fabricated')
    for name in ('installation-original-status-error-01.txt', 'installation-original-read-error-01.txt'):
        need(b'FileNotFoundError' in data[prefix + name] and original_job.encode() in data[prefix + name],
             'original unavailable status/read error missing')
    external_payload = history['original_install']['stdin_script']
    need(external_payload == {'path': 'installation-original-payload-01.py', 'bytes': 477316,
         'sha256': '62397e09eee881494e8ed659eb8266f05c591b153224a5b3769ad796c4bff9c6'}
         and prefix + external_payload['path'] not in data,
         'separately retained original stdin identity differs')

    recon_job = '1a1af5f2833-fc05-6802'
    recon_native = read('installation-reconcile-native-01.json')
    native_terminal(recon_native, recon_job, 'succeeded', 0)
    recon_streams = original_streams(read('installation-reconcile-read-01.json'), recon_native)
    need(recon_streams['stderr'] == b'', 'reconciliation original stderr differs')
    recon = json.loads(recon_streams['stdout'])
    recon_start = read('installation-reconcile-start-01.json')
    need(recon_start['job']['id'] == recon_job and recon_start['job']['launch_state'] == 'launched'
         and recon_start['launch']['ok'] is True and recon_start['reused'] is False,
         'read-only reconciliation start identity differs')
    need(recon['schema'] == 'hepta-r35-unknown-package-install-readonly-reconciliation/v1'
         and recon['original_job_id'] == original_job
         and recon['root_exists'] is False and recon['job_directory_exists'] is False
         and recon['qualification_was_not_requested'] is True
         and recon['inputs_modified'] is False and recon['install_or_qualification_reexecuted'] is False
         and history['read_only_reconciliation']['job_id'] == recon_job
         and history['read_only_reconciliation']['observed_result'] == recon,
         'read-only original reconciliation differs')
    unit = recon['unit_query']
    fields = dict(line.split('=', 1) for line in unit['stdout'].splitlines())
    need(unit['returncode'] == 0 and unit['stderr'] == ''
         and fields == {'MainPID': '0', 'ExecMainPID': '0', 'LoadState': 'not-found',
                        'ActiveState': 'inactive', 'SubState': 'dead'},
         'original unit absence observation differs')

    installed = json.loads(data['qualification-package-install-02.json'])
    install_job = '1a1af611834-fc05-680f'
    install_native = read('installation-staged-native-02.json')
    native_terminal(install_native, install_job, 'succeeded', 0)
    install_streams = original_streams(read('installation-staged-read-02.json'), install_native)
    need(install_streams['stderr'] == b'', 'staged installation original stderr differs')
    install_start = read('installation-staged-start-02.json')
    need(install_start['job']['id'] == install_job and install_start['job']['launch_state'] == 'launched'
         and install_start['launch']['ok'] is True and install_start['reused'] is False,
         'staged installation start identity differs')
    output = json.loads(install_streams['stdout'])
    need(output['installed'] is True and output['root'] == str(ROOT)
         and output['receipt'] == pin('qualification-package-install-02.json'),
         'staged original native stdout does not bind installed receipt')
    manifest = json.loads(data['frozen-preparation-manifest.json'])
    expected = {row['path']: {key: row[key] for key in ('bytes', 'sha256')} for row in manifest['files']}
    expected['frozen-preparation-manifest.json'] = {key: pin('frozen-preparation-manifest.json')[key]
                                                 for key in ('bytes', 'sha256')}
    need(installed['schema'] == 'hepta-r35-qualification-package-install/v1'
         and installed['root'] == str(ROOT) and installed['file_count'] == len(expected) == 39
         and installed['files'] == expected and installed['expanded_file_bytes'] == 1383630
         and installed['archive_bytes'] == 354738
         and installed['archive_sha256'] == '7303e1ded7ac4aab5f02c5240b1e6211bbaf7ca8cd7ebe19d686546842366dba'
         and installed['original_minimum_free_bytes'] == 3 * 1024**3
         and installed['free_bytes_before_install'] == 6835855360,
         'original frozen package installation differs')
    need(all(installed[key] is False for key in ('qualification_started', 'source_materialized',
              'cache_moved', 'cache_deleted', 'production_services_modified')),
         'installation unexpectedly performed preparation or qualification')
    for name in ('file_count', 'expanded_file_bytes', 'archive_sha256', 'free_bytes_before_install',
                 'qualification_started', 'cache_moved', 'cache_deleted'):
        need(output[name] == installed[name], 'original installation stdout/report disagree: ' + name)
    need(history['staged_install'] == {'job_id': install_job, 'succeeded': True, 'exit_code': 0,
         'files': 39, 'expanded_bytes': 1383630, 'free_bytes_before': 6835855360,
         'qualification_started': False}, 'derived history disagrees with original installation')

    upload = read('package-upload-receipts-01.json')
    chunks = [json.loads(raw) for raw in upload['original_chunk_responses']]
    commit = json.loads(upload['original_commit_response'])
    need(upload['schema'] == 'hepta-r35-package-upload-original-receipts/v1'
         and upload['expected_version'] == 'absent'
         and upload['size'] == installed['archive_bytes'] and upload['sha256'] == installed['archive_sha256']
         and upload['path'] == installed['archive_path']
         and len(chunks) == 6 and [row['next_offset'] for row in chunks] == [
             65536, 131072, 196608, 262144, 327680, 354738]
         and all(row['visible'] is False and row['upload_id'] == upload['upload_id'] for row in chunks)
         and commit['committed'] is True and commit['reused'] is False
         and commit['size'] == upload['size'] and commit['sha256'] == upload['sha256']
         and commit['version'] == installed['archive_version'],
         'original chunk/commit receipts disagree with the installed package')

    launch = read('qualification-start-01.json')
    need(launch['audit_recorded'] is True and launch['reused'] is False
         and launch['job']['id'] == ACTUAL['qualification_job_id'] == '1a1af619097-fc05-6813'
         and launch['job']['launch_state'] == 'launched' and launch['launch']['ok'] is True
         and launch['job']['cwd'] == str(ROOT)
         and [launch['job']['executable'], *launch['job']['args']] == manifest['single_authorized_launch_argv']
         and history['first_qualification']['job_id'] == ACTUAL['qualification_job_id']
         and history['first_qualification']['automatic_retry_requested'] is False,
         'actual original qualification start differs from the frozen launch')
    return {
        'original_install': {'job_id': original_job, 'recorded_launch_state': 'launch_unknown',
            'native_terminal_available': False, 'terminal_state': None, 'exit_code': None,
            'complete_original_status_and_read_errors_preserved': True},
        'read_only_reconciliation': {'job_id': recon_job, 'original_observed_result': recon,
            'native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)}
                               for name, raw in recon_streams.items()}},
        'staged_install': {'job_id': install_job, 'reported_succeeded': True,
            'receipt': pin('qualification-package-install-02.json'),
            'native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)}
                               for name, raw in install_streams.items()},
            'package_members': 39, 'expanded_file_bytes': 1383630,
            'qualification_started_by_installer': False},
        'separate_chunked_delivery': {'chunks': len(chunks), 'bytes': upload['size'], 'sha256': upload['sha256']},
        'first_qualification_job_id': ACTUAL['qualification_job_id'],
        'installation_unknown_is_not_a_qualification_retry': True,
        'cause_of_original_transport_failure_established': False,
        'selected_original_files': 15,
        'large_original_stdin_body_in_archive': False,
        'large_original_stdin_identity_retained_separately': external_payload,
        'original_derived_history_kept_with_its_at_capture_pending_qualification_state': True,
        'installer_reconciliation_or_workload_reexecuted': False,
    }


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original R35 qualification may be archived')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin
             for name, pin in PINNED.items()), 'frozen preparation/installation input differs')
    for name, pin in actual['files'].items():
        need((name not in data) if pin is None else
             (name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin),
             'actual original qualification receipt presence/identity differs: ' + name)
    terminal = json.loads(data['qualification-terminal-status-01.json'])
    if actual['outcome'] == 'passed':
        native_terminal(terminal, actual['qualification_job_id'], 'succeeded', 0)
    else:
        need(terminal.get('state') == 'failed' and type(terminal.get('exit_code')) is int
             and terminal['exit_code'] != 0, 'failed archive requires the original failed terminal')
        native_terminal(terminal, actual['qualification_job_id'], 'failed', terminal['exit_code'])
    native = original_streams(json.loads(data['qualification-native-read-01.json']), terminal)
    installation = installation_summary(data)
    if actual['outcome'] == 'passed':
        result = qualified_summary(kind, data)
        need(result['counts'] == actual['counts'] and result['qualified_binary_sha256'] == actual['qualified_binary_sha256'],
             'actual frozen full inventory or runtime digest differs')
    else:
        prep = json.loads(data['preparation.json'])
        report = json.loads(data['qualification-01/report.json']) if 'qualification-01/report.json' in data else None
        tests = json.loads(data['qualification-01/isolated-tests/summary.json']) if 'qualification-01/isolated-tests/summary.json' in data else None
        audit = json.loads(data['qualification-01/isolated-tests.audit.json']) if 'qualification-01/isolated-tests.audit.json' in data else None
        counts = None if tests is None else {key: tests.get(key) for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
        binaries = None if report is None else {key: value.get('sha256') for key, value in report.get('binaries', {}).items()}
        need(counts == actual['counts'] and binaries == actual['qualified_binary_sha256'], 'raw failed inventory differs from its actual pins')
        result = {'kind': kind, 'qualified': False, 'original_job_id': terminal['job_id'],
            'outcome': 'failed', 'counts': counts, 'qualified_binary_sha256': binaries,
            'reported_preparation_passed': prep.get('passed'), 'preparation_error': prep.get('error'),
            'reported_qualified': None if report is None else report.get('qualified'),
            'qualification_error': None if report is None else report.get('error'),
            'reported_stage_results': [] if report is None else [
                {'name': row.get('name'), 'returncode': row.get('returncode')} for row in report.get('stages', [])],
            'reported_test_success': None if tests is None else tests.get('success'),
            'reported_test_fatal_error': None if tests is None else tests.get('fatal_error'),
            'reported_audit_success': None if audit is None else audit.get('success'),
            'reported_audit_errors': None if audit is None else audit.get('errors'),
            'missing_later_receipts': [name for name, pin in actual['files'].items() if pin is None],
            'failure_scope': 'exact raw first-attempt receipts preserved; no qualification or audit success inferred',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'tests_reexecuted': False, 'original_test_audit_reexecuted': False,
            'test_binary_hashes_recomputed': False, 'performance_adoption_evaluated': False}
    result['installation_preparation'] = installation
    result['native_original_logs'] = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in native.items()}
    return result

