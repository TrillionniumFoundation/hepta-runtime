# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Pure receipt binding functions embedded in the generated collector; not executed by the builder.


def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r34-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original R34 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original R34 native job identity required')
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


def cache_preparation_summary(data):
    read = lambda name: json.loads(data[name])
    identity = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    originals = 'cache-prune-tools-02/originals/'
    one = read('cache-prune-01/report.json')
    two = read('cache-prune-02/report.json')
    first_native = read(originals + 'native-terminal-original-01.json')
    second_native = read('cache-prune-native-02.json')
    native_terminal(first_native, '1a1aeeea99f-fc05-6440', 'failed', 1)
    native_terminal(second_native, '1a1aef5957d-fc05-6486', 'succeeded', 0)
    first_streams = original_streams(read(originals + 'native-read-original-01.json'), first_native)
    second_streams = original_streams(read('cache-prune-native-read-02.json'), second_native)
    need(first_streams['stderr'] == second_streams['stderr'] == b'', 'unexpected original prune stderr')
    need(data[originals + 'report-original-01.json'] == data['cache-prune-01/report.json'],
         'failed prune original copy differs')
    for number, value in (('01', one), ('02', two)):
        need(value['schema'] == 'hepta-r34-two-file-cache-prune/v1'
             and value['automatic_retries'] == value['subprocesses_started'] == value['directories_deleted'] == 0
             and value['cache_renamed'] is False and value['source_or_threshold_modified'] is False
             and value['minimum_free_bytes'] == 3 * 1024 ** 3 and value['postcheck_errors'] == []
             and value['independent_retained_programs_unchanged'] is True
             and value['unselected_cache_entries_unchanged'] is True,
             'original cache preparation invariants differ: ' + number)
        need(value['tool'] == identity('cache-prune-tools-' + number + '/prune_cache.py')
             and value['plan'] == identity('cache-prune-tools-' + number + '/plan.json')
             and value['helper_launcher'] == identity('prepare_qualify.py'), 'original prune tool/plan/helper differs')
        for pin in value['receipts'].values():
            relative = Path(pin['path']).relative_to(ROOT).as_posix()
            need(relative.startswith('cache-prune-' + number + '/') and pin == identity(relative),
                 'original prune receipt bytes differ: ' + relative)
    need(one['passed'] is False and one['deletions'] == []
         and one['error'] == 'RuntimeError: candidate fixed stat differs: hepta_runtime-1b8b761b89392e3b',
         'original zero-deletion failure was changed or omitted')
    need(two['passed'] is True and 'error' not in two and two['two_requested_files_unlinked'] is True
         and two['free_space_gate_met'] is True and two['free_bytes_after'] == 3566792704,
         'original second prune successful result differs')
    expected_paths = ['debug/deps/hepta_runtime-1b8b761b89392e3b',
                      'debug/deps/libhepta_runtime-564505b54e9d81cd.rlib']
    need([row['path'] for row in two['deletions']] == expected_paths
         and two['observed_absent_allowed_candidates'] == expected_paths
         and all(all(row[k] is True for k in ('unlinked', 'path_absent', 'opened_inode_unlinked', 'parent_synced'))
                 for row in two['deletions']), 'second prune did not record exactly the two intended deletions')
    need(two['deletions'][0]['sha256'] == 'e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1',
         'original test artifact digest differs from the retained-audit provenance')
    for raw, value, number in ((first_streams['stdout'], one, '01'), (second_streams['stdout'], two, '02')):
        output = json.loads(raw)
        need(output['passed'] == value['passed'] and output['deleted'] == len(value['deletions'])
             and output['report'] == identity('cache-prune-' + number + '/report.json'),
             'original native prune stdout does not bind the report')
    need(sha(data['cache-prune-01/cache-before.json']) == sha(data['cache-prune-01/cache-after.json'])
         == sha(data['cache-prune-02/cache-before.json'])
         == '9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154',
         'failed prune was not a zero-change predecessor of the second attempt')
    need(len({sha(data['cache-prune-' + number + '/owner-' + side + '.json'])
              for number in ('01', '02') for side in ('before', 'after')}) == 1,
         'original owner/retained receipts differ between cache preparations')
    plan1, plan2 = read('cache-prune-tools-01/plan.json'), read('cache-prune-tools-02/plan.json')
    wrong = ['1793930603038937300', '1793930262097573600']
    exact = ['1793930603038937265', '1793930262097573724']
    need([str(row['stat']['mtime_ns']) for row in plan1['candidates']] == wrong
         and [row['stat']['mtime_ns'] for row in plan2['candidates']] == exact,
         'original imprecise and corrected input identities were not both preserved')
    cross_native = read(originals + 'precision-native-terminal-original-01.json')
    native_terminal(cross_native, '1a1aef15be1-fc05-6460', 'succeeded', 0)
    cross_streams = original_streams(read(originals + 'precision-native-read-original-01.json'), cross_native)
    need(cross_streams['stdout'] == data[originals + 'precision-crosscheck-original-01.json']
         and cross_streams['stderr'] == b'', 'original precision crosscheck native bytes differ')
    cross = read(originals + 'precision-crosscheck-original-01.json')
    need(cross['read_only'] is True and cross['source_sha256'] == sha(data['cache-prune-01/cache-before.json'])
         and [row['path'] for row in cross['rows']] == expected_paths
         and all(row['live_selected_stat_matches_original'] is True for row in cross['rows'])
         and [row['original_cache_before_stat_decimal']['mtime_ns'] for row in cross['rows']] == exact,
         'original exact integer crosscheck differs')
    return {
        'attempts': [{'job_id': first_native['job_id'], 'reported_passed': False, 'deleted': 0,
                      'error': one['error'], 'report': identity('cache-prune-01/report.json')},
                     {'job_id': second_native['job_id'], 'reported_passed': True, 'deleted': 2,
                      'report': identity('cache-prune-02/report.json')}],
        'input_precision_correction': {'first_supplied_mtime_ns': wrong, 'exact_decimal_mtime_ns': exact,
            'method': 'original exact bytes parsed as Python integers; no JS Number or tolerance comparison'},
        'original_free_bytes_after_second_prune': two['free_bytes_after'],
        'minimum_free_bytes_unchanged': 3 * 1024 ** 3,
        'metadata_only_no_cache_or_elf_content': True,
        'raw_cache_before_after_manifests_included': 4,
        'retained_hashes_supported_by_original_receipts': True,
        'retained_or_deleted_elf_rehashed': False, 'pruner_or_helper_reexecuted': False,
    }


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original R34 qualification may be archived')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin
             for name, pin in PINNED.items()), 'frozen preparation/prune input differs')
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
    cache = cache_preparation_summary(data)
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
    result['cache_preparation'] = cache
    result['native_original_logs'] = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in native.items()}
    return result
