def require_sealed():
    need(not sys.flags.optimize, 'original receipt assertions must be enabled')
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d1-c1-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True,
         'UNSEALED: actual original holder terminal/pages and captured C1 receipts are required')
    job = ACTUAL.get('holder_original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual holder job identity is missing')
    need(ACTUAL.get('outcome') in {'diagnostic_passed', 'not_passed'}, 'actual diagnostic outcome missing')
    pages = ACTUAL.get('native_read_paths')
    need(type(pages) is list and 1 <= len(pages) <= 16
         and pages == ['c1-holder-native-read-01-%03d.json' % i for i in range(len(pages))],
         'complete original contiguous holder page inventory required')
    files = ACTUAL.get('files')
    need(type(files) is dict and set(files) == set(CORE_PATHS) | set(pages),
         'actual captured core file inventory differs')
    for name, pin in files.items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual pin: ' + name)
    need(all(files[name] is not None for name in ['c1-holder-native-01.json', *pages]),
         'actual original holder terminal and stored native pages are mandatory')
    if ACTUAL['outcome'] == 'diagnostic_passed':
        need(all(files[name] is not None for name in CORE_PATHS
                 if name != 'c1-holder-start-01.json'), 'successful diagnostic receipts are incomplete')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == set(COUNTS)
             and all(type(value) is int and value >= 0 for value in counts.values()),
             'actual original native counts are incomplete')
    return ACTUAL


def archived_identity(data, name):
    need(name in data, 'required original is not in the archive: ' + name)
    return {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}


def match_original(data, pin):
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact original identity required')
    path = Path(pin['path'])
    need(path.is_absolute() and path.is_relative_to(ROOT), 'original is outside the fixed C1 source root')
    name = path.relative_to(ROOT).as_posix()
    need(archived_identity(data, name) == pin, 'archived original differs: ' + name)
    return name


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'c1', 'this script only archives the original C1 diagnostic capture')
    for name, pin in {**PINNED, **actual['files']}.items():
        if pin is None:
            need(name not in data, 'original declared absent appeared: ' + name)
        else:
            need(name in data and pin == {'bytes': len(data[name]), 'sha256': sha(data[name])},
                 'frozen original input differs: ' + name)
    native, streams = captured_native(data, 'c1-holder-native-01.json', actual['native_read_paths'],
        actual['holder_original_job_id'], actual['outcome'] == 'diagnostic_passed')
    errors, documents = [], {}
    for name in CORE_PATHS:
        if name in data and name.endswith('.json'):
            try:
                value = json.loads(data[name])
                need(type(value) is dict, 'original JSON root is not an object')
                documents[name] = value
            except (ValueError, TypeError, UnicodeError) as error:
                errors.append({'path': name, 'type': type(error).__name__, 'reason': str(error)[:1000]})

    def checked(label, callback):
        try:
            callback()
        except (KeyError, IndexError, ValueError, TypeError, AssertionError) as error:
            errors.append({'binding': label, 'type': type(error).__name__, 'reason': str(error)[:1500]})

    def relative_capture(directory, pin, filename):
        need(type(pin) is dict and pin.get('file') == filename,
             'original relative capture filename differs')
        observed = archived_identity(data, directory + '/' + filename)
        need(pin.get('bytes') == observed['bytes'] and pin.get('sha256') == observed['sha256'],
             'original relative capture bytes differ')

    parent = documents.get('c1-campaign-01/report.json')
    diagnostic = documents.get('c1-campaign-01/summary.json')
    observation = documents.get('c1-observation-01/report.json')
    audit = documents.get('c1-observation-01/independent-summary.json')
    adapted = documents.get('c1-adapter-evidence-01/adapter-report.json')
    holder = documents.get('c1-holder-report-01.json')
    monitor = documents.get('c1-campaign-01/compiler-monitor.audit.json')
    ledger = documents.get('c1-campaign-01/compiler-monitor.json')
    counts = None if audit is None else {key: audit.get(key) for key in COUNTS}
    need(counts == actual.get('counts'), 'actual captured original native counts differ')
    successful = actual['outcome'] == 'diagnostic_passed'
    stages, closures, traces, holder_logs = [], [], [], []

    if parent is not None:
        def parent_binding():
            need(parent['schema'] == 'hepta-d1-c1-campaign-control/v1'
                 and parent['attempt'] == '01' and parent['automatic_retries'] == 0
                 and parent['candidate_adopted'] is False and parent['performance_acceptance_claim'] is False
                 and parent['normal_lifecycle_started'] is False and parent['capacity_workload_started'] is False,
                 'original parent scope differs')
            need(parent['launcher_sha256'] == sha(data['c1-tools-01/d1_campaign.py']),
                 'original parent transmitted source differs')
            match_original(data, parent['input_receipt'])
            for name in ('prerequisite_inputs', 'qualification_binder', 'adapter', 'source_inputs',
                         'baseline_source_inputs', 'pre_execution_clarification', 'summary'):
                if name in parent:
                    match_original(data, parent[name])
            if successful:
                need(parent['passed'] is True and parent['diagnostic_evidence_passed'] is True
                     and parent['inputs_unchanged'] is True and parent['source_inputs_unchanged'] is True
                     and parent['baseline_source_inputs_unchanged'] is True
                     and parent['qualified_source_maps_match_current_inputs'] is True
                     and parent['measurement_attribution_valid'] is True
                     and parent['quiescence']['passed'] is True and parent.get('finished_utc')
                     and not parent.get('error'), 'original successful parent closure differs')
        checked('parent scope and original identities', parent_binding)
        rows = parent.get('stages', [])
        if type(rows) is list:
            for row in rows:
                if type(row) is not dict:
                    errors.append({'binding': 'stage', 'reason': 'original stage is not an object'})
                    continue
                stages.append({key: row.get(key) for key in ('name', 'returncode', 'passed',
                    'waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent',
                    'cleanup_error', 'independent_controller_cleanup')})
                for stream in ('stdout', 'stderr'):
                    if stream in row:
                        checked('stage ' + str(row.get('name')) + ' ' + stream,
                                lambda row=row, stream=stream: match_original(data, row[stream]))
                for pin in row.get('output_bindings', []):
                    checked('stage original output', lambda pin=pin: match_original(data, pin))
            def stage_binding():
                names = [row['name'] for row in rows]
                need(names == STAGES[:len(names)], 'original stage order is not a prefix')
                if successful:
                    need(names == STAGES and all(row['returncode'] == 0 and row['passed'] is True
                         and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                         and row['owned_process_group_absent'] is True and not row.get('cleanup_error')
                         for row in rows), 'original stage child custody is incomplete')
            checked('original stage custody', stage_binding)
        else:
            errors.append({'binding': 'stages', 'reason': 'original stages are not a list'})
        proof = parent.get('compiler_monitor', {})
        if type(proof) is dict:
            for field in ('ledger', 'independent_audit'):
                if field in proof:
                    checked('compiler monitor ' + field,
                            lambda field=field: match_original(data, proof[field]))

    if monitor is not None:
        def monitor_binding():
            need(monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1', 'original monitor schema differs')
            match_original(data, monitor['ledger'])
            match_original(data, monitor['validator'])
            if successful:
                need(monitor['validation']['passed'] is True and monitor['monitor_sources_unchanged'] is True
                     and monitor['source_recheck_errors'] == [] and ledger is not None and ledger['passed'] is True
                     and parent['compiler_monitor']['passed'] is True,
                     'original monitor/audit did not close')
        checked('original compiler monitor and audit', monitor_binding)

    if observation is not None:
        def observation_binding():
            need(observation['schema'] == 'hepta-x230-readonly-observation-abba/v2'
                 and observation['order'] == 'ABBA' and observation['concurrency'] == [1]
                 and observation['calls_per_cell'] == 192 and observation['tokio_workers'] == 2,
                 'original C1 matrix protocol differs')
            if successful:
                need(observation['passed'] is True and not observation.get('error')
                     and observation['source_originals_unchanged'] is True
                     and observation['binary_hashes_unchanged'] is True
                     and observation['topology_manifest_unchanged'] is True
                     and observation['binary_sha256']['A'] == observation['binary_sha256']['B'],
                     'original same-ELF matrix did not close')
        checked('original native matrix', observation_binding)
        rounds = observation.get('rounds', [])
        if type(rounds) is list:
            for index, row in enumerate(rounds):
                if type(row) is not dict or index >= 4:
                    errors.append({'binding': 'rounds', 'reason': 'unexpected original round shape'})
                    continue
                arm = 'ABBA'[index]
                for phase, field in (('first', 'shutdown'), ('restart', 'restart_shutdown')):
                    closed = row.get(field)
                    if type(closed) is not dict:
                        continue
                    directory = 'c1-observation-01/round-%d-%s/%s' % (index, arm, phase)
                    closures.append({'round': index, 'arm': arm, 'phase': phase,
                        'exit_code': closed.get('exit_code'), 'shutdown_method': closed.get('shutdown_method'),
                        'observed_descendant_survivors': closed.get('observed_descendant_survivors'),
                        'reader_error': closed.get('reader_error'), 'unmatched_responses': closed.get('unmatched_responses')})
                    def close_binding(closed=closed, directory=directory):
                        capture = closed['transport_capture']
                        relative_capture(directory, capture['raw'], 'transport-responses.jsonl')
                        relative_capture(directory, capture['index'], 'transport-responses.index.jsonl')
                        relative_capture(directory, closed['resources']['trace'], 'resource-samples.jsonl')
                        if successful:
                            need(closed['exit_code'] == 0 and closed['shutdown_method'] == 'stdin_eof'
                                 and closed['observed_descendant_survivors'] == []
                                 and closed['reader_error'] is None and closed['unmatched_responses'] == 0
                                 and capture['reader_eof'] is True and closed['resources']['sampler_error'] is None,
                                 'original controller normal close is incomplete')
                    checked('controller %d/%s raw closure' % (index, phase), close_binding)
        if successful:
            checked('eight original controller closes', lambda: need(len(closures) == 8,
                    'successful original matrix does not contain eight closes'))

    if audit is not None:
        def audit_binding():
            need(audit['schema'] == 'hepta-native-observation-independent-analysis/v3'
                 and audit['original_bytes'] == len(data['c1-observation-01/report.json'])
                 and audit['original_sha256'] == sha(data['c1-observation-01/report.json']),
                 'original native auditor input identity differs')
            if successful:
                need(audit['verified'] is True
                     and counts == dict(zip(COUNTS, (768, 96, 72, 936, 0)))
                     and [case['concurrency'] for case in audit['cases']] == [1]
                     and audit['binary_sha256'] == observation['binary_sha256'],
                     'original auditor did not verify the fixed C1 protocol')
        checked('original native auditor receipt', audit_binding)

    if adapted is not None:
        def adapter_binding():
            need(adapted['schema'] == 'hepta-d1-c1-phase-cost-adapter/v1'
                 and adapted['performance_acceptance_claim'] is False,
                 'original adapter scope differs')
            match_original(data, adapted['adapter_source'])
            if 'original_report' in adapted:
                match_original(data, adapted['original_report'])
            if successful:
                need(adapted['original_returncode'] == 0 and adapted['original_wrapper_returned'] is True
                     and adapted['controller_close_evidence_complete'] is True and adapted['analysis_complete'] is True
                     and adapted['all_trace_reads_after_original_matrix'] is True and adapted['errors'] == []
                     and len(adapted['traces']) == len(adapted['bindings']) == 8,
                     'original adapter analysis or custody is incomplete')
        checked('original adapter receipt', adapter_binding)
        rows = adapted.get('traces', [])
        if type(rows) is list:
            for index, row in enumerate(rows):
                if type(row) is not dict or index >= 8:
                    errors.append({'binding': 'traces', 'reason': 'unexpected original trace entry'})
                    continue
                binding = row.get('binding', {})
                traces.append({'binding': binding, 'trace': row.get('trace'),
                    'raw_transport': row.get('raw_transport'), 'raw_transport_index': row.get('raw_transport_index'),
                    'selected_on_counts': row.get('selected_on_counts')})
                def trace_binding(row=row, binding=binding, index=index):
                    round_index, phase = index // 2, ('first' if index % 2 == 0 else 'restart')
                    arm = 'ABBA'[round_index]
                    directory = ROOT / 'c1-observation-01' / ('round-%d-%s' % (round_index, arm)) / phase
                    need(binding == adapted['bindings'][index] and binding['round'] == round_index
                         and binding['arm'] == arm and binding['phase'] == phase
                         and binding['mode'] == ('off' if arm == 'A' else 'on')
                         and binding['directory'] == str(directory)
                         and row['trace']['path'] == str(directory / 'phase-cost.trace.jsonl'),
                         'trace binding is outside the original eight slots')
                    for key in ('trace', 'raw_transport', 'raw_transport_index'):
                        match_original(data, row[key])
                    if successful:
                        expected = dict.fromkeys(('preflight', 'warmup', 'measured', 'restart'), 0)
                        if arm == 'B':
                            expected.update({'preflight': 6, 'warmup': 24, 'measured': 192}
                                            if phase == 'first' else {'restart': 12})
                        need(row['selected_on_counts'] == expected,
                             'original selected request category counts differ')
                checked('original trace identity %d' % index, trace_binding)

    if diagnostic is not None:
        def diagnostic_binding():
            need(diagnostic['schema'] == 'hepta-d1-c1-diagnostic-evidence/v1'
                 and diagnostic['performance_acceptance_claim'] is False and diagnostic['candidate_adopted'] is False,
                 'diagnostic summary is not an optimization acceptance')
            for key in ('native_report', 'native_audit', 'adapter_report'):
                match_original(data, diagnostic[key])
            if successful:
                need(diagnostic['evidence_verified'] is True and diagnostic['same_elf'] is True
                     and diagnostic['mode_order'] == ['off', 'on', 'on', 'off']
                     and diagnostic['counts'] == counts, 'original diagnostic summary differs')
        checked('original diagnostic summary', diagnostic_binding)

    if holder is not None:
        def holder_binding():
            need(holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1', 'original holder schema differs')
            need(holder['remote_script_sha256'] == sha(data['c1-tools-01/d1_campaign.py']),
                 'holder transmitted another parent')
            if successful:
                need(holder['passed'] is True and holder['remote_returncode'] == 0
                     and holder['owned_agent_reaped'] is True
                     and holder['owned_agent_directory_absent_after_context'] is True
                     and holder['owned_agent_socket_absent_after_context'] is True
                     and not holder.get('error'), 'original held-agent custody is incomplete')
            terminal_lines = [json.loads(line) for line in streams['stdout'].splitlines() if line.strip()]
            need(terminal_lines and terminal_lines[-1]['report'] == str(MAC_HOLDER / 'report.json')
                 and terminal_lines[-1]['passed'] == holder['passed']
                 and terminal_lines[-1]['remote_returncode'] == holder['remote_returncode']
                 and terminal_lines[-1]['owned_agent_reaped'] == holder.get('owned_agent_reaped'),
                 'original native completion line and holder report differ')
        checked('original holder and native completion', holder_binding)
        rows = holder.get('log_files', [])
        if type(rows) is list:
            for pin in rows:
                def holder_log_binding(pin=pin):
                    need(type(pin) is dict and set(pin) == {'file', 'bytes', 'sha256'}
                         and type(pin['file']) is str and Path(pin['file']).name == pin['file']
                         and pin['file'] not in {'', '.', '..'}, 'unsafe original holder filename')
                    path = MAC_HOLDER / pin['file']
                    need(path.name not in SKIP_FILES, 'unsafe holder original path')
                    destination = 'c1-holder-originals-01/' + path.name
                    observed = archived_identity(data, destination)
                    need(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256'],
                         'original Mac holder log copy differs')
                    holder_logs.append({'original': pin, 'original_directory': str(MAC_HOLDER),
                                        'archived': observed})
                    if path.name == 'remote-script.py':
                        need(data[destination] == data['c1-tools-01/d1_campaign.py'],
                             'original transmitted source copy differs')
                checked('original holder log copy', holder_log_binding)
            if successful:
                checked('complete holder log copies', lambda: need(len(holder_logs) == len(rows),
                        'original holder log copy inventory incomplete'))

    source = documents.get('c1-campaign-01/source-inputs.json')
    baseline = documents.get('c1-campaign-01/baseline-source-inputs.json')
    if successful:
        def source_binding():
            need(source is not None and baseline is not None and source['file_count'] == 222
                 and baseline['file_count'] == 220 and len(source['files']) == 222
                 and len(baseline['files']) == 220,
                 'original compiler input snapshots differ')
        checked('original source input snapshots', source_binding)
    raw_trace_names = sorted(name for name in data if name.startswith('c1-observation-01/')
                             and name.endswith('/phase-cost.trace.jsonl'))
    expected_trace_names = ['c1-observation-01/round-%d-%s/%s/phase-cost.trace.jsonl' % (i, arm, phase)
                            for i, arm in enumerate('ABBA') for phase in ('first', 'restart')]
    checked('fixed raw trace paths', lambda: need(set(raw_trace_names) <= set(expected_trace_names)
             and (not successful or set(raw_trace_names) == set(expected_trace_names)),
             'raw trace inventory differs from the original eight fixed slots'))
    return {'schema': 'hepta-d1-c1-evidence-summary/v1',
        'original_job_id': actual['holder_original_job_id'], 'outcome': actual['outcome'], 'counts': counts,
        'reported_parent_passed': None if parent is None else parent.get('passed'),
        'reported_diagnostic_evidence_passed': None if parent is None else parent.get('diagnostic_evidence_passed'),
        'reported_adapter_analysis_complete': None if adapted is None else adapted.get('analysis_complete'),
        'reported_native_audit_verified': None if audit is None else audit.get('verified'),
        'captured_originals_binding_verified': not errors, 'receipt_binding_errors': errors,
        'original_holder_terminal': native,
        'original_holder_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in streams.items()},
        'parent_stages': stages, 'original_controller_closures': closures,
        'original_trace_bindings': traces, 'raw_trace_files': [archived_identity(data, name) for name in raw_trace_names],
        'raw_trace_file_count': len(raw_trace_names), 'original_holder_log_copies': holder_logs,
        'original_compiler_monitor': None if parent is None else parent.get('compiler_monitor'),
        'original_monitor_validation': None if monitor is None else monitor.get('validation'),
        'original_monitor_sample_count': None if ledger is None or type(ledger.get('samples')) is not list
            else len(ledger['samples']),
        'original_errors': {name: value.get('error', value.get('errors')) for name, value in documents.items()
                            if value.get('error') or value.get('errors')},
        'external_prerequisite_references': EXTERNAL_EVIDENCE_REFERENCES,
        'external_prerequisite_bodies_revalidated_here': False,
        'original_native_auditor_reexecuted': False, 'original_trace_parser_reexecuted': False,
        'original_compiler_monitor_validator_reexecuted': False, 'release_or_test_elf_rehashed_here': False,
        'performance_acceptance_claim': False, 'candidate_adopted': False,
        'scope': 'Byte preservation and original receipt reconciliation for the single C1 diagnostic capture; no cost recomputation or new performance gate.'}
