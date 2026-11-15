# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Source fragment assembled into the collector. No target program is imported.
def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-normal-lifecycle-archive-bindings/v1',
         'unsealed lifecycle collector: actual original receipts required')
    need(type(HOLDER_JOB) is str and HOLDER_JOB and ACTUAL.get('holder_job_id') == HOLDER_JOB,
         'actual lifecycle holder job required')
    pins, sizes = ACTUAL.get('sha256'), ACTUAL.get('bytes')
    need(type(pins) is dict and type(sizes) is dict and set(pins) == set(sizes)
         and {'lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json'} <= set(pins),
         'actual native original identities missing')
    need(all(type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in pins.values())
         and all(type(v) is int and 0 <= v <= MAX_FILE for v in sizes.values()),
         'malformed lifecycle original identities')
    need(all(allowed_binding_name(name) for name in pins), 'actual binding escaped fixed lifecycle selection')
    reads = ACTUAL.get('holder_read_members')
    need(type(reads) is list and reads and reads[0] == 'lifecycle-holder-read-01.json'
         and len(reads) == len(set(reads)) and set(reads) <= set(pins),
         'complete original lifecycle holder read pages required')
    need(type(ACTUAL.get('outcomes')) is dict, 'actual reported outcome object required')
    for key in ('workflow_reported_passed', 'parent_reported_adoption_passed',
                'normal_lifecycle_gate_verified', 'normal_lifecycle_gate_passed'):
        need(ACTUAL['outcomes'].get(key) is None or type(ACTUAL['outcomes'][key]) is bool,
             'reported lifecycle outcome must be a boolean or unavailable')


def allowed_binding_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name or not path.parts:
        return False
    if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
        return False
    if path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
        return False
    return (name in STATIC_PINS or name in CORE_FILES
            or name.startswith('lifecycle-holder-read-01-page-') and name.endswith('.json')
            and '/' not in name
            or any(name.startswith(directory + '/') for directory in SELECTED_DIRS))


def summary(kind, data, namespace):
    require_sealed()
    need(kind == 'lifecycle' and all(name in data for name in REQUIRED), 'missing fixed lifecycle input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen lifecycle input differs')
    need(all(len(data[name]) == size for name, size in ACTUAL['bytes'].items()), 'actual original byte lengths differ')
    need(set(namespace) == set(NAMESPACE_PATHS) and all(type(v) is bool for v in namespace.values()),
         'invalid captured lifecycle namespace')
    errors, limitations, parse_errors, external = [], [], [], {}

    def check(value, reason):
        if not value:
            errors.append(reason)
        return bool(value)

    def maybe(name):
        if name not in data:
            return None
        try:
            value = json.loads(data[name])
            if not isinstance(value, dict):
                raise ValueError('original is not a JSON object')
            return value
        except (ValueError, UnicodeError, TypeError) as error:
            parse_errors.append({'member': name, 'type': type(error).__name__, 'reason': str(error)[:300]})
            return None

    def identity(name):
        return {'path': str(source_path(name)), 'bytes': len(data[name]), 'sha256': sha(data[name])}

    def binding(value, label, expected_name=None):
        if not isinstance(value, dict) or not {'path', 'bytes', 'sha256'} <= set(value):
            errors.append(label + ': original identity is unavailable or malformed')
            return False
        try:
            name = member_path(value['path'])
        except (ValueError, TypeError):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'outside the fixed archive roots; body not copied'}
            return None
        if expected_name is not None and name != expected_name:
            errors.append(label + ': reported path differs from the original fixed protocol path')
            return False
        if not allowed_binding_name(name):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'source/ELF/profile or separately archived prerequisite; body not repeated'}
            return None
        return check(name in data and type(value['bytes']) is int and value['bytes'] == len(data[name])
                     and value['sha256'] == sha(data[name]), label + ': archived original identity differs')

    def walk(value, label):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= set(value):
                binding(value, label)
                return
            for key, child in value.items():
                walk(child, label + '/' + str(key))
        elif isinstance(value, list):
            for number, child in enumerate(value):
                walk(child, label + '/' + str(number))

    parent = maybe('lifecycle-campaign-01/report.json')
    normal = maybe('lifecycle-abba-01/report.json')
    index = maybe('lifecycle-abba-01/round-index.json')
    gates = maybe('lifecycle-abba-01/gates.json')
    descriptive = maybe('lifecycle-abba-01/summary.json')
    tests = maybe('lifecycle-tool-tests-01/report.json')
    monitor = maybe('lifecycle-campaign-01/compiler-monitor.json')
    monitor_audit = maybe('lifecycle-campaign-01/compiler-monitor.audit.json')
    holder = maybe('lifecycle-holder-report-01.json')
    inputs = maybe('lifecycle-inputs-01.json')
    observation = maybe('campaign-01/report.json')
    qualified_map = maybe('qualification-01/source-map.json')
    native = json.loads(data['lifecycle-holder-native-01.json'])
    pages = [json.loads(data[name]) for name in ACTUAL['holder_read_members']]
    native_receipt = terminal(native, HOLDER_JOB)
    native_receipt['original_streams'] = streams_from_reads(native, pages)
    complete_native = (native.get('output_complete') is True and native.get('output_durable') is True
        and native.get('automatic_retry') is False
        and native.get('log_synced') == {'stdout': True, 'stderr': True}
        and native.get('log_errors') == {'stdout': None, 'stderr': None}
        and native.get('log_truncated') == {'stdout': False, 'stderr': False}
        and all(row['seen_equals_stored'] for row in native_receipt['original_streams'].values()))
    native_receipt['all_native_output_completeness_fields_closed'] = complete_native
    stdout = b''.join(bytes.fromhex(page['stdout']['bytes_hex']) for page in pages)
    completion = None
    try:
        lines = [json.loads(line) for line in stdout.decode().splitlines() if line]
        completion = lines[-1] if lines else None
    except (ValueError, UnicodeError):
        limitations.append('Original holder stdout is retained but is not a complete JSON completion stream.')
    if holder is not None:
        check(holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1', 'holder report schema differs')
        check(holder.get('holder_script_sha256') == HOLDER_SHA, 'holder source identity differs')
        check(holder.get('remote_script_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'holder used a different lifecycle parent source')
        if isinstance(completion, dict):
            check(all(completion.get(key) == holder.get(key) for key in
                      ('passed', 'remote_returncode', 'owned_agent_reaped')),
                  'original holder completion and full report differ')
        elif holder.get('passed') is True:
            errors.append('positive holder report lacks matching original native completion')
    else:
        limitations.append('Full holder report unavailable; original terminal/read bytes remain retained.')

    reported_parent_passed = parent.get('passed') if parent is not None else None
    reported_adoption = parent.get('adoption_passed') if parent is not None else None
    gate_verified = gates.get('verified') if gates is not None else None
    gate_passed = gates.get('passed') if gates is not None else None
    observed_outcomes = {'workflow_reported_passed': reported_parent_passed,
        'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed}
    for key, expected in ACTUAL['outcomes'].items():
        if expected is not None and key in observed_outcomes:
            check(observed_outcomes[key] == expected, 'sealed and captured reported outcome differs: ' + key)
    positive = (reported_parent_passed is True and reported_adoption is True
                and native.get('state') == 'succeeded' and native.get('exit_code') == 0
                and complete_native
                and holder is not None and holder.get('passed') is True
                and holder.get('owned_agent_reaped') is True)
    if reported_parent_passed is True:
        check(positive, 'positive parent report lacks complete original holder/native custody')

    def stages(value, directory, expected_names, require_positive, process_key='owned_process_absent'):
        if value is None:
            return []
        rows = value.get('stages', [])
        if not check(isinstance(rows, list) and len(rows) <= len(expected_names)
                     and all(isinstance(row, dict) for row in rows)
                     and [row.get('name') for row in rows] == list(expected_names[:len(rows)]),
                     directory + ': original stage order/prefix differs'):
            return []
        result = []
        for number, row in enumerate(rows):
            label = directory + '/' + row['name']
            for stream in ('stdout', 'stderr'):
                if stream in row:
                    binding(row[stream], label + ' ' + stream, directory + '/' + row['name'] + '.' + stream)
                elif require_positive:
                    errors.append(label + ': positive stage lacks ' + stream)
            for pin in row.get('output_bindings', []):
                binding(pin, label + ' output')
            if require_positive:
                check(row.get('returncode') == 0 and row.get('waited_and_reaped') is True
                      and row.get(process_key) is True and row.get('owned_process_group_absent') is True
                      and row.get('cleanup_error') is None and row.get('passed', True) is True,
                      label + ': positive stage custody did not close')
            result.append({key: row.get(key) for key in
                ('name', 'passed', 'returncode', 'timed_out', 'waited_and_reaped', process_key,
                 'owned_process_group_absent', 'cleanup_signals', 'cleanup_error', 'error', 'automatic_retry')})
        if require_positive:
            check(len(rows) == len(expected_names), directory + ': positive stage inventory is incomplete')
        return result

    parent_stages = stages(parent, 'lifecycle-campaign-01', STAGES, positive)
    normal_stages = stages(normal, 'lifecycle-abba-01', NORMAL_STAGES, positive, 'proc_absent')
    for name, value in (('parent', parent), ('normal', normal), ('round-index', index),
                        ('normal-gates', gates), ('descriptive-summary', descriptive),
                        ('original-tool-tests', tests), ('compiler-monitor-audit', monitor_audit)):
        if value is not None:
            walk(value, name)
    if parent is not None:
        check(parent.get('schema') == 'hepta-r35-normal-lifecycle-campaign-control/v1', 'LC parent schema differs')
        check(parent.get('launcher_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'LC parent source identity differs')
        check(parent.get('automatic_retries') == 0 and parent.get('production_services_modified') is False,
              'LC parent retry/production scope differs')
        if inputs is not None:
            check(inputs.get('schema') == 'hepta-r25-lifecycle-inputs/v1' and inputs.get('attempt') == '01'
                  and inputs.get('launcher_sha256') == parent.get('launcher_sha256'),
                  'original LC input/parent source differs')
            binding(parent.get('input_receipt'), 'parent input', 'lifecycle-inputs-01.json')
            if 'lifecycle-campaign-01/inputs.json' in data:
                check(data['lifecycle-campaign-01/inputs.json'] == data['lifecycle-inputs-01.json'],
                      'retained parent input copy differs')
        if observation is not None and parent.get('binaries'):
            check(parent['binaries'] == observation.get('binaries'), 'LC/OBS original A/B artifacts differ')
        if positive:
            check(all(parent.get(key) is True for key in ('inputs_unchanged', 'source_inputs_unchanged',
                  'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'observation_gate_verified')),
                  'positive LC lacks original source/input/measurement closure')
            check(observation is not None and observation.get('passed') is True
                  and observation.get('observation_gate_passed') is True,
                  'positive LC lacks its completed OBS prerequisite')
            check(parent.get('source_inputs_sha256') == inputs.get('source_inputs_sha256')
                  == observation.get('source_inputs_sha256')
                  and parent.get('baseline_source_inputs_sha256') == observation.get('baseline_source_inputs_sha256'),
                  'positive LC source digests differ from original OBS')
    snapshots = {}
    for name in ('source-inputs.json', 'baseline-source-inputs.json'):
        member = 'lifecycle-campaign-01/' + name
        value = maybe(member)
        if value is not None:
            snapshots[name] = {'identity': identity(member), 'root': value.get('root'),
                               'file_count': value.get('file_count'), 'sha256': value.get('sha256')}
            if name == 'source-inputs.json' and qualified_map is not None and isinstance(value.get('files'), dict):
                check({key: pin.get('sha256') for key, pin in value['files'].items()} == qualified_map
                      and value.get('file_count') == len(qualified_map) == 220,
                      'LC source snapshot differs from all actual qualified inputs')
    if normal is not None:
        check(normal.get('schema') == 'hepta-r25-lifecycle-abba-control/v1'
              and normal.get('order') == 'ABBA' and normal.get('automatic_retries') == 0,
              'normal LC schema/order/retries differ')
        binding(normal.get('tools_manifest'), 'normal tools manifest', 'lifecycle-tools-01/lifecycle-tools-manifest-01.json')
        if parent is not None and parent.get('binaries'):
            check(normal.get('baseline') == parent['binaries']['A']['hepta-runtime']
                  and normal.get('candidate') == parent['binaries']['B']['hepta-runtime'],
                  'normal LC artifacts differ from its parent')
    if index is not None:
        check(index.get('schema') == 'hepta-r25-lifecycle-round-index/v1'
              and index.get('order') == 'ABBA' and index.get('automatic_retries') == 0,
              'LC round-index schema/order/retries differ')
        if index.get('closed') is True:
            check(index.get('round_count') == 4 and isinstance(index.get('rounds'), list)
                  and len(index['rounds']) == 4, 'closed original LC index is incomplete')
        if normal is not None:
            check(all(index.get(key) == normal.get(key) for key in
                      ('rounds', 'baseline', 'candidate', 'tools_manifest', 'plan')),
                  'normal report/index original identities differ')
    if gates is not None:
        check(gates.get('schema') == 'hepta-r25-lifecycle-gates/v1'
              and type(gates.get('verified')) is bool and type(gates.get('passed')) is bool,
              'normal LC gate schema/outcome shape differs')
        binding(gates.get('round_index'), 'LC gate round index', 'lifecycle-abba-01/round-index.json')
        binding(gates.get('gate_policy'), 'LC gate policy', 'lifecycle-tools-01/lifecycle-gate-policy.json')
    if descriptive is not None and 'lifecycle-abba-01/round-index.json' in data:
        check(descriptive.get('round_index_sha256') == sha(data['lifecycle-abba-01/round-index.json']),
              'descriptive LC summary index hash differs')

    rounds, shutdowns, intentional_crashes, missing_shutdowns = [], [], [], []
    declared = index.get('rounds', []) if index is not None else normal.get('rounds', []) if normal is not None else []
    if not isinstance(declared, list):
        errors.append('original declared LC rounds is not a list')
        declared = []
    if len(declared) > 4:
        errors.append('original declared LC round count exceeds ABBA')
    for number, arm in enumerate('ABBA'):
        directory = 'lifecycle-abba-01/round-%d-%s' % (number, arm)
        raw_name, audit_name = directory + '/report.json', directory + '/independent-summary.json'
        raw, audit = maybe(raw_name), maybe(audit_name)
        declaration = declared[number] if number < len(declared) else None
        if raw is None and audit is None and declaration is None:
            continue
        item = {'index': number, 'arm': arm, 'directory': directory, 'declared_in_original_index': declaration is not None,
                'raw_report_present': raw_name in data, 'raw_report_structured': raw is not None,
                'independent_analysis_present': audit_name in data, 'independent_analysis_structured': audit is not None,
                'reported_raw_passed': raw.get('passed') if raw is not None else None,
                'reported_audit_verified': audit.get('verified') if audit is not None else None}
        if declaration is not None:
            check(isinstance(declaration, dict) and declaration.get('index') == number and declaration.get('arm') == arm
                  and declaration.get('directory') == directory.split('/')[-1],
                  directory + ': original declared round path/order differs')
            if isinstance(declaration, dict):
                binding(declaration.get('report'), directory + ' declared report', raw_name)
                binding(declaration.get('independent_analysis'), directory + ' declared audit', audit_name)
                phases = declaration.get('phase_files', [])
                check(isinstance(phases, list) and len(phases) == 11
                      and {PurePosixPath(p.get('path', '')).name for p in phases if isinstance(p, dict)}
                         == {'phase-' + phase + '.json' for phase in LIFECYCLE_PHASES},
                      directory + ': declared 11-phase inventory differs')
                for pin in phases if isinstance(phases, list) else []:
                    binding(pin, directory + ' original phase',
                            directory + '/' + PurePosixPath(pin.get('path', '')).name)
                item['phase_files_reported'] = len(phases) if isinstance(phases, list) else None
        item['phase_files_captured'] = [phase for phase in LIFECYCLE_PHASES if directory + '/phase-' + phase + '.json' in data]
        if raw is not None:
            if parent is not None and parent.get('binaries'):
                check(raw.get('candidate_sha256') == parent['binaries'][arm]['hepta-runtime']['sha256'],
                      directory + ': raw runtime differs from original arm')
            for phase in ('shutdown', 'after_cancel_shutdown'):
                value = raw.get(phase)
                if not isinstance(value, dict):
                    missing_shutdowns.append(directory + '/' + phase)
                    continue
                capture = value.get('transport_capture', {})
                row = {key: value.get(key) for key in ('exit_code', 'shutdown_method',
                    'observed_descendant_survivors', 'reader_error', 'unmatched_responses')}
                row.update(round=number, arm=arm, phase=phase, reader_eof=capture.get('reader_eof'))
                row['reported_clean_shutdown'] = (row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
                    and row['observed_descendant_survivors'] == [] and row['reader_error'] is None
                    and row['unmatched_responses'] == 0 and row['reader_eof'] is True)
                shutdowns.append(row)
            crash = raw.get('intentional_crash')
            if isinstance(crash, dict):
                intentional_crashes.append({'round': number, 'arm': arm,
                    'reported_fields': {key: crash.get(key) for key in ('exit_code', 'shutdown_method',
                        'observed_descendant_survivors', 'reader_error', 'unmatched_responses')},
                    'full_original_retained_in': raw_name})
        if audit is not None:
            item['original_audit_counts'] = {key: audit.get(key) for key in COUNTER_KEYS}
            item['original_audit_limitations'] = audit.get('not_covered', audit.get('limitations'))
            if raw_name in data:
                check(audit.get('source_sha256') == sha(data[raw_name])
                      and audit.get('source_bytes') == len(data[raw_name]),
                      directory + ': original independent audit source identity differs')
            if raw is not None:
                check(audit.get('candidate_sha256') == raw.get('candidate_sha256'),
                      directory + ': raw/audit candidate identity differs')
            if positive:
                check(raw is not None and raw.get('passed') is True and audit.get('verified') is True
                      and raw.get('automatic_rpc_retries') == audit.get('automatic_rpc_retries') == 0,
                      directory + ': positive original raw/audit closure incomplete')
        elif positive:
            errors.append(directory + ': positive original independent audit missing')
        rounds.append(item)
    counters = {}
    for key in COUNTER_KEYS:
        values = [row.get('original_audit_counts', {}).get(key) for row in rounds]
        counters[key] = sum(values) if values and all(type(value) is int for value in values) else None
    counts = {'captured_round_reports': sum(row['raw_report_present'] for row in rounds),
              'captured_round_audits': sum(row['independent_analysis_present'] for row in rounds),
              'original_declared_rounds': len(declared), 'original_audit_count_sums': counters,
              'count_sums_cover_all_four_round_audits': len(rounds) == 4
                  and all(row['independent_analysis_structured'] for row in rounds)}
    monitor_count = monitor.get('sample_count') if monitor is not None else None
    if monitor is not None:
        check(type(monitor_count) is int and isinstance(monitor.get('samples'), list)
              and monitor_count == len(monitor['samples']), 'LC monitor declared/raw sample count differs')
    if monitor_audit is not None:
        binding(monitor_audit.get('ledger'), 'LC monitor audit ledger', 'lifecycle-campaign-01/compiler-monitor.json')
        if monitor_count is not None:
            check(monitor_audit.get('validation', {}).get('validated_sample_count') == monitor_count,
                  'LC monitor original audit sample count differs')
    expected_count = ACTUAL.get('compiler_monitor_sample_count')
    if expected_count is not None:
        check(monitor_count == expected_count, 'sealed and captured LC monitor count differs')
    if positive:
        check(tests is not None and tests.get('passed') is True and tests.get('tests_run') == 14
              and tests.get('skipped') == tests.get('errors') == tests.get('failures') == 0,
              'positive LC lacks all 14 original tool-test results')
        check(normal is not None and normal.get('passed') is True and normal.get('inputs_unchanged') is True
              and index is not None and index.get('closed') is True and len(rounds) == 4
              and descriptive is not None and descriptive.get('verified') is True
              and gate_verified is True and gate_passed is True,
              'positive LC parent lacks complete original normal ABBA gates')
        check(monitor is not None and monitor_audit is not None
              and monitor_audit.get('validation', {}).get('passed') is True,
              'positive LC parent lacks original compiler-monitor closure')
    errors.extend(row['member'] + ': retained original JSON cannot be interpreted' for row in parse_errors)
    return {'kind': kind, 'original_lifecycle_holder_job_id': HOLDER_JOB,
        'workflow_reported_passed': reported_parent_passed, 'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed,
        'reported_rejection_reasons': gates.get('rejection_reasons', gates.get('failures')) if gates is not None else None,
        'candidate_adopted_by_archiver': False, 'final_publication_or_adoption_decision': None,
        'original_native_terminal': native_receipt, 'original_holder_completion': completion,
        'original_holder_report': {key: holder.get(key) for key in ('schema', 'passed', 'remote_returncode',
            'holder_script_sha256', 'remote_script_sha256', 'automatic_ssh_retries', 'services_modified',
            'owned_agent_reaped', 'owned_agent_returncode', 'owned_agent_socket_absent_after_context',
            'owned_agent_directory_absent_after_context')} if holder is not None else None,
        'full_Mac_holder_log_bodies_copied_here': False,
        'Mac_holder_log_identities_retained_in_original_holder_report': holder is not None,
        'parent_stages': parent_stages, 'normal_ABBA_stages': normal_stages,
        'tool_tests_reported': {key: tests.get(key) for key in ('schema', 'passed', 'tests_run',
            'skipped', 'errors', 'failures')} if tests is not None else None,
        'counts': counts, 'rounds': rounds, 'original_normal_lifecycle_gates': gates,
        'normal_descriptive_summary': {'identity': identity('lifecycle-abba-01/summary.json'),
            'schema': descriptive.get('schema'), 'verified': descriptive.get('verified')} if descriptive is not None else None,
        'compiler_monitor': {'sample_count': monitor_count,
            'original_ledger_identity': identity('lifecycle-campaign-01/compiler-monitor.json') if monitor is not None else None,
            'original_audit': monitor_audit,
            'reported_parent_monitor': parent.get('compiler_monitor') if parent is not None else None},
        'shutdowns': shutdowns, 'missing_standard_shutdown_evidence': missing_shutdowns,
        'all_observed_standard_shutdowns_clean': all(row['reported_clean_shutdown'] for row in shutdowns) if shutdowns else None,
        'all_four_rounds_and_eight_standard_shutdowns_observed': len(rounds) == 4 and len(shutdowns) == 8,
        'intentional_crashes': intentional_crashes, 'source_snapshots': snapshots,
        'original_parent_error': parent.get('error') if parent is not None else None,
        'original_parent_finalization_error': parent.get('finalization_error') if parent is not None else None,
        'original_normal_error': normal.get('error') if normal is not None else None,
        'original_saturation_verified_field': parent.get('saturated_cancellation_verified') if parent is not None else None,
        'source_and_measurement_flags': {key: parent.get(key) for key in ('inputs_unchanged', 'source_inputs_unchanged',
            'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'automatic_retries',
            'production_services_modified')} if parent is not None else None,
        'captured_namespace_presence': namespace,
        'unavailable_core_originals_at_capture': [name for name in CORE_FILES if name not in data],
        'unarchived_identity_references': list(external.values()),
        'original_json_parse_errors': parse_errors, 'archived_receipt_binding_errors': errors,
        'original_qualification_archive_sha256': QUALIFICATION_ARCHIVE_SHA,
        'original_exact_ci_archive_sha256': CI_ARCHIVE_SHA,
        'original_observation_archive_sha256': OBSERVATION_ARCHIVE_SHA,
        'scope': {'raw_results_modified': False, 'tests_or_benchmarks_rerun': False,
            'original_auditors_reexecuted': False, 'archived_programs_executed': False,
            'separate_saturation_campaign_included': False, 'qualification_ELFs_or_source_trees_repeated': False,
            'known_OBS_success_is_not_lifecycle_success': True, 'limits_and_original_thresholds_changed': False},
        'limitations': limitations}
