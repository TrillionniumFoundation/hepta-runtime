# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Pure byte/receipt interpretation. No archived Python is imported or executed.

def require_sealed():
    need(not sys.flags.optimize, 'Python optimized assertions are not supported')
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d2-exact-ci-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual completed D2 exact-CI originals required')
    job = ACTUAL.get('original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original native CI identity required')
    pages = ACTUAL.get('read_pages')
    need(type(pages) is list and 1 <= len(pages) <= 16 and len(set(pages)) == len(pages)
         and (pages == ['rust-ci-native-read-01.json']
              or pages == ['rust-ci-native-read-01-%03d.json' % i for i in range(len(pages))]),
         'original native read page names/order are unbound')
    need(ACTUAL.get('outcome') in {'passed', 'failed'} and type(ACTUAL.get('exit_code')) is int
         and ((ACTUAL['outcome'] == 'passed' and ACTUAL['exit_code'] == 0)
              or (ACTUAL['outcome'] == 'failed' and ACTUAL['exit_code'] != 0)),
         'actual CI outcome and exit status disagree')
    need(type(ACTUAL.get('files')) is dict
         and set(ACTUAL['files']) == set(FUTURE_PATHS) | set(pages), 'actual CI file inventory differs')
    for name, pin in ACTUAL['files'].items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual receipt pin: ' + name)
    need(all(ACTUAL['files'][name] is not None for name in
             ['rust-ci-native-01.json', 'rust-ci-installation-started-01.json',
              'rust-ci-installation-01.json', *pages]), 'actual native/installation originals missing')
    if ACTUAL['outcome'] == 'passed':
        need(all(pin is not None for pin in ACTUAL['files'].values()), 'successful CI is missing raw receipts')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == set(COUNT_KEYS)
             and all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored'], 'actual complete CI counts required')
    else:
        need(ACTUAL.get('counts') is None, 'failed CI cannot inherit successful qualification counts')
    return ACTUAL


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'ci', 'this script archives only the original D2 exact-CI attempt')
    for name, pin in {**PINNED, **actual['files']}.items():
        if pin is None:
            need(name not in data, 'receipt declared absent appears in archive: ' + name)
        else:
            need(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin,
                 'original receipt identity differs: ' + name)

    def document(name):
        return json.loads(data[name])

    def identity(name):
        return {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}

    def bound_identity(pin, expected_name):
        need(pin == identity(expected_name), 'original report body identity differs: ' + expected_name)
        return pin

    foundation = document('qualification-prerequisites-01.json')
    need(foundation['schema'] == 'hepta-d2-c1-prerequisites/v1'
         and foundation['qualification_sealed'] is True and foundation['exact_ci_sealed'] is False
         and foundation['prerequisite_module'] == identity('full-prerequisites-01/d2_prerequisites.py'),
         'original Q-only foundation/canonical module differs')
    q = document('qualification-01/report.json')
    qmap = document('qualification-01/source-map.json')
    qs = document('qualification-01/isolated-tests/summary.json')
    qa = document('qualification-01/isolated-tests.audit.json')
    qcounts = {key: qs[key] for key in COUNT_KEYS}
    need(q['qualified'] is True and q['source_tested'] == q['source_after'] == qmap and len(qmap) == 222
         and qs['success'] is True and qa['success'] is True and qa['errors'] == []
         and {key: qa[key] for key in ('passed', 'failed', 'ignored', 'selected')} ==
             {key: qcounts[key] for key in ('passed', 'failed', 'ignored', 'selected')},
         'original qualified source/counts disagree')
    qnative = document('qualification-terminal-status-01.json')
    native_terminal(qnative, foundation['qualification_original_job_id'], 'succeeded', 0)
    qreads = []
    for pin in foundation['qualification_read_pages']:
        name = Path(pin['path']).relative_to(ROOT).as_posix()
        bound_identity(pin, name)
        qreads.append(document(name))
    native_stream_pages(qreads, qnative)
    for name in ('preparation.json', 'qualification-01/report.json', 'qualification-01/source-map.json',
                 'qualification-01/isolated-tests/summary.json', 'qualification-01/isolated-tests.audit.json',
                 'qualification-terminal-status-01.json'):
        bound_identity(foundation['artifact_map'][name], name)

    deployment = document('rust-ci-deployment-manifest-01.json')
    need(deployment['schema'] == 'hepta-d2-exact-ci-deployment/v1'
         and deployment['root'] == str(ROOT) and deployment['file_count_excluding_manifest'] == 11,
         'original deployment manifest differs')
    for row in deployment['files']:
        need({'bytes': row['bytes'], 'sha256': row['sha256']} == PINNED[row['path']],
             'original deployed member differs')

    terminal = document('rust-ci-native-01.json')
    state = 'succeeded' if actual['outcome'] == 'passed' else 'failed'
    native_terminal(terminal, actual['original_job_id'], state, actual['exit_code'])
    streams = native_stream_pages([document(name) for name in actual['read_pages']], terminal)
    ci = document('rust-ci-01/report.json') if actual['files']['rust-ci-01/report.json'] else None
    plan = document('rust-ci-plan-01.json') if actual['files']['rust-ci-plan-01.json'] else None
    audit = document('rust-ci-01/nextest-output-audit.json') if actual['files']['rust-ci-01/nextest-output-audit.json'] else None
    stages = []
    if ci is not None:
        need(ci['schema'] == 'hepta-d2-external-rust-ci/v1', 'unexpected CI receipt schema')
        need(type(ci['stages']) is list, 'original stage inventory is not a list')
        seen = set()
        for row in ci['stages']:
            name = row['name']
            need(name in CI_COMMANDS and name not in seen, 'unexpected/duplicate original CI stage')
            seen.add(name)
            logs = {}
            for channel in ('stdout', 'stderr'):
                pin = row.get(channel)
                if pin is not None:
                    logs[channel] = bound_identity(pin, 'rust-ci-01/' + name + '.' + channel)
            stages.append({'name': name, 'returncode': row.get('returncode'), 'passed': row.get('passed'),
                           'timed_out': row.get('timed_out'), 'waited_and_reaped': row.get('waited_and_reaped'),
                           'owned_process_absent': row.get('owned_process_absent'),
                           'owned_process_group_absent': row.get('owned_process_group_absent'), 'logs': logs})

    if actual['outcome'] == 'passed':
        need(ci['passed'] is True and ci.get('finished_utc') and not ci.get('error')
             and ci['automatic_retries'] == 0 and ci['production_services_modified'] is False
             and ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
             and ci['home_unchanged'] is True and ci['hosted_actions_passed'] is False
             and ci['original_qualification_job_id'] == foundation['qualification_original_job_id'],
             'original CI workflow did not completely close successfully')
        bound_identity(ci['plan'], 'rust-ci-plan-01.json')
        need(plan['schema'] == 'hepta-d2-materialized-exact-rust-ci-plan/v1'
             and plan['attempt'] == '01' and plan['executed'] is False and plan['hosted_actions_passed'] is False
             and plan['qualification_job_id'] == foundation['qualification_original_job_id']
             and plan['source'] == str(ROOT / 'source') and plan['source_files'] == qmap
             and plan['qualification_counts'] == qcounts == actual['counts'],
             'original exact-CI plan identifies another source/qualification')
        for key, name in (('qualification', 'qualification-01/report.json'), ('preparation', 'preparation.json'),
                          ('source_map', 'qualification-01/source-map.json'),
                          ('qualification_summary', 'qualification-01/isolated-tests/summary.json'),
                          ('qualification_independent_audit', 'qualification-01/isolated-tests.audit.json'),
                          ('qualification_terminal_status', 'qualification-terminal-status-01.json')):
            bound_identity(plan[key], name)
            need(plan[key] in plan['input_bindings'], 'original plan omits a Q input binding')
        need(identity('full-prerequisites-01/d2_prerequisites.py') in plan['input_bindings']
             and identity('qualification-prerequisites-01.json') in plan['input_bindings'],
             'original plan omits canonical module/Q-only foundation')
        need(plan['commands'] == [
                 {'workflow_step': 'Check all targets', 'argv': CI_COMMANDS['cargo-check'], 'cwd': str(ROOT / 'source')},
                 {'workflow_step': 'Test in isolated processes', 'argv': CI_COMMANDS['nextest-run'], 'cwd': str(ROOT / 'source')}]
             and plan['inventory_command']['argv'] == CI_COMMANDS['nextest-list']
             and plan['inventory_command']['cwd'] == str(ROOT / 'source')
             and ci['explicit_environment'] == plan['environment'] == CI_ENVIRONMENT,
             'original CI commands/environment differ')
        need([row['name'] for row in ci['stages']] == list(CI_COMMANDS), 'original six CI stages are incomplete')
        for row in ci['stages']:
            need(row['argv'] == CI_COMMANDS[row['name']] and row['cwd'] == str(ROOT / 'source')
                 and row['returncode'] == 0 and row['passed'] is True and row['timed_out'] is False
                 and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                 and row['owned_process_group_absent'] is True, 'original stage failed or was not closed')
            for channel in ('stdout', 'stderr'):
                bound_identity(row[channel], 'rust-ci-01/' + row['name'] + '.' + channel)
        need(data['rust-ci-01/nextest-version.stdout'].decode().splitlines()[0].startswith('cargo-nextest 0.9.137 '),
             'original nextest version differs')
        need(ci['nextest_output_audit'] == audit and audit['verified'] is True
             and {key: audit[key] for key in COUNT_KEYS} == actual['counts']
             and audit['completed_exact_case_count'] == actual['counts']['passed']
             and audit['progress_counter_complete'] is True
             and audit['raw_bytes'] == len(data['rust-ci-01/nextest-run.stderr'])
             and audit['raw_sha256'] == sha(data['rust-ci-01/nextest-run.stderr']),
             'original nextest audit/counts do not bind the retained raw stderr')
        inventory, expected = ci['structured_inventory'], plan['expected_nextest']
        need(inventory['verified'] is True and inventory['total'] == actual['counts']['selected']
             and inventory['ignored'] == actual['counts']['ignored']
             and inventory['case_inventory_sha256'] == audit['case_inventory_sha256'] == expected['case_inventory_sha256']
             and inventory['original_stdout'] == identity('rust-ci-01/nextest-list.stdout')
             and len(expected['exact_cases']) == actual['counts']['selected']
             and sum(row['ignored'] for row in expected['exact_cases']) == actual['counts']['ignored']
             and sha(json.dumps(expected['exact_cases'], sort_keys=True, separators=(',', ':')).encode())
                 == expected['case_inventory_sha256'], 'original complete unfiltered case inventory differs')
        bound_identity(plan['workflow_binding']['canonical'], 'rust-ci-tools-01/canonical-workflow.yml')
        bound_identity(ci['auditor'], 'rust-ci-tools-01/audit_nextest_0137.py')
        bound_identity(ci['launcher'], 'rust-ci-tools-01/run_rust_ci_01.py')
        bound_identity(ci['materializer'], 'rust-ci-tools-01/materialize_rust_ci_plan_01.py')
        for name, pin in plan['qualified_binaries'].items():
            need(pin['path'] == q['binaries'][name]['path'] and pin['sha256'] == q['binaries'][name]['sha256'],
                 'original qualified release identity differs')

    return {'schema': 'hepta-d2-exact-ci-evidence-compact/v1', 'kind': kind,
            'original_job_id': actual['original_job_id'], 'outcome': actual['outcome'],
            'native_state': terminal['state'], 'native_exit_code': terminal['exit_code'],
            'original_native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in streams.items()},
            'original_read_pages': [identity(name) for name in actual['read_pages']],
            'original_qualification_job_id': foundation['qualification_original_job_id'],
            'counts': actual['counts'], 'qualification_counts': qcounts,
            'reported_workflow_passed': None if ci is None else ci.get('passed'),
            'original_stage_outcomes': stages,
            'qualified_binary_sha256': {name: pin['sha256'] for name, pin in q['binaries'].items()},
            'compiler_input_count': len(qmap), 'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'canonical_prerequisite_module': identity('full-prerequisites-01/d2_prerequisites.py'),
            'all_original_ci_directory_files_preserved_except_explicit_exclusions': True,
            'ci_reported_current_source_unchanged': None if ci is None else ci.get('source_inputs_unchanged'),
            'current_source_or_binary_bodies_rehashed_by_archiver': False,
            'archived_python_executed': False, 'auditor_rerun': False, 'tests_or_benchmarks_run': False,
            'hosted_actions_passed': False, 'performance_acceptance_claim': False, 'candidate_adopted': False}
