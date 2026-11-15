# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0

def original(spec):
    need(type(spec) is dict and set(spec) == {'local_path', 'bytes', 'sha256'}
         and type(spec['bytes']) is int and 0 < spec['bytes'] <= MAX_FILE
         and type(spec['sha256']) is str and len(spec['sha256']) == 64
         and set(spec['sha256']) <= set('0123456789abcdef'), 'actual immutable local original required')
    raw = read(spec['local_path'], maximum=MAX_FILE)
    need(identity(raw) == {key: spec[key] for key in ('bytes', 'sha256')}, 'original byte identity differs')
    return raw


def constant(source, name):
    found = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(found) == 1, 'expected one source constant: ' + name)
    return ast.literal_eval(found[0].value)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(not sys.flags.optimize, 'Python optimized assertions are not supported')
    request_raw = read(args.input.absolute(), maximum=2 * 1024 * 1024)
    request = json.loads(request_raw)
    need(request.get('schema') == 'hepta-d2-exact-ci-archive-seal-request/v1', 'unexpected seal request')
    template_raw = original(request['collector'])
    template = template_raw.decode('utf-8')
    need(constant(template, 'ACTUAL') is None and template.count('\nACTUAL = None\n') == 1,
         'collector must be the unchanged unsealed preparation')
    future = constant(template, 'FUTURE_PATHS')
    count_keys = constant(template, 'COUNT_KEYS')
    commands = constant(template, 'CI_COMMANDS')
    environment = constant(template, 'CI_ENVIRONMENT')
    pinned = constant(template, 'PINNED')
    need(len(pinned) == 19, 'fixed original deployment/Q inventory differs')
    job = request.get('original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original CI job required')
    pages = request.get('read_pages')
    need(type(pages) is list and 1 <= len(pages) <= 16 and len(set(pages)) == len(pages)
         and (pages == ['rust-ci-native-read-01.json']
              or pages == ['rust-ci-native-read-01-%03d.json' % i for i in range(len(pages))]),
         'actual original native read pages required')
    need(type(request.get('originals')) is dict
         and set(request['originals']) == set(future) | set(pages), 'original receipt selection differs')
    raw, pins, doc = {}, {}, {}
    for name, spec in request['originals'].items():
        if spec is None:
            pins[name] = None
        else:
            raw[name] = original(spec)
            pins[name] = identity(raw[name])
            doc[name] = json.loads(raw[name])
    for name in ['rust-ci-native-01.json', 'rust-ci-installation-started-01.json',
                 'rust-ci-installation-01.json', *pages]:
        need(pins[name] is not None, 'complete native/installation originals required')
    terminal = doc['rust-ci-native-01.json']
    need(terminal['state'] in {'succeeded', 'failed'} and type(terminal['exit_code']) is int,
         'the original native CI attempt is not terminal')
    native_terminal(terminal, job, terminal['state'], terminal['exit_code'])
    streams = native_stream_pages([doc[name] for name in pages], terminal)
    passed = terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    need(passed or (terminal['state'] == 'failed' and terminal['exit_code'] != 0),
         'original terminal outcome and exit status disagree')
    counts = None
    if passed:
        need(all(value is not None for value in pins.values()), 'successful CI requires all actual core originals')
        ci, plan, audit = (doc[name] for name in
                           ('rust-ci-01/report.json', 'rust-ci-plan-01.json', 'rust-ci-01/nextest-output-audit.json'))
        need(ci['schema'] == 'hepta-d2-external-rust-ci/v1' and ci.get('passed') is True
             and ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
             and ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
             and ci['home_unchanged'] is True and ci['hosted_actions_passed'] is False
             and ci['production_services_modified'] is False,
             'original completed CI report is not successful')
        need(ci['plan'] == {'path': str(ROOT / 'rust-ci-plan-01.json'), **pins['rust-ci-plan-01.json']}
             and plan['schema'] == 'hepta-d2-materialized-exact-rust-ci-plan/v1'
             and plan['qualification_job_id'] == ci['original_qualification_job_id']
             and plan['source'] == str(ROOT / 'source') and len(plan['source_files']) == 222,
             'original CI plan binding differs')
        need([row['name'] for row in ci['stages']] == list(commands)
             and ci['explicit_environment'] == plan['environment'] == environment,
             'original six stages/environment differ')
        for row in ci['stages']:
            need(row['argv'] == commands[row['name']] and row['cwd'] == str(ROOT / 'source')
                 and row['returncode'] == 0 and row['passed'] is True and row['timed_out'] is False
                 and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                 and row['owned_process_group_absent'] is True, 'original CI stage did not close successfully')
        need(ci['nextest_output_audit'] == audit and audit['verified'] is True
             and audit['progress_counter_complete'] is True, 'actual original nextest audit required')
        counts = {name: audit[name] for name in count_keys}
        need(all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored']
             and plan['qualification_counts'] == counts
             and audit['completed_exact_case_count'] == counts['passed'], 'actual CI counts differ')
    actual = {'schema': 'hepta-d2-exact-ci-archive-actual-pins/v1', 'sealed': True,
              'original_job_id': job, 'outcome': 'passed' if passed else 'failed',
              'exit_code': terminal['exit_code'], 'files': pins, 'read_pages': pages, 'counts': counts}
    source = template.replace('\nACTUAL = None\n', '\nACTUAL = ' + pprint.pformat(actual, sort_dicts=True, width=110) + '\n')
    ast.parse(source)
    output = args.output.absolute()
    need(output.resolve() == output and not os.path.lexists(output), 'create-only seal output already exists')
    output.mkdir(mode=0o700)
    source_raw, actual_raw = source.encode(), encoded(actual)
    receipt = {'schema': 'hepta-d2-exact-ci-archive-seal-receipt/v1', 'sealed': True,
               'original_job_id': job, 'outcome': actual['outcome'], 'counts': counts,
               'request': {'path': str(args.input.absolute()), **identity(request_raw)},
               'template': request['collector'], 'sealed_collector': identity(source_raw),
               'actual_pins': identity(actual_raw), 'originals': request['originals'],
               'complete_native_streams': {name: identity(value) for name, value in streams.items()},
               'collector_requires_actual_stage_raw_stream_recheck': True,
               'collector_or_auditor_executed_by_sealer': False,
               'runtime_or_host_called': False, 'performance_acceptance_claim': False}
    for name, value in (('archive_d2_ci.py', source_raw), ('actual-pins.json', actual_raw),
                        ('seal-receipt.json', encoded(receipt))):
        create(output / name, value)
    print(json.dumps({'sealed': True, 'output': str(output), 'collector': identity(source_raw),
                      'actual_pins': identity(actual_raw), 'outcome': actual['outcome']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
