#!/usr/bin/env python3
"""Offline independent audit of the original A54 three-case native evidence.

Reads only downloaded originals; makes no network calls or process launches.
The derived audit does not replace either original report or evidence archive.
"""
import base64
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import argparse
import os
import stat

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'runtime-resume/docs/experiments/x230/a54'
PLAN_SHA = 'b96b6c180238b384dbf2e7982480b6d02d69fb00601bfd24bd5e48d98b29999e'
Q_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ELF_SHA = 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'
MAP_SHA = 'caecddb1c64ba2ac377d32f7d6880b85fe7d0013ea62931672ae16098efacf4c'
COMPACT_MAP_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'
INPUT = ('0123456789abcdef' * 256).encode()
INPUT_SHA = '929b11f47a02202e710632002203f7ea8dd3c1bc51ef818e59b6a3cd1dc2d5dc'
input_receipts = []
IDENTITY_SHA = '464d503f925044f7dd4f13288c31f7735ea427ee9f863531ecbb55a52238237b'
checks = []
blob_count = 0


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(ok, label):
    checks.append({'check': label, 'passed': bool(ok)})
    if not ok:
        raise ValueError(label)



def stamp(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def read_input(path):
    path = Path(path).absolute()
    check(path == path.resolve(strict=True), 'direct local input: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        check(stat.S_ISREG(before.st_mode), 'regular local input: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        check(stamp(before) == stamp(after) == stamp(path.lstat()) and len(raw) == before.st_size,
              'stable original local input: ' + str(path))
    finally:
        os.close(fd)
    input_receipts.append({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'identity': stamp(before)})
    return raw

def decoded(value, label):
    global blob_count
    raw = base64.b64decode(value['base64'], validate=True)
    receipt = value.get('receipt', value)
    check(len(raw) == receipt['bytes'] and sha(raw) == receipt['sha256'], label + ': bytes/hash')
    blob_count += 1
    return raw


def walk(value, label):
    if isinstance(value, dict):
        if 'base64' in value:
            decoded(value, label)
        for k, v in value.items():
            if k != 'base64':
                walk(v, label + '/' + k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            walk(v, label + '/' + str(i))


def custody(value, label, crash=False, unconsumed=False):
    wait = value['original_wait4']
    check(wait['pid'] == value['identity']['pid'], label + ': original child identity')
    check(wait['exit_code'] == (-9 if crash else 0), label + ': expected original wait4')
    check(os.waitstatus_to_exitcode(wait['raw_status']) == wait['exit_code'], label + ': exact raw wait status')
    check(value['cleanup_complete'] and not value['cleanup_errors'] and value['stdout_eof']
          and not value.get('adopted_children', []), label + ': complete owned cleanup')
    check(unconsumed or value['unconsumed_reply_bytes'] == 0, label + ': expected reply consumption')
    if crash:
        signals = value['signals']
        check(len(signals) == 1 and signals[0]['signal'] == 'SIGKILL'
              and signals[0]['pidfd_bound'] and signals[0]['identity'] == value['identity'],
              label + ': single original pidfd SIGKILL')
    else:
        check(not value['signals'], label + ': no cleanup signal')


def audit(args):
    REPORT_SHA = args.report_sha256
    ARCHIVE_SHA = args.archive_sha256
    raw = read_input(args.report)
    archive_raw = read_input(args.archive)
    check(sha(raw) == REPORT_SHA and len(raw) == args.report_bytes, 'original report pin')
    check(sha(archive_raw) == ARCHIVE_SHA and len(archive_raw) == args.archive_bytes, 'original archive pin')
    report = json.loads(raw)
    archive = json.loads(gzip.decompress(archive_raw))
    check(archive['report_sha256'] == REPORT_SHA and len(archive['files']) == 88, 'archive membership')
    files = {}
    for path, value in archive['files'].items():
        parsed = PurePosixPath(path)
        check(not parsed.is_absolute() and '..' not in parsed.parts and str(parsed) == path, 'direct relative archive path: ' + path)
        check(value['link_count'] == 1, 'archive regular single link: ' + path)
        files[path] = decoded(value, 'archive/' + path)
    check(files['report.json'] == raw, 'archived report byte identity')
    walk(report, 'report')
    plan_raw = files['frozen-plan.original.json']
    plan = json.loads(plan_raw)
    admitted_plan_raw = read_input(DOC / 'native-owner-plan.original.json')
    check(plan_raw == admitted_plan_raw and sha(plan_raw) == report['plan_sha256'] == PLAN_SHA, 'actual A54 frozen plan identity')
    check(archive['root'] == plan['local_out'], 'archive belongs to the single fresh A54 local fixture')
    check(plan['ready'] is True and plan['cases'] == ['controller-loss', 'reply-loss', 'owner-loss']
          and plan['input_sha256'] == sha(INPUT) == INPUT_SHA, 'original fixed three cases and 4096-byte stdin')
    qraw = read_input(DOC / 'qualification-r01.original.json')
    q = json.loads(qraw)
    check(sha(qraw) == Q_SHA and q['qualified'] is True and q['current_stage'] == 'complete'
          and len(q['stages']) == 6 and q['source_tested'] == q['source_after'], 'actual completed A54 r01 qualification')
    check(report['passed'] and report['errors'] == [] and report['unexecuted_cases'] == []
          and report['frozen_inputs_unchanged'], 'top-level completion and input fence')
    bundle = report['qualified_bundle']
    check(bundle['qualification']['sha256'] == Q_SHA and bundle['binary']['sha256'] == ELF_SHA
          and bundle['source_files'] == len(bundle['source_map']) == 175
          and bundle['source_map_sha256'] == MAP_SHA and bundle['source_map'] == q['source_tested']
          and q['binary']['sha256'] == ELF_SHA, 'actual A54 qualification/full source/ELF')
    check(sha(json.dumps(bundle['source_map'], sort_keys=True, separators=(',', ':')).encode()) == COMPACT_MAP_SHA,
          'actual A54 compact 175-source map')
    check(sha((json.dumps(bundle['source_map'], sort_keys=True, indent=2) + '\n').encode()) == MAP_SHA,
          'source map canonical hash')
    check(report['independent_admission']['sha256'] == IDENTITY_SHA
          and sha(read_input(ROOT / 'multihost-review/ai395-independent-identity.original.json')) == IDENTITY_SHA,
          'independent operator identity receipt')
    admission = json.loads(read_input(ROOT / 'multihost-review/ai395-independent-identity.original.json'))
    remote = plan['remote_identity']
    identity_keys = ('boot_id', 'home', 'hostname', 'machine', 'machine_id', 'uid')
    check(all(admission[k] == remote[k] for k in identity_keys)
          and admission['python'] == remote['python_realpath'], 'plan machine identity matches independent operator')
    check(report['automatic_retries'] == report['remote_helper_business_launches']
          == report['service_configuration_changes'] == 0, 'no automatic retry/helper launch/service change')
    check(report['private_identity_metadata_only']['contents_read_by_harness'] is False,
          'private key metadata-only evidence')
    input_by_path = {v['path']: v for v in report['inputs']}
    check(len(input_by_path) == len(report['inputs']), 'unique frozen report input receipts')
    for key, local_name in [('harness_sha256', 'run_native_remote_owner_a54.py'),
                            ('helper_sha256', 'remote_owner_custody_a54.py')]:
        body = read_input(ROOT / 'recovery-review/a54-qualification/actual-r01-acceptance' / local_name)
        check(sha(body) == plan[key] and any(v['sha256'] == plan[key] for v in report['inputs']),
              'reviewed actual implementation bound: ' + local_name)
    check(report['planned_cases'] == plan['cases'] and report['business_launches_planned'] == 3
          and report['mode'] == 'x230-controller-ai395-original-systemd-owner', 'explicit cross-host original business path')
    rows = []
    check([c['name'] for c in report['cases']] == ['controller-loss', 'reply-loss', 'owner-loss'], 'exact three cases')
    for c in report['cases']:
        name = c['name']
        check(json.loads(files[name + '/case-report.json']) == c, name + ': archived case equality')
        check(c['passed'] and c['business_effect_count'] == 1 and c['start_requests'] == 2
              and c['same_job_identity_preserved'], name + ': completed same-job reconciliation')
        rec = c['original_record']
        job = rec['id']
        check(c['remote_root'] == plan['remote_parent'] + '/' + name
              and c['case_nonce'] == sha((plan['attempt_nonce'] + '/' + name).encode()), name + ': exact fresh fixture scope')
        check(c['first_recovered_status']['job_id'] == job, name + ': original job in recovered status')
        if name != 'owner-loss':
            check(c['first_recovered_status']['state'] == 'running', name + ': original job still running after controller loss')
        if name != 'reply-loss':
            check(c['first_launch']['reused'] is False and c['first_launch']['launch']['backend'] == 'systemd'
                  and c['first_launch']['job'] == rec, name + ': first new original systemd launch')
        local_jobs = [p for p in files if p.startswith(name + '/state/jobs/')]
        check(local_jobs == [name + '/state/jobs/' + job + '.json']
              and json.loads(files[local_jobs[0]]) == rec, name + ': exactly one original local job record')
        starts = []
        for path, stream in files.items():
            if path.startswith(name + '/controller-') and path.endswith('/requests.original.jsonl'):
                starts.extend(r['params']['arguments'] for r in map(json.loads, stream.splitlines())
                              if r.get('params', {}).get('name') == 'process_start')
        check(len(starts) == 2 and starts[0] == starts[1]
              and starts[0] == json.loads(files[name + '/request.original.json']),
              name + ': exact same request submitted twice')
        request = starts[0]
        check(request['timeout_seconds'] == 90 and request['stdin'].encode() == INPUT
              and request['cwd'] == c['remote_root'] and request['host'] == 'ai395'
              and request['executable'] == '/usr/bin/python3'
              and request['args'] == ['-I', '-S', '-u', '-c', plan['business_code'],
                                      c['remote_root'] + '/effect', INPUT_SHA, c['remote_root'] + '/release'],
              name + ': unchanged native business request and timeout')
        for receipt in c['retained_local_files']:
            path = str(Path(receipt['path']).relative_to(archive['root']))
            check(path in files and sha(files[path]) == receipt['sha256'] and len(files[path]) == receipt['bytes'],
                  name + ': retained receipt ' + path)
        original = c['original_remote_binding']
        binding = original['binding']
        check(binding['job_id'] == job and binding['request_digest'] == rec['request_digest'], name + ': remote original binding')
        check(c['actual_remote_hello']['remote_identity'] == remote, name + ': actual same remote machine')
        for actor in ('owner', 'business'):
            check(binding[actor]['boot_id'] == remote['boot_id'] and binding[actor]['uid'] == remote['uid'],
                  name + ': remote ' + actor + ' identity')
        check(original['owner_same_incarnation'] and original['business_same_incarnation']
              and not original['owner_exited'] and not original['business_exited'], name + ': bound live originals')
        for field in ('original_remote_binding', 'before_same_key_remote', 'after_same_key_remote',
                      'survived_controller_loss', 'final_remote', 'owner_loss'):
            if field not in c:
                continue
            observation = c[field]
            check(observation['binding'] == binding and observation['immutable'] == original['immutable'],
                  name + ': immutable original binding/' + field)
            check(decoded(observation['files']['effect'], name + '/' + field + '/effect') == b'EXECUTED\n',
                  name + ': exactly one original effect/' + field)
        same = c['same_key_reuse']
        check(same['reused'] and not same['retried_launch'] and same['launch'] is None
              and same['job']['id'] == same['status']['job_id'] == job, name + ': reuse without relaunch')
        for field in ('shutdown', 'custody_ssh_shutdown', 'final_custody_ssh_receipt'):
            custody(c[field], name + '/' + field)
            check(c[field]['identity']['uid'] == plan['controller_identity']['uid']
                  and c[field]['identity']['boot_id'] == plan['controller_identity']['boot_id'],
                  name + '/' + field + ': wait4 is for original local X230 child only')
        helper = c['remote_finish']['report']
        check(json.loads(decoded(c['remote_finish'], name + '/helper-final')) == helper, name + ': helper original bytes')
        check(helper['case'] == name and helper['case_nonce'] == c['case_nonce']
              and helper['plan_sha256'] == report['plan_sha256'] and helper['remote_identity'] == remote,
              name + ': helper final scope')
        check(helper['cleanup_complete'] and not helper['errors'] and helper['owner_pidfd_exited']
              and helper['business_pidfd_exited'] and not helper['remote_wait4_claimed']
              and helper['business_launches'] == helper['business_signals'] == 0, name + ': helper final custody')
        final = helper['final_observation']
        check(final['binding'] == binding and final['owner_exited'] and final['business_exited']
              and not final['owner_same_incarnation'] and not final['business_same_incarnation'], name + ': originals exited')
        check(decoded(final['files']['effect'], name + '/final-effect') == b'EXECUTED\n', name + ': final single effect')
        if name != 'owner-loss':
            custody(c['controller_crash'], name + '/controller-crash', crash=True, unconsumed=name == 'reply-loss')
            check(c['survived_controller_loss']['owner_same_incarnation']
                  and c['survived_controller_loss']['business_same_incarnation'], name + ': remote originals survived controller SIGKILL')
            terminal = c['terminal']
            exit_raw = decoded(final['files']['exit.json'], name + '/exit')
            exit_value = json.loads(exit_raw)
            witness = json.loads(decoded(final['files']['exit.witness.json'], name + '/witness'))
            check(all(terminal[k] == v for k, v in exit_value.items()) and witness['exit_sha256'] == sha(exit_raw)
                  and witness == c['witness'] and witness['job_id'] == job, name + ': authoritative exact terminal bytes')
            check(terminal['state'] == 'succeeded' and terminal['exit_code'] == 0 and terminal['output_complete']
                  and terminal['output_durable'] and terminal['terminal_publication_confirmed']
                  and not terminal['automatic_retry'], name + ': successful durable terminal')
            for stream in ('stdout', 'stderr'):
                part = c['output'][stream]
                content = decoded(final['files'][stream + '.log'], name + '/' + stream)
                expected = (b'BEGIN\nEND ' + INPUT_SHA.encode() + b'\n') if stream == 'stdout' else b'RECOVERY-STDERR\n'
                check(content == expected, name + ': original expected business output/' + stream)
                check(bytes.fromhex(part['bytes_hex']) == content and part['eof'] and part['offset'] == 0
                      and part['next_offset'] == part['size'] == len(content), name + ': exact read/' + stream)
            check(decoded(final['files']['stdin.bin'], name + '/original-stdin') == INPUT, name + ': exact durable stdin')
            check(not helper['owner_kill_attempted'], name + ': no owner kill')
            if name == 'reply-loss':
                check(c['launch_reply_consumed_before_controller_kill'] is False and c['unconsumed_launch_rpc_id'] == 2,
                      name + ': launch reply deliberately unconsumed')
        else:
            for status in (c['first_recovered_status'], same['status']):
                check(status['job_id'] == job and status['state'] in ('owner_unknown', 'finalizing') and status['outcome'] == 'unknown'
                      and not status['status_authoritative'] and not status['terminal_publication_confirmed']
                      and not status['automatic_retry'], name + ': conservative unknown outcome')
            signals = [e for e in helper['events'] if 'owner_signal' in e]
            check(helper['owner_kill_attempted'] and len(signals) == 1 and signals[0]['owner_signal'] == 'SIGKILL'
                  and signals[0]['via_original_pidfd'] and signals[0]['business_was_live']
                  and signals[0]['owner_identity'] == binding['owner'], name + ': one bound original owner SIGKILL')
            check('exit.witness.json' not in final['files'], name + ': no fabricated terminal witness')
        rows.append({'case': name, 'job_id': job, 'effect_count': 1, 'same_key_reused': True,
                     'retried_launch': False, 'original_local_records': 1,
                     'controller_sigkill': name != 'owner-loss', 'owner_sigkill': name == 'owner-loss',
                     'unconsumed_launch_reply_bytes': c.get('controller_crash', {}).get('unconsumed_reply_bytes', 0),
                     'normal_controller_wait4_exit_code': c['shutdown']['original_wait4']['exit_code'],
                     'custody_ssh_wait4_exit_code': c['custody_ssh_shutdown']['original_wait4']['exit_code'],
                     'terminal_claim': 'unknown, ' + c['first_recovered_status']['state'] + ', nonauthoritative' if name == 'owner-loss' else 'succeeded with original terminal witness'})
    for receipt in list(input_receipts):
        path = Path(receipt['path'])
        check(stamp(path.lstat()) == receipt['identity'] and sha(path.read_bytes()) == receipt['sha256'],
              'original local inputs unchanged at end: ' + str(path))
    return {'schema': 'hepta-a54-native-owner-independent-offline-audit/v1', 'passed': True,
            'actual_qualification_sha256': Q_SHA, 'actual_plan_sha256': PLAN_SHA,
            'actual_release_sha256': ELF_SHA, 'source_files': 175, 'source_map_compact_sha256': COMPACT_MAP_SHA,
            'local_input_receipts': input_receipts, 'local_input_fence_unchanged': True,
            'original_report_sha256': REPORT_SHA, 'original_archive_sha256': ARCHIVE_SHA,
            'archive_files_verified': len(files), 'base64_receipt_instances_verified': blob_count,
            'original_cases': rows, 'checks': checks, 'remote_calls': 0, 'business_launches': 0,
            'scope': 'Existing X230 controller to AI395 systemd owner evidence; no new execution',
            'not_proven': ['six-host pool gate', 'power loss', 'arbitrary external-effect exactly-once',
                           'observation pool acceptance', 'performance improvement']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--report-sha256', required=True)
    parser.add_argument('--report-bytes', type=int, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--archive-bytes', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('refuse to overwrite an existing audit')
    try:
        result = audit(args)
    except Exception as error:
        result = {'schema': 'hepta-a54-native-owner-independent-offline-audit/v1', 'passed': False,
                  'error': type(error).__name__ + ': ' + str(error), 'checks': checks,
                  'remote_calls': 0, 'business_launches': 0}
    encoded = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with args.out.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'path': str(args.out), 'passed': result['passed'], 'error': result.get('error'),
                      'checks': len(checks), 'sha256': sha(encoded)}))
    raise SystemExit(0 if result['passed'] else 1)
