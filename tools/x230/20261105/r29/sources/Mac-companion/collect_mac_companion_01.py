#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Capture the two fixed R29 formal Mac holder declarations. No SSH, workload or cleanup.

Completed failed originals are retained with their original negative fields.
Future executed states and hashes must be supplied from original terminal receipts.
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
WORK = Path('/Users/qianqi/work')
INPUTS = WORK / 'hepta-runtime-r29-mac-companion-inputs-01'
TOOLS = WORK / 'hepta-runtime-r29-mac-companion-tools-01'
OUT = WORK / 'hepta-runtime-r29-mac-companion-evidence-01'
HOLDER = WORK / 'hepta-runtime-x230-r21-20261105/held_agent_campaign_02.py'
HOLDER_PIN = (11374, '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65')
PLANS = {'observation01': {'directory': '/Users/qianqi/work/hepta-runtime-r29-observation-evidence-01',
                   'footer_gate': 'observation_gate_passed',
                   'footer_kind': 'formal',
                   'group': 'formal',
                   'known_job_id': '1a1ad77dfe5-fc05-59f9',
                   'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r29/campaign-01/report.json',
                   'script': '/Users/qianqi/work/hepta-runtime-r29-observation-campaign-01.py',
                   'script_bytes': 66141,
                   'script_sha256': '0eaf6dd96e6a69eba4ef382360febefd58e1f0370baf7cd79bb817ac2ce266ec',
                   'timeout_seconds': 3600},
 'lifecycle01': {'directory': '/Users/qianqi/work/hepta-runtime-r29-lifecycle-evidence-01',
                 'footer_gate': 'adoption_passed',
                 'footer_kind': 'formal',
                 'group': 'formal',
                 'known_job_id': None,
                 'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-campaign-01/report.json',
                 'script': '/Users/qianqi/work/hepta-runtime-r29-lifecycle-campaign-01.py',
                 'script_bytes': 26760,
                 'script_sha256': '12b9ad142d95148e9d08a69d44be3e4e3d17a03877eadc956a020602aa22e846',
                 'timeout_seconds': 3600}}
GROUPS = ('formal',)
GROUP_KINDS = {'formal': ('observation01', 'lifecycle01')}
ARCHIVE_NAMES = {'formal': 'formal-holders-01.tar.gz'}
FIXED_NAMES = frozenset(['forwarded.stderr', 'forwarded.stdout', 'identity-discovery-00.stderr', 'identity-discovery-01.stderr', 'identity-discovery-02.stderr', 'identity-discovery-03.stderr', 'identity-discovery-04.stderr', 'identity-discovery-05.stderr', 'identity-discovery-06.stderr', 'identity-load-00.stderr', 'identity-load-00.stdout', 'identity-load-01.stderr', 'identity-load-01.stdout', 'identity-load-02.stderr', 'identity-load-02.stdout', 'identity-load-03.stderr', 'identity-load-03.stdout', 'identity-load-04.stderr', 'identity-load-04.stdout', 'owned-agent.stderr', 'remote-script.py', 'report.json'])
KNOWN_ORIGINAL_PINS = {}
HEX = re.compile(r'[0-9a-f]{64}\Z')
JOB = re.compile(r'[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\Z')
LOG_NAME = re.compile(r'(?:report\.json|remote-script\.py|forwarded\.(?:stdout|stderr)|owned-agent\.stderr|'
                      r'identity-discovery-[0-9]{2,}\.stderr|identity-load-[0-9]{2,}\.(?:stdout|stderr))\Z')
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
CHUNK_BYTES = 48000
MAX_CHUNKS = 128
SECRET_RULES = [
    ('private_key_pem', re.compile(b'-----BEGIN ' + b'(?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?' + b'PRIVATE ' + b'KEY-----')),
    ('github_token', re.compile(rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b')),
    ('github_fine_grained_token', re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{40,}\b')),
    ('api_secret_token', re.compile(rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b')),
    ('authorization_bearer', re.compile(rb'(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}')),
    ('named_secret_value', re.compile(rb'''(?i)["'](?:api[_-]?key|access_token|refresh_token|client_secret|password|private_key)["']\s*:\s*["'][^"'\r\n]{8,}''')),
]


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def scan(raw):
    for label, pattern in SECRET_RULES:
        need(pattern.search(raw) is None, 'sensitive marker rejected: ' + label)


def stamp(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
            'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def version(info):
    return ':'.join(str(getattr(info, key)) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def directory(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect directory')
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o022 == 0,
         'directory owner/mode/type differs')
    return stamp(info)


def read(path, *, text_scan=True):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
             and before.st_mode & 0o022 == 0 and before.st_size <= MAX_FILE, 'input owner/mode/type/link/size differs')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_FILE + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'input changed during read')
        if text_scan:
            scan(raw)
        return raw, {'original_path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                     'mode': stat.S_IMODE(before.st_mode), 'version': version(before), 'stamp': stamp(before)}
    finally:
        os.close(fd)


def inventory(path):
    directory(path)
    rows = []
    for child in sorted(path.iterdir()):
        info = child.lstat()
        need(child.name in FIXED_NAMES and stat.S_ISREG(info.st_mode), 'unexpected holder entry; contents not read')
        rows.append({'name': child.name, 'stamp': stamp(info), 'version': version(info)})
    need({row['name'] for row in rows} == FIXED_NAMES, 'complete fixed 22-file original holder inventory required')
    return rows


def absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def tool_value(raw):
    value = parse(raw)
    if isinstance(value, dict) and 'result' in value:
        value = value['result']
    if isinstance(value, dict) and 'content' in value:
        need(value.get('isError', False) is False, 'native tool returned an error')
        texts = [block['text'] for block in value['content'] if block.get('type') == 'text']
        need(len(texts) == 1, 'native tool envelope is ambiguous')
        value = parse(texts[0])
    need(isinstance(value, dict), 'native evidence is not an object')
    return value


def terminal(value, job_id):
    need(value.get('job_id') == job_id and value.get('state') in ('succeeded', 'failed')
         and type(value.get('exit_code')) is int
         and ((value['state'] == 'succeeded' and value['exit_code'] == 0)
              or (value['state'] == 'failed' and value['exit_code'] != 0))
         and all(value.get(key) is False for key in ('automatic_retry', 'timed_out', 'cancelled'))
         and all(value.get(key) is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and type(value.get('terminal_publication_protocol')) is int and value['terminal_publication_protocol'] == 1
         and value.get('log_synced') == {'stdout': True, 'stderr': True}
         and value.get('log_errors') == {'stdout': None, 'stderr': None}
         and value.get('log_truncated') == {'stdout': False, 'stderr': False},
         'original native job lacks completed durable success/failure proof')


def native_streams(value, status, job_id):
    need(value.get('job_id') == job_id, 'native read belongs to another job')
    streams = {}
    for key in ('stdout', 'stderr'):
        row = value[key]
        need(isinstance(row.get('bytes_hex'), str), 'original native bytes are absent')
        raw = bytes.fromhex(row['bytes_hex'])
        need(type(row.get('size')) is int and row['size'] == len(raw)
             and type(row.get('offset')) is int and row['offset'] == 0
             and type(row.get('next_offset')) is int and row['next_offset'] == len(raw)
             and row.get('eof') is True and row.get('text') == raw.decode('utf-8'),
             'native stream is partial or decoded bytes differ')
        need(status['log_bytes'][key] == {'seen': len(raw), 'stored': len(raw)}
             and all(type(value) is int for value in status['log_bytes'][key].values()), 'native terminal byte count differs')
        scan(raw)
        streams[key] = raw
    return streams


def footer(raw):
    lines = [line for line in raw.decode('utf-8').splitlines() if line.strip()]
    need(lines, 'original stdout has no final nonempty line')
    value = parse(lines[-1])
    need(isinstance(value, dict), 'final stdout line is not an object')
    return value


def validate_holder(kind, files, status, streams, expected_report_sha, job_id):
    plan = PLANS[kind]
    need(JOB.fullmatch(job_id) and (plan['known_job_id'] is None or plan['known_job_id'] == job_id), 'original job identity differs')
    terminal(status, job_id)
    need(sha(files['report.json']) == expected_report_sha, 'actual holder report SHA differs')
    report = parse(files['report.json'])
    need(report.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1' and type(report.get('passed')) is bool
         and isinstance(report.get('finished_utc'), str) and report['finished_utc']
         and isinstance(report.get('started_utc'), str) and report['started_utc']
         and type(report.get('remote_returncode')) is int
         and report['passed'] is (report['remote_returncode'] == 0)
         and ((report['passed'] and 'error' not in report)
              or (not report['passed'] and isinstance(report.get('error'), dict)))
         and report.get('foreground_timed_out') is not True
         and report.get('remote_completion_unknown') is not True, 'holder is not a completed original success/failure')
    need(status['state'] == ('succeeded' if report['passed'] else 'failed')
         and status['exit_code'] == (0 if report['passed'] else 1),
         'original native outcome disagrees with the completed holder outcome')
    started = datetime.datetime.fromisoformat(report['started_utc'])
    finished = datetime.datetime.fromisoformat(report['finished_utc'])
    need(started.tzinfo is not None and finished.tzinfo is not None and finished >= started, 'holder UTC interval is invalid')
    need(report.get('holder_script_sha256') == HOLDER_PIN[1]
         and report.get('remote_script_sha256') == plan['script_sha256']
         and len(files['remote-script.py']) == plan['script_bytes'] and sha(files['remote-script.py']) == plan['script_sha256'],
         'holder or remote script identity differs')
    need(type(report.get('automatic_ssh_retries')) is int and report['automatic_ssh_retries'] == 0
         and report.get('services_modified') is False and report.get('key_bytes_retained') is False
         and report.get('complete_environment_retained') is False and report.get('ssh_configuration_dump_retained') is False,
         'holder retry/service/sensitive-data contract differs')
    need(report.get('timeout_seconds') == plan['timeout_seconds'] and type(report['timeout_seconds']) is int,
         'holder time bound differs from its fixed original plan')
    need(report.get('owned_agent_reaped') is True and type(report.get('owned_agent_returncode')) is int
         and report.get('owned_agent_directory_absent_after_context') is True
         and report.get('owned_agent_socket_absent_after_context') is True, 'owned agent cleanup is unproved')
    start, end = report.get('foreground_start_monotonic_ns'), report.get('foreground_end_monotonic_ns')
    need(type(start) is int and type(end) is int and end >= start
         and report.get('foreground_seconds') == (end - start) / 1e9
         and type(report.get('foreground_pid')) is int and report['foreground_pid'] > 1
         and type(report.get('owned_agent_pid')) is int and report['owned_agent_pid'] > 1,
         'original foreground/agent process completion fields differ')
    owned_dir, owned_socket = report.get('owned_agent_directory'), report.get('owned_agent_socket')
    need(isinstance(owned_dir, str) and re.fullmatch(r'/tmp/hr19a-[A-Za-z0-9_-]+', owned_dir)
         and owned_socket == owned_dir + '/agent.sock', 'owned cleanup paths are outside holder scope')
    expected_argv = ['/usr/bin/ssh', '-A', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                     '-o', 'StrictHostKeyChecking=yes', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                     '-o', 'ControlPersist=no', 'x230-ts', '/usr/bin/python3', '-B', '-', '--launcher-sha256', plan['script_sha256']]
    need(report.get('foreground_argv') == expected_argv, 'original foreground invocation differs')
    logs = report.get('log_files')
    need(isinstance(logs, list) and all(isinstance(row, dict) for row in logs), 'holder log inventory absent')
    names = [row.get('file') for row in logs]
    need(len(names) == len(set(names)) and set(names) == set(files) - {'report.json'}, 'holder log inventory is incomplete or duplicated')
    for row in logs:
        raw = files[row['file']]
        need(row.get('bytes') == len(raw) and type(row.get('bytes')) is int and row.get('sha256') == sha(raw), 'original log bytes differ')
    required = {'report.json', 'remote-script.py', 'forwarded.stdout', 'forwarded.stderr', 'owned-agent.stderr'}
    for group, count_key, prefix, suffixes in (
        ('identity_discovery', 'configured_target_count', 'identity-discovery', ('stderr',)),
        ('identity_loads', 'configured_identity_count', 'identity-load', ('stdout', 'stderr')),
    ):
        rows = report.get(group)
        count = report.get(count_key)
        expected_count = 7 if group == 'identity_discovery' else 5
        need(type(count) is int and count == expected_count and isinstance(rows, list) and len(rows) == count, 'identity operation count differs')
        need([row.get('index') for row in rows] == list(range(count)), 'identity operation sequence differs')
        for row in rows:
            need(type(row.get('returncode')) is int and row['returncode'] == 0, 'identity operation failed')
            for stream in suffixes:
                name = f"{prefix}-{row['index']:02d}.{stream}"
                required.add(name)
                raw = files[name]
                need(row.get(stream) == {'file': name, 'bytes': len(raw), 'sha256': sha(raw)}, 'identity stream bytes differ')
            if group == 'identity_loads':
                need(row.get('ttl_seconds') == plan['timeout_seconds'] + 120 and type(row.get('start_monotonic_ns')) is int
                     and type(row.get('end_monotonic_ns')) is int and row['end_monotonic_ns'] >= row['start_monotonic_ns'],
                     'identity TTL or operation timing differs')
    need(set(files) == required, 'unrecognized or missing original holder log')
    remote_footer = footer(files['forwarded.stdout'])
    need(type(remote_footer.get('passed')) is bool and remote_footer['passed'] is report['passed'],
         'remote final stdout disagrees with the completed original outcome')
    if plan['footer_kind'] == 'formal':
        need(remote_footer.get('report') == plan['remote_report']
             and type(remote_footer.get(plan['footer_gate'])) is bool
             and (not remote_footer['passed'] or remote_footer.get('error') is None),
             'formal final stdout does not close the exact original report')
        performance_gate = remote_footer[plan['footer_gate']]
    else:
        descriptor = remote_footer.get('report')
        need(remote_footer.get('phase') == 'source_bound_bootstrap_finished'
             and (type(remote_footer.get('wrapper_returncode')) is int
                  or remote_footer.get('wrapper_returncode') is None)
             and (not remote_footer['passed'] or remote_footer['wrapper_returncode'] == 0)
             and isinstance(descriptor, dict) and set(descriptor) == {'path', 'bytes', 'sha256'}
             and descriptor['path'] == plan['remote_report'] and type(descriptor['bytes']) is int
             and 0 < descriptor['bytes'] <= MAX_FILE and HEX.fullmatch(descriptor['sha256']),
             'diagnostic bootstrap final stdout does not bind its original report')
        performance_gate = None
    holder_footer = footer(streams['stdout'])
    need(holder_footer == {'passed': report['passed'], 'remote_returncode': report['remote_returncode'], 'owned_agent_reaped': True,
                           'report': plan['directory'] + '/report.json'}, 'native holder final stdout differs')
    ready_lines = [parse(line) for line in streams['stdout'].decode().splitlines() if line.strip()]
    need(len(ready_lines) == 2 and ready_lines[0] == {'phase': 'owned_agent_ready',
         'identity_count': report['configured_identity_count'], 'remote_script_sha256': plan['script_sha256']},
         'native holder original ready/final sequence differs')
    return {'job_id': job_id, 'holder_report_sha256': sha(files['report.json']),
            'holder_report_bytes': len(files['report.json']), 'remote_final_line': remote_footer,
            'native_holder_final_line': holder_footer, 'owned_directory': owned_dir, 'owned_socket': owned_socket,
            'original_logs': len(logs), 'foreground_seconds': report['foreground_seconds'],
            'started_utc': report['started_utc'], 'finished_utc': report['finished_utc'],
            'performance_gate_observed': performance_gate,
            'original_native_state': status['state'], 'original_native_exit_code': status['exit_code'],
            'original_holder_passed': report['passed'], 'original_remote_returncode': report['remote_returncode'],
            'original_holder_error': report.get('error')}


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def archive(path, payloads, manifest_raw):
    with path.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, raw in [('_export-manifest.json', manifest_raw)] + sorted(payloads.items()):
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(raw), 0o600, 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    tar.addfile(member, io.BytesIO(raw))
        stream.flush()
        os.fsync(stream.fileno())


def validate_input(value):
    need(isinstance(value, dict) and set(value) == {'schema', 'all_originals_terminal_or_unexecuted', 'holders'}
         and value['schema'] == 'hepta-r29-mac-companion-originals/v1'
         and value['all_originals_terminal_or_unexecuted'] is True
         and isinstance(value['holders'], dict) and set(value['holders']) == set(PLANS),
         'actual fixed original declarations required; unresolved future state must not execute')
    jobs = []
    for kind, plan in PLANS.items():
        row = value['holders'][kind]
        need(isinstance(row, dict) and set(row) == {'executed', 'job_id', 'report_sha256',
             'terminal_sha256', 'read_sha256', 'reason'} and type(row['executed']) is bool,
             'unresolved or extra original declaration fields: ' + kind)
        if row['executed']:
            need(isinstance(row['job_id'], str) and JOB.fullmatch(row['job_id'])
                 and (plan['known_job_id'] is None or row['job_id'] == plan['known_job_id'])
                 and all(isinstance(row[name], str) and HEX.fullmatch(row[name])
                         for name in ('report_sha256', 'terminal_sha256', 'read_sha256'))
                 and row['reason'] is None, 'actual original ID and byte hashes required: ' + kind)
            jobs.append(row['job_id'])
            if kind in KNOWN_ORIGINAL_PINS:
                need(all(row[key] == expected for key, expected in KNOWN_ORIGINAL_PINS[kind].items()),
                     'already observed original evidence must remain unchanged: ' + kind)
        else:
            need(plan['known_job_id'] is None and all(row[name] is None for name in
                 ('job_id', 'report_sha256', 'terminal_sha256', 'read_sha256'))
                 and isinstance(row['reason'], str) and row['reason'].strip(),
                 'known actual jobs cannot be omitted or replaced by an unexecuted declaration')
    need(len(jobs) == len(set(jobs)), 'original holder IDs must be distinct')
    return value['holders']


def input_inventory(expected):
    """Only exact input files and their optional known binary_write lock records."""
    directory(INPUTS)
    allowed_locks = {'.hepta-lock-' + sha(name.encode())[:24] for name in expected}
    rows, locks, observed = [], [], set()
    for path in sorted(INPUTS.iterdir()):
        need(path.name in expected or path.name in allowed_locks, 'unknown native-input entry; body not read')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and info.st_mode & 0o022 == 0, 'unsafe native input metadata')
        rows.append({'name': path.name, 'stamp': stamp(info), 'version': version(info)})
        if path.name in allowed_locks:
            raw, identity = read(path)
            need(raw == b'' and identity['mode'] == 0o600, 'known persistent lock is not empty private metadata')
            locks.append(identity)
        else:
            observed.add(path.name)
    need(observed == expected, 'missing exact original native input')
    return rows, locks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector-sha256', required=True)
    parser.add_argument('--consumer-sha256', required=True)
    parser.add_argument('--input-sha256', required=True)
    args = parser.parse_args()
    need(all(HEX.fullmatch(value) for value in vars(args).values()), 'canonical source/input hashes required')
    need(sys.platform == 'darwin' and os.geteuid() != 0, 'native nonroot Mac required')
    need(Path(__file__).absolute() == TOOLS / 'collect_mac_companion_01.py', 'fixed reviewed collector path required')
    for path in (WORK, TOOLS, INPUTS):
        directory(path)
    input_raw, input_identity = read(INPUTS / 'actual-input-01.json')
    need(sha(input_raw) == args.input_sha256, 'actual late-bound input SHA differs')
    declarations = validate_input(parse(input_raw))
    selected = [kind for group in GROUPS for kind in GROUP_KINDS[group] if declarations[kind]['executed']]
    expected_inputs = {'actual-input-01.json'} | {
        kind + '-' + suffix + '.json' for kind in selected for suffix in ('terminal', 'read')}
    native_inventory, input_locks = input_inventory(expected_inputs)
    source_pins = {'holder': list(HOLDER_PIN), 'collector_sha256': args.collector_sha256,
                   'consumer_sha256': args.consumer_sha256}
    need(not os.path.lexists(OUT), 'original capture output already exists; reconcile instead of replaying')
    original_jobs = {kind: declarations[kind]['job_id'] for kind in selected}
    originals, inventories, absent_paths, all_proofs = {}, {}, [], {}

    def capture(path):
        raw, identity = read(path)
        key = str(path)
        need(key not in originals or originals[key] == (raw, identity), 'one original source changed between groups')
        originals[key] = (raw, identity)
        return raw, identity

    holder_raw, _ = capture(HOLDER)
    need((len(holder_raw), sha(holder_raw)) == HOLDER_PIN, 'original unchanged holder source differs')
    for name, digest in (('collect_mac_companion_01.py', args.collector_sha256),
                         ('verify_mac_companion_01.py', args.consumer_sha256)):
        need(sha(capture(TOOLS / name)[0]) == digest, 'installed reviewed capture/consumer source differs')
    capture(INPUTS / 'actual-input-01.json')

    def unchanged():
        need(input_inventory(expected_inputs) == (native_inventory, input_locks), 'native input inventory or exact lock metadata changed')
        for path, (raw, identity) in originals.items():
            need(read(Path(path)) == (raw, identity), 'captured original bytes or descriptor changed')
        for kind, expected in inventories.items():
            need(inventory(Path(PLANS[kind]['directory'])) == expected, 'holder inventory changed')
        for path in absent_paths:
            need(absent(path), 'declared unexecuted or missing prepared source appeared during capture')
        for proof in all_proofs.values():
            need(absent(Path(proof['owned_directory'])) and absent(Path(proof['owned_socket'])),
                 'closed original owned agent path reappeared during capture')

    os.umask(0o077)
    OUT.mkdir(mode=0o700)
    receipt = {'schema': 'hepta-r29-mac-companion-receipt/v1', 'attempt': '01',
               'passed': False, 'capture_complete': False, 'source_inputs_unchanged': False,
               'groups': {}, 'input': input_identity, 'source_script_pins': source_pins,
               'original_jobs': original_jobs, 'original_outcomes': {}, 'automatic_retries': 0,
               'runtime_adoption_assessed': False, 'hosted_actions_passed': False,
               'x230_report_bytes_read': False}
    print(json.dumps({'phase': 'mac_companion_capture_ready', 'collector_sha256': args.collector_sha256,
                      'consumer_sha256': args.consumer_sha256, 'input_sha256': args.input_sha256}), flush=True)
    try:
        for group in GROUPS:
            kinds = list(GROUP_KINDS[group])
            executed = [kind for kind in kinds if declarations[kind]['executed']]
            need(executed, 'each fixed group must retain its already observed original')
            payloads, identities, prepared_sources, proofs = {}, {}, {}, {}

            def retain(path, member):
                need(member not in payloads, 'duplicate archive destination')
                raw, identity = capture(path)
                need(sum(len(body) for body in payloads.values()) + len(raw) <= MAX_TOTAL,
                     'bounded group evidence size exceeded')
                payloads[member], identities[member] = raw, identity
                return raw

            retain(HOLDER, 'sources/held_agent_campaign_02.py')
            for name in ('collect_mac_companion_01.py', 'verify_mac_companion_01.py'):
                retain(TOOLS / name, 'tools/' + name)
            need(retain(INPUTS / 'actual-input-01.json', 'inputs/actual-input-01.json') == input_raw,
                 'late-bound declaration changed')
            for kind in kinds:
                plan, declaration = PLANS[kind], declarations[kind]
                script_path, directory_path = Path(plan['script']), Path(plan['directory'])
                prepared_sources[kind] = {'captured': False, 'path': plan['script'],
                                          'bytes': plan['script_bytes'], 'sha256': plan['script_sha256']}
                if os.path.lexists(script_path):
                    raw = retain(script_path, 'sources/' + kind + '-campaign.py')
                    need((len(raw), sha(raw)) == (plan['script_bytes'], plan['script_sha256']),
                         'fixed staged original source differs: ' + kind)
                    prepared_sources[kind]['captured'] = True
                else:
                    need(not declaration['executed'], 'executed original staged source is absent')
                    absent_paths.append(script_path)
                if not declaration['executed']:
                    need(absent(directory_path), 'unexecuted declaration contradicts original holder directory')
                    absent_paths.append(directory_path)
                    continue
                inventories[kind] = inventory(directory_path)
                files = {row['name']: retain(directory_path / row['name'], 'holders/' + kind + '/' + row['name'])
                         for row in inventories[kind]}
                native = {}
                for suffix in ('terminal', 'read'):
                    raw = retain(INPUTS / (kind + '-' + suffix + '.json'), 'native/' + kind + '-' + suffix + '.json')
                    need(sha(raw) == declaration[suffix + '_sha256'], 'original native input hash differs')
                    native[suffix] = tool_value(raw)
                terminal(native['terminal'], declaration['job_id'])
                streams = native_streams(native['read'], native['terminal'], declaration['job_id'])
                proof = validate_holder(kind, files, native['terminal'], streams,
                                        declaration['report_sha256'], declaration['job_id'])
                for name in ('directory', 'socket'):
                    proof['current_owned_' + name + '_absent'] = absent(Path(proof['owned_' + name]))
                    need(proof['current_owned_' + name + '_absent'], 'original owned agent path remains')
                proofs[kind] = all_proofs[kind] = proof
                for stream, raw in streams.items():
                    member = 'native-decoded/' + kind + '.' + stream
                    payloads[member] = raw
                    identities[member] = {'bytes': len(raw), 'sha256': sha(raw), 'mode': 0o600,
                        'derived_from': 'native/' + kind + '-read.json',
                        'derivation': 'strict original bytes_hex decode; no inferred or substituted bytes'}
            unchanged()
            manifest = {'schema': 'hepta-r29-mac-companion-archive/v1', 'attempt': '01', 'group': group,
                'campaign_names': executed, 'declarations': {kind: declarations[kind] for kind in kinds},
                'campaigns': proofs, 'fixed_plans': {kind: PLANS[kind] for kind in kinds},
                'prepared_sources': prepared_sources,
                'files': [{'path': name, **identity} for name, identity in sorted(identities.items())],
                'source_inventories': {kind: [row['name'] for row in inventories[kind]] for kind in executed},
                'source_script_pins': source_pins, 'input_lock_metadata': input_locks,
                'included_original_holders_complete': True, 'capture_success_is_not_workload_success': True,
                'runtime_adoption_assessed': False, 'hosted_actions_passed': False,
                'cross_package_report_binding_required': True, 'x230_report_bytes_read': False,
                'new_ssh_workload_cleanup_or_service_operation': False, 'automatic_retries': 0}
            manifest_raw = encode(manifest)
            need(len(manifest_raw) <= 65536, 'compact group manifest exceeds one bounded metadata read')
            scan(manifest_raw)
            group_out = OUT / group
            group_out.mkdir(mode=0o700)
            write_new(group_out / 'manifest.json', manifest_raw)
            archive_path = group_out / ARCHIVE_NAMES[group]
            archive(archive_path, payloads, manifest_raw)
            archive_raw, archive_identity = read(archive_path, text_scan=False)
            need(0 < len(archive_raw) <= CHUNK_BYTES * MAX_CHUNKS, 'archive exceeds frozen transfer bound')
            (group_out / 'chunks').mkdir(mode=0o700)
            chunks = []
            for index, offset in enumerate(range(0, len(archive_raw), CHUNK_BYTES)):
                raw = archive_raw[offset:offset + CHUNK_BYTES]
                encoded = base64.b64encode(raw)
                path = group_out / 'chunks' / f'chunk-{index:04d}.b64'
                write_new(path, encoded)
                _, identity = read(path, text_scan=False)
                chunks.append({'path': path.relative_to(OUT).as_posix(), 'offset': offset,
                               'bytes': len(raw), 'sha256': sha(raw), 'text_bytes': len(encoded),
                               'text_sha256': sha(encoded), 'version': identity['version']})
            chunk_manifest = {'schema': 'hepta-r29-mac-companion-text-chunks/v1', 'group': group,
                'chunk_bytes': CHUNK_BYTES, 'archive': archive_identity, 'chunks': chunks,
                'read_multiple_files': {'host': 'main', 'paths_per_rpc_max': 4,
                                        'max_file_bytes': 65536, 'max_response_bytes': 262144}}
            chunk_raw = encode(chunk_manifest)
            need(len(chunk_raw) <= 65536, 'chunk manifest exceeds one bounded metadata read')
            write_new(group_out / 'chunks-manifest.json', chunk_raw)
            need(read(archive_path, text_scan=False) == (archive_raw, archive_identity), 'archive changed across chunking')
            receipt['groups'][group] = {'campaign_names': executed, 'archive': archive_identity,
                'manifest': read(group_out / 'manifest.json')[1],
                'chunks_manifest': read(group_out / 'chunks-manifest.json')[1],
                'payload_files': len(payloads), 'archive_members': len(payloads) + 1,
                'source_bytes': sum(len(body) for body in payloads.values())}
        intervals = sorted((datetime.datetime.fromisoformat(proof['started_utc']),
                            datetime.datetime.fromisoformat(proof['finished_utc']), kind)
                           for kind, proof in all_proofs.items())
        need(all(intervals[index - 1][1] <= intervals[index][0] for index in range(1, len(intervals))),
             'fixed original Mac holder intervals overlap')
        unchanged()
        receipt.update(passed=True, capture_complete=True, source_inputs_unchanged=True,
                       original_outcomes=all_proofs)
    except BaseException as error:
        receipt['error'] = {'type': type(error).__name__, 'reason': str(error)}
        receipt['original_outcomes'] = all_proofs
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_new(OUT / 'receipt.json', encode(receipt))
        for path in [OUT] + [OUT / group for group in GROUPS if (OUT / group).exists()] + [
                OUT / group / 'chunks' for group in GROUPS if (OUT / group / 'chunks').exists()]:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        print(json.dumps({'passed': receipt['passed'], 'receipt': str(OUT / 'receipt.json'),
                          'archive_groups': list(receipt['groups']), 'original_jobs': original_jobs}), flush=True)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'error_type': type(error).__name__, 'reason': str(error),
                          'automatic_retries': 0, 'originals_modified': False}), flush=True)
        raise SystemExit(1)

