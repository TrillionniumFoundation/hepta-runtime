#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independently verify two Mac companion archives and their original native custody.

Local evidence only: no network, subprocess, archived-code execution or cleanup.
A complete failed holder remains a failed holder; capture success is separate.
The original R25 verifier supplies the local-read, JSON, text-transport and
holder guards. Gzip completion uses the reviewed stable_archive zlib algorithm.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import zlib

sys.dont_write_bytecode = True
REMOTE = '/Users/qianqi/work/hepta-runtime-r26-mac-holder-export-01'
NATIVE_INPUTS = '/Users/qianqi/work/hepta-runtime-r26-mac-holder-inputs-01'
TOOLS = '/Users/qianqi/work/hepta-runtime-r26-mac-companion-tools-01'
HOLDER = '/Users/qianqi/work/hepta-runtime-x230-r21-20261105/held_agent_campaign_02.py'
HOLDER_PIN = (11374, '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65')
PLANS = {'lifecycle01': {'directory': '/Users/qianqi/work/hepta-runtime-r26-lifecycle-evidence-01',
                 'footer_gate': 'adoption_passed',
                 'footer_kind': 'formal',
                 'group': 'formal',
                 'known_job_id': '1a1ababc175-fc05-4f94',
                 'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-campaign-01/report.json',
                 'script': '/Users/qianqi/work/hepta-runtime-r26-lifecycle-campaign-03.py',
                 'script_bytes': 26760,
                 'script_sha256': '2970725473f7dab854a9d13326aa0ca792b9442615d325ebb0e767065bd08f37',
                 'timeout_seconds': 3600},
 'lifecycle02': {'directory': '/Users/qianqi/work/hepta-runtime-r26-lifecycle-evidence-02',
                 'footer_gate': 'adoption_passed',
                 'footer_kind': 'formal',
                 'group': 'formal',
                 'known_job_id': '1a1abcac847-fc05-509a',
                 'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-campaign-02/report.json',
                 'script': '/Users/qianqi/work/hepta-runtime-r26-lifecycle-campaign-04.py',
                 'script_bytes': 37172,
                 'script_sha256': '73435f80156d6b20b0ca8ffadbc7ae583182f3ae78b00949f77a16101522a182',
                 'timeout_seconds': 3600},
 'observation01': {'directory': '/Users/qianqi/work/hepta-runtime-r26-observation-evidence-01',
                   'footer_gate': 'observation_gate_passed',
                   'footer_kind': 'formal',
                   'group': 'formal',
                   'known_job_id': '1a1ab9c71ee-fc05-4f01',
                   'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r26/campaign-01/report.json',
                   'script': '/Users/qianqi/work/hepta-runtime-r26-observation-campaign-03.py',
                   'script_bytes': 55076,
                   'script_sha256': '34883c3b7bcae75e81604e7a3fb2845540eef979328010f4f597fdd218f79add',
                   'timeout_seconds': 3600},
 'phase02': {'directory': '/Users/qianqi/work/hepta-runtime-r25-phase-evidence-02',
             'footer_gate': None,
             'footer_kind': 'diagnostic',
             'group': 'diagnostics',
             'known_job_id': '1a1ab6ef44c-fc05-4dd3',
             'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-bootstrap-report-02.json',
             'script': '/Users/qianqi/work/hepta-runtime-r25-phase-bootstrap-02.py',
             'script_bytes': 7133,
             'script_sha256': '776fef341b0006af71277e4a2fe0aae31410475182f2f8a299747eb36be3b0b3',
             'timeout_seconds': 2700},
 'phase03': {'directory': '/Users/qianqi/work/hepta-runtime-r25-phase-evidence-03',
             'footer_gate': None,
             'footer_kind': 'diagnostic',
             'group': 'diagnostics',
             'known_job_id': None,
             'remote_report': '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-bootstrap-report-03.json',
             'script': '/Users/qianqi/work/hepta-runtime-r25-phase-bootstrap-03.py',
             'script_bytes': 7133,
             'script_sha256': '79989ebf185f9d2cead0ba60ecd1a7edebd91ca8c07c541cdab5ef64d1f69fbf',
             'timeout_seconds': 2700}}
GROUPS = {'formal': ['observation01', 'lifecycle01', 'lifecycle02'], 'diagnostics': ['phase02', 'phase03']}
ARCHIVE_NAMES = {'diagnostics': 'diagnostic-holders-01.tar.gz', 'formal': 'formal-holders-01.tar.gz'}
FIXED_HOLDER_FILES = ['forwarded.stderr',
 'forwarded.stdout',
 'identity-discovery-00.stderr',
 'identity-discovery-01.stderr',
 'identity-discovery-02.stderr',
 'identity-discovery-03.stderr',
 'identity-discovery-04.stderr',
 'identity-discovery-05.stderr',
 'identity-discovery-06.stderr',
 'identity-load-00.stderr',
 'identity-load-00.stdout',
 'identity-load-01.stderr',
 'identity-load-01.stdout',
 'identity-load-02.stderr',
 'identity-load-02.stdout',
 'identity-load-03.stderr',
 'identity-load-03.stdout',
 'identity-load-04.stderr',
 'identity-load-04.stdout',
 'owned-agent.stderr',
 'remote-script.py',
 'report.json']
HEX = re.compile(r'[0-9a-f]{64}\Z')
JOB = re.compile(r'[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\Z')
VERSION = re.compile(r'[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+\Z')
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ARCHIVE = 48000 * 128
BLOCK = 1024 * 1024
KNOWN_ORIGINAL_PINS = {
    'observation01': {
        'report_sha256': '82bde5c41d8303df3072caecadb4e3d6dce1f09734852418076688e55cc1f1b2',
        'terminal_sha256': '03f79a94f98e4b46a27b23510e0cb4b2e44c77242a99592e21813e0e1e13cea0',
        'read_sha256': '052beae306e01b6c878abb97f84d8f92bca6cc8ac3f0c4d5b5bb5c49ec1cda7a'},
    'lifecycle01': {
        'report_sha256': 'c5569b1fbeb40acd5f8c10ff33f6bd7afc58c9862ef949309d6c88387bf1bd69',
        'terminal_sha256': '87f52ad158e945f95976b31d85b720938374bf52ec010acee045e4a819c65aea',
        'read_sha256': '3d2ced2ae58f9f478c2174b73538540a76fb9f2544032703d0eb18e37993d247'},
    'phase02': {
        'report_sha256': '25de2008f949ab5c4fa95945f7e35ffe86689153aff76dce7fcb209b0af10f04',
        'terminal_sha256': 'c26bfbe38a92b36501477e054541e973d7950c021fe2a7916ca699effd57f1e0',
        'read_sha256': 'dc55212bcef36d36e56f613b6fece7302c31eab3b8025acf64e757d63d29bcef'},
}
SECRET_PATTERNS = [
    re.compile(b'-----BEGIN ' + b'(?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?' + b'PRIVATE ' + b'KEY-----'),
    re.compile(rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{40,}\b'),
    re.compile(rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b'),
    re.compile(rb'(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}'),
    re.compile(rb'''(?i)["'](?:api[_-]?key|access_token|refresh_token|client_secret|password|private_key)["']\s*:\s*["'][^"'\r\n]{8,}'''),
]


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(items):
        output = {}
        for key, value in items:
            need(key not in output, 'duplicate JSON key')
            output[key] = value
        return output
    return json.loads(raw, object_pairs_hook=unique)


def scan(raw):
    need(not any(pattern.search(raw) for pattern in SECRET_PATTERNS), 'sensitive marker in received evidence')


def read(path, limit=MAX_FILE):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect local input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'unbounded or nonregular local input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key)
             for after in (os.fstat(fd), path.lstat()) for key in fields), 'local input changed')
        return raw
    finally:
        os.close(fd)


def unwrap(raw):
    value = parse(raw)
    if isinstance(value, dict) and 'result' in value:
        value = value['result']
    if isinstance(value, dict) and 'content' in value:
        need(value.get('isError', False) is False, 'recorded MCP error')
        text = [item['text'] for item in value['content'] if item.get('type') == 'text']
        need(len(text) == 1, 'ambiguous native tool result')
        value = parse(text[0])
    need(isinstance(value, dict), 'native result must be an object')
    return value


def last_json(raw):
    lines = [line for line in raw.decode('utf-8').splitlines() if line.strip()]
    need(lines, 'missing original final stdout')
    value = parse(lines[-1])
    need(isinstance(value, dict), 'final stdout is not an object')
    return value


def transport(rows, files, expected_versions):
    """Validate original successful read_multiple_files request/reply envelopes."""
    found = {}
    for raw in rows:
        envelope = parse(raw)
        request = envelope['request']
        need(request.get('host') == 'main' and 1 <= len(request['paths']) <= 4
             and len(set(request['paths'])) == len(request['paths'])
             and 1 <= request.get('max_file_bytes', 16384) <= 65536
             and 1024 <= request.get('max_response_bytes', 65536) <= 262144, 'unbounded or wrong-host transport request')
        result = unwrap(json.dumps(envelope['result']))
        need(result.get('truncated') is False and result.get('encoding') == 'utf-8'
             and result.get('atomic_snapshot') is False and result.get('snapshot_scope') == 'independent_file',
             'transport result is truncated or lacks independent-file provenance')
        returned = result['files']
        need(len(returned) == len(request['paths']) and {row['path'] for row in returned} == set(request['paths']),
             'transport returned a different file set')
        for row in returned:
            path = row['path']
            need(path.startswith(REMOTE + '/'), 'transport path is outside fixed exporter')
            name = path[len(REMOTE) + 1:]
            need(name in files and row.get('eof') is True and isinstance(row.get('text'), str), 'unexpected or incomplete transported file')
            raw_file = row['text'].encode('utf-8')
            need(type(row.get('size')) is int and row['size'] == len(raw_file) <= 65536
                 and row.get('sha256') == sha(raw_file) and raw_file == files[name]
                 and row.get('version') == expected_versions[name] and VERSION.fullmatch(row['version'])
                 and int(row['version'].split(':')[2]) == len(raw_file), 'transported bytes, SHA or pinned version differ')
            identity = {key: row[key] for key in ('path', 'size', 'sha256', 'version')}
            need(name not in found or found[name] == identity, 'repeated transport observed changing input')
            found[name] = identity
    need(set(found) == set(files), 'not every received text file has an original pinned transport receipt')
    return found


def validate_input(value):
    need(isinstance(value, dict) and set(value) == {
        'schema', 'all_originals_terminal_or_unexecuted', 'holders'}
        and value['schema'] == 'hepta-r26-mac-companion-originals/v1'
        and value['all_originals_terminal_or_unexecuted'] is True
        and isinstance(value['holders'], dict) and set(value['holders']) == set(PLANS),
        'actual, resolved original declarations required')
    jobs = {}
    for kind, plan in PLANS.items():
        row = value['holders'][kind]
        need(isinstance(row, dict) and set(row) == {
            'executed', 'job_id', 'report_sha256', 'terminal_sha256', 'read_sha256', 'reason'}
            and type(row['executed']) is bool, 'unresolved or unexpected original declaration')
        if row['executed']:
            need(isinstance(row['job_id'], str) and JOB.fullmatch(row['job_id'])
                 and (plan['known_job_id'] is None or row['job_id'] == plan['known_job_id'])
                 and row['reason'] is None
                 and all(isinstance(row[key], str) and HEX.fullmatch(row[key])
                         for key in ('report_sha256', 'terminal_sha256', 'read_sha256')),
                 'actual executed original job and complete byte pins required')
            jobs[kind] = row['job_id']
            if kind in KNOWN_ORIGINAL_PINS:
                need(all(row[key] == digest for key, digest in KNOWN_ORIGINAL_PINS[kind].items()),
                     'known original negative or positive byte pins were changed')
        else:
            need(plan['known_job_id'] is None and row['job_id'] is None
                 and all(row[key] is None for key in ('report_sha256', 'terminal_sha256', 'read_sha256'))
                 and isinstance(row['reason'], str) and row['reason'].strip(),
                 'known original operation cannot be erased or assigned an invented result')
    need(len(set(jobs.values())) == len(jobs), 'original job reused for distinct holders')
    return value['holders'], jobs


def native_proof(status_raw, read_raw, job_id, *, require_success=False):
    status, original = unwrap(status_raw), unwrap(read_raw)
    need(isinstance(job_id, str) and JOB.fullmatch(job_id)
         and status.get('job_id') == original.get('job_id') == job_id
         and status.get('state') in ('succeeded', 'failed')
         and type(status.get('exit_code')) is int
         and status['exit_code'] == (0 if status['state'] == 'succeeded' else 1)
         and (not require_success or status['state'] == 'succeeded')
         and all(status.get(name) is False for name in ('automatic_retry', 'timed_out', 'cancelled'))
         and all(status.get(name) is True for name in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and type(status.get('terminal_publication_protocol')) is int and status['terminal_publication_protocol'] == 1
         and status.get('log_synced') == {'stdout': True, 'stderr': True}
         and status.get('log_errors') == {'stdout': None, 'stderr': None}
         and status.get('log_truncated') == {'stdout': False, 'stderr': False},
         'original native terminal is incomplete, unknown or inconsistent')
    streams = {}
    for name in ('stdout', 'stderr'):
        row = original[name]
        need(isinstance(row.get('bytes_hex'), str) and len(row['bytes_hex']) <= MAX_FILE * 2,
             'original native byte stream missing or exceeds bound')
        raw = bytes.fromhex(row['bytes_hex'])
        need(type(row.get('offset')) is int and row['offset'] == 0
             and type(row.get('next_offset')) is int and row['next_offset'] == len(raw)
             and type(row.get('size')) is int and row['size'] == len(raw)
             and row.get('eof') is True and row.get('text') == raw.decode('utf-8')
             and status['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)}
             and all(type(value) is int for value in status['log_bytes'][name].values()),
             'native stream is partial or inconsistent')
        scan(raw)
        streams[name] = raw
    return status, streams


def verify_gzip(raw):
    """Reviewed stable_archive single-member/CRC/ISIZE/EOF algorithm, on bound bytes."""
    need(0 < len(raw) <= MAX_ARCHIVE, 'compressed archive exceeds fixed chunk bound')
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = 0
    for offset in range(0, len(raw), BLOCK):
        need(not decoder.eof, 'trailing compressed bytes or concatenated gzip stream')
        pending = raw[offset:offset + BLOCK]
        while pending:
            block = decoder.decompress(pending, BLOCK)
            expanded += len(block)
            need(expanded <= MAX_TOTAL, 'expanded archive exceeds fixed bound')
            need(not decoder.unused_data, 'trailing compressed bytes or concatenated gzip stream')
            pending = decoder.unconsumed_tail
    need(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'gzip trailer or compressed EOF is incomplete')
    return {'single_gzip_member': True, 'crc_and_isize_verified': True,
            'exact_compressed_eof': True, 'expanded_bytes': expanded}


def restore_archive(raw, manifest_raw, records):
    gzip_proof = verify_gzip(raw)
    need(isinstance(records, list), 'archive records must be a list')
    by_name = {row['path']: row for row in records}
    need(len(by_name) == len(records) <= 300, 'duplicate or excessive archive inventory')
    restored, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(path.parts and not path.is_absolute() and str(path) == member.name
                 and all(part not in ('', '.', '..') for part in path.parts)
                 and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.linkname
                 and not member.sparse and not member.pax_headers and member.mode == 0o600
                 and member.name not in restored and 0 <= member.size <= MAX_FILE
                 and member.name in set(by_name) | {'_export-manifest.json'},
                 'unsafe, duplicated or unexpected archive member')
            total += member.size
            need(total <= MAX_TOTAL and len(restored) < 301, 'expanded archive exceeds fixed bounds')
            stream = archive.extractfile(member)
            need(stream is not None, 'regular archive member unreadable')
            body = stream.read(MAX_FILE + 1)
            need(len(body) == member.size, 'archive member is truncated')
            scan(body)
            if member.name == '_export-manifest.json':
                need(body == manifest_raw, 'embedded and external manifests differ')
            else:
                row = by_name[member.name]
                need(type(row['bytes']) is int and row['bytes'] == len(body)
                     and row['sha256'] == sha(body), 'archive member identity differs')
            restored[member.name] = body
    need(set(restored) == set(by_name) | {'_export-manifest.json'},
         'archive does not contain the complete exact manifest')
    return restored, gzip_proof


def source_identity(row, expected_path):
    need(row.get('original_path') == expected_path
         and type(row.get('bytes')) is int and 0 <= row['bytes'] <= MAX_FILE
         and isinstance(row.get('sha256'), str) and HEX.fullmatch(row['sha256']),
         'captured original source path or byte identity differs')
    witness = row['stamp']
    need(isinstance(witness, dict) and set(witness) == {
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'}
        and all(type(value) is int and value >= 0 for value in witness.values())
        and stat.S_ISREG(witness['st_mode']) and witness['st_mode'] & 0o022 == 0
        and witness['st_nlink'] == 1 and witness['st_uid'] > 0
        and witness['st_size'] == row['bytes'] and stat.S_IMODE(witness['st_mode']) == row['mode'],
        'captured original owner/mode/link/type/length differs')
    version = ':'.join(str(witness[key]) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    need(row.get('version') == version and VERSION.fullmatch(version),
         'captured original version differs from stat witness')
    return witness['st_uid']


def original_paths(records, group):
    owners = set()
    for row in records:
        name = row['path']
        parts = name.split('/')
        if name.startswith('native-decoded/'):
            match = re.fullmatch(r'native-decoded/([a-z0-9]+)\.(stdout|stderr)', name)
            need(match is not None and match[1] in GROUPS[group]
                 and row.get('derived_from') == 'native/' + match[1] + '-read.json'
                 and row.get('mode') == 0o600 and 'original_path' not in row,
                 'invalid decoded native stream provenance')
            continue
        if name.startswith('holders/'):
            need(len(parts) == 3 and parts[1] in GROUPS[group]
                 and parts[2] in FIXED_HOLDER_FILES, 'unexpected original holder path')
            expected = PLANS[parts[1]]['directory'] + '/' + parts[2]
        elif name == 'sources/held_agent_campaign_02.py':
            expected = HOLDER
        elif name.startswith('sources/'):
            matches = [kind for kind in GROUPS[group] if name == 'sources/' + kind + '-campaign.py']
            need(len(matches) == 1, 'unexpected staged parent source')
            expected = PLANS[matches[0]]['script']
        elif name in ('tools/collect_mac_companion_01.py', 'tools/verify_mac_companion_01.py'):
            expected = TOOLS + '/' + parts[1]
        elif name == 'inputs/actual-input-01.json':
            expected = NATIVE_INPUTS + '/actual-input-01.json'
        else:
            match = re.fullmatch(r'native/([a-z0-9]+)-(terminal|read)\.json', name)
            need(match is not None and match[1] in GROUPS[group], 'unexpected original source member')
            expected = NATIVE_INPUTS + '/' + parts[1]
        owners.add(source_identity(row, expected))
    need(len(owners) == 1, 'captured originals have inconsistent Mac owners')
    return owners.pop()


def verify_locks(rows, declarations, owner):
    expected = {'actual-input-01.json'}
    for kind, row in declarations.items():
        if row['executed']:
            expected.update(kind + '-' + suffix + '.json' for suffix in ('terminal', 'read'))
    allowed = {NATIVE_INPUTS + '/.hepta-lock-' + sha(name.encode())[:24] for name in expected}
    need(isinstance(rows, list) and len(rows) <= len(allowed), 'input lock inventory exceeds fixed scope')
    seen = set()
    for row in rows:
        path = row.get('original_path')
        need(path in allowed and path not in seen and row.get('bytes') == 0
             and row.get('sha256') == sha(b'') and row.get('mode') == 0o600,
             'unexpected input lock path or contents')
        need(source_identity(row, path) == owner, 'input lock owner differs from captured originals')
        seen.add(path)


def verify_holder(kind, files, declaration, status, streams):
    """Derive the original result from complete original bytes, including failed1."""
    plan = PLANS[kind]
    need(set(files) == set(FIXED_HOLDER_FILES) and sha(files['report.json']) == declaration['report_sha256'],
         'original holder file set or report pin differs')
    report = parse(files['report.json'])
    need(report.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1'
         and type(report.get('passed')) is bool and type(report.get('remote_returncode')) is int
         and report['passed'] is (report['remote_returncode'] == 0)
         and ((report['passed'] and 'error' not in report)
              or (not report['passed'] and isinstance(report.get('error'), dict)))
         and report.get('foreground_timed_out') is not True
         and report.get('remote_completion_unknown') is not True,
         'holder is not a completed original success/failure')
    need(status['state'] == ('succeeded' if report['passed'] else 'failed')
         and status['exit_code'] == (0 if report['passed'] else 1),
         'native and holder original outcomes disagree')
    started = datetime.datetime.fromisoformat(report['started_utc'])
    finished = datetime.datetime.fromisoformat(report['finished_utc'])
    need(started.tzinfo is not None and finished.tzinfo is not None and finished >= started,
         'holder UTC interval is invalid')
    need(report.get('holder_script_sha256') == HOLDER_PIN[1]
         and report.get('remote_script_sha256') == plan['script_sha256']
         and (len(files['remote-script.py']), sha(files['remote-script.py']))
             == (plan['script_bytes'], plan['script_sha256']), 'holder source binding differs')
    need(type(report.get('automatic_ssh_retries')) is int and report['automatic_ssh_retries'] == 0
         and all(report.get(key) is False for key in ('services_modified', 'key_bytes_retained',
                 'complete_environment_retained', 'ssh_configuration_dump_retained'))
         and type(report.get('timeout_seconds')) is int and report['timeout_seconds'] == plan['timeout_seconds'],
         'holder time/retry/service/sensitive-data contract differs')
    need(report.get('owned_agent_reaped') is True and type(report.get('owned_agent_returncode')) is int
         and report.get('owned_agent_directory_absent_after_context') is True
         and report.get('owned_agent_socket_absent_after_context') is True,
         'original holder did not close its owned agent')
    owned_dir, owned_socket = report.get('owned_agent_directory'), report.get('owned_agent_socket')
    need(isinstance(owned_dir, str) and re.fullmatch(r'/tmp/hr19a-[A-Za-z0-9_-]+', owned_dir)
         and owned_socket == owned_dir + '/agent.sock', 'holder owned paths differ')
    start, end = report.get('foreground_start_monotonic_ns'), report.get('foreground_end_monotonic_ns')
    need(type(start) is int and type(end) is int and end >= start
         and report.get('foreground_seconds') == (end - start) / 1e9
         and all(type(report.get(key)) is int and report[key] > 1 for key in ('foreground_pid', 'owned_agent_pid')),
         'foreground completion fields differ')
    expected_argv = ['/usr/bin/ssh', '-A', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                     '-o', 'StrictHostKeyChecking=yes', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                     '-o', 'ControlPersist=no', 'x230-ts', '/usr/bin/python3', '-B', '-',
                     '--launcher-sha256', plan['script_sha256']]
    need(report.get('foreground_argv') == expected_argv, 'original foreground argv differs')
    logs = report['log_files']
    names = [row['file'] for row in logs]
    need(len(names) == len(set(names)) and set(names) == set(files) - {'report.json'},
         'original log inventory is incomplete or duplicated')
    for row in logs:
        need(type(row.get('bytes')) is int and row['bytes'] == len(files[row['file']])
             and row['sha256'] == sha(files[row['file']]), 'original log bytes differ')
    for field, count_key, prefix, suffixes, count in (
        ('identity_discovery', 'configured_target_count', 'identity-discovery', ('stderr',), 7),
        ('identity_loads', 'configured_identity_count', 'identity-load', ('stdout', 'stderr'), 5),
    ):
        rows = report[field]
        need(type(report[count_key]) is int and report[count_key] == count
             and len(rows) == count and [row['index'] for row in rows] == list(range(count)),
             'identity operation sequence or count differs')
        for row in rows:
            need(type(row['returncode']) is int and row['returncode'] == 0, 'identity operation failed')
            for stream in suffixes:
                name = f"{prefix}-{row['index']:02d}.{stream}"
                need(row[stream] == {'file': name, 'bytes': len(files[name]), 'sha256': sha(files[name])},
                     'identity operation stream differs')
            if field == 'identity_loads':
                need(row['ttl_seconds'] == plan['timeout_seconds'] + 120
                     and type(row['start_monotonic_ns']) is int and type(row['end_monotonic_ns']) is int
                     and row['end_monotonic_ns'] >= row['start_monotonic_ns'], 'identity TTL or lifetime differs')
    remote_footer = last_json(files['forwarded.stdout'])
    need(type(remote_footer.get('passed')) is bool and remote_footer['passed'] is report['passed'],
         'forwarded terminal result disagrees with the original holder')
    if plan['footer_kind'] == 'formal':
        need(remote_footer.get('report') == plan['remote_report']
             and type(remote_footer.get(plan['footer_gate'])) is bool
             and (not remote_footer['passed'] or remote_footer.get('error') is None),
             'formal original terminal footer differs')
        gate = remote_footer[plan['footer_gate']]
    else:
        descriptor = remote_footer.get('report')
        need(remote_footer.get('phase') == 'source_bound_bootstrap_finished'
             and (type(remote_footer.get('wrapper_returncode')) is int
                  or remote_footer.get('wrapper_returncode') is None)
             and (not remote_footer['passed'] or remote_footer['wrapper_returncode'] == 0)
             and isinstance(descriptor, dict) and set(descriptor) == {'path', 'bytes', 'sha256'}
             and descriptor['path'] == plan['remote_report']
             and type(descriptor['bytes']) is int and 0 < descriptor['bytes'] <= MAX_FILE
             and isinstance(descriptor['sha256'], str) and HEX.fullmatch(descriptor['sha256']),
             'diagnostic original bootstrap footer differs')
        gate = None
    lines = [parse(line) for line in streams['stdout'].decode().splitlines() if line.strip()]
    holder_footer = {'passed': report['passed'], 'remote_returncode': report['remote_returncode'],
                     'owned_agent_reaped': True, 'report': plan['directory'] + '/report.json'}
    need(lines == [{'phase': 'owned_agent_ready', 'identity_count': 5,
                    'remote_script_sha256': plan['script_sha256']}, holder_footer],
         'original native holder output sequence differs')
    return {'job_id': declaration['job_id'], 'holder_report_sha256': sha(files['report.json']),
            'holder_report_bytes': len(files['report.json']), 'remote_final_line': remote_footer,
            'native_holder_final_line': holder_footer, 'owned_directory': owned_dir, 'owned_socket': owned_socket,
            'original_logs': len(logs), 'foreground_seconds': report['foreground_seconds'],
            'started_utc': report['started_utc'], 'finished_utc': report['finished_utc'],
            'performance_gate_observed': gate, 'original_native_state': status['state'],
            'original_native_exit_code': status['exit_code'], 'original_holder_passed': report['passed'],
            'original_remote_returncode': report['remote_returncode'], 'original_holder_error': report.get('error'),
            'current_owned_directory_absent': True, 'current_owned_socket_absent': True}


def verify_group(restored, manifest, group, actual_input_raw, tool_pins):
    declarations, jobs = validate_input(parse(actual_input_raw))
    kinds = GROUPS[group]
    selected = [kind for kind in kinds if declarations[kind]['executed']]
    need(manifest.get('schema') == 'hepta-r26-mac-companion-archive/v1'
         and manifest.get('attempt') == '01' and manifest.get('group') == group
         and manifest.get('campaign_names') == selected
         and manifest.get('declarations') == {kind: declarations[kind] for kind in kinds}
         and manifest.get('fixed_plans') == {kind: PLANS[kind] for kind in kinds}
         and set(manifest.get('campaigns', {})) == set(selected)
         and set(manifest.get('source_inventories', {})) == set(selected)
         and set(manifest.get('prepared_sources', {})) == set(kinds), 'group selection or declarations differ')
    need(all(manifest.get(key) is True for key in (
        'included_original_holders_complete', 'capture_success_is_not_workload_success',
        'cross_package_report_binding_required'))
        and all(manifest.get(key) is False for key in (
            'runtime_adoption_assessed', 'hosted_actions_passed', 'x230_report_bytes_read',
            'new_ssh_workload_cleanup_or_service_operation'))
        and type(manifest.get('automatic_retries')) is int and manifest['automatic_retries'] == 0,
        'group manifest broadens its capture-only scope')
    need(manifest.get('source_script_pins') == tool_pins
         and restored['inputs/actual-input-01.json'] == actual_input_raw
         and (len(restored['sources/held_agent_campaign_02.py']), sha(restored['sources/held_agent_campaign_02.py'])) == HOLDER_PIN
         and sha(restored['tools/collect_mac_companion_01.py']) == tool_pins['collector_sha256']
         and sha(restored['tools/verify_mac_companion_01.py']) == tool_pins['consumer_sha256'],
         'archived input, holder or tool bytes differ from external pins')
    fixed = {'sources/held_agent_campaign_02.py', 'tools/collect_mac_companion_01.py',
             'tools/verify_mac_companion_01.py', 'inputs/actual-input-01.json'}
    for kind in kinds:
        plan, prepared = PLANS[kind], manifest['prepared_sources'][kind]
        need(isinstance(prepared, dict) and set(prepared) == {'captured', 'path', 'bytes', 'sha256'}
             and type(prepared['captured']) is bool
             and prepared['path'] == plan['script'] and prepared['bytes'] == plan['script_bytes']
             and prepared['sha256'] == plan['script_sha256']
             and (not declarations[kind]['executed'] or prepared['captured']),
             'staged source declaration differs')
        if prepared['captured']:
            name = 'sources/' + kind + '-campaign.py'
            fixed.add(name)
            need((len(restored[name]), sha(restored[name])) == (plan['script_bytes'], plan['script_sha256']),
                 'prepared parent source byte identity differs')
        if declarations[kind]['executed']:
            fixed.update('native/' + kind + '-' + suffix + '.json' for suffix in ('terminal', 'read'))
            fixed.update('native-decoded/' + kind + '.' + stream for stream in ('stdout', 'stderr'))
            fixed.update('holders/' + kind + '/' + name for name in FIXED_HOLDER_FILES)
    need(set(restored) == fixed | {'_export-manifest.json'},
         'unselected, unknown or missing original evidence in group archive')
    records = {row['path']: row for row in manifest['files']}
    owner = original_paths(manifest['files'], group)
    verify_locks(manifest['input_lock_metadata'], declarations, owner)
    verified = {}
    for kind in selected:
        declaration = declarations[kind]
        prefix = 'holders/' + kind + '/'
        files = {name[len(prefix):]: raw for name, raw in restored.items() if name.startswith(prefix)}
        need(manifest['source_inventories'][kind] == sorted(FIXED_HOLDER_FILES),
             'complete original directory inventory differs')
        for suffix, key in (('terminal', 'terminal_sha256'), ('read', 'read_sha256')):
            need(sha(restored['native/' + kind + '-' + suffix + '.json']) == declaration[key],
                 'original native raw byte pin differs')
        status, streams = native_proof(restored['native/' + kind + '-terminal.json'],
                                      restored['native/' + kind + '-read.json'], jobs[kind])
        for name, body in streams.items():
            need(restored['native-decoded/' + kind + '.' + name] == body,
                 'decoded native stream differs from original bytes_hex')
        need(files['remote-script.py'] == restored['sources/' + kind + '-campaign.py'],
             'holder stdin copy differs from staged source')
        proof = verify_holder(kind, files, declaration, status, streams)
        need(manifest['campaigns'][kind] == proof,
             'manifest outcome or cleanup witness differs from complete original bytes')
        verified[kind] = proof
    return verified, owner, records


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(read(path, max(MAX_FILE, len(raw))) == raw, 'written verification output differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    for name in ('receipt-sha256', 'receipt-version', 'collector-sha256', 'consumer-sha256',
                 'input-sha256', 'capture-job-id'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    need(all(isinstance(value, str) and HEX.fullmatch(value)
             for name, value in vars(args).items() if name.endswith('_sha256'))
         and VERSION.fullmatch(args.receipt_version) and JOB.fullmatch(args.capture_job_id),
         'invalid actual external identity pin')
    root = args.root.absolute()
    need(root.resolve(strict=True) == root and root.is_dir(), 'canonical received evidence directory required')
    destination = root / 'verified-01'
    need(not os.path.lexists(destination), 'fresh independent verification output required')
    local_inputs = {}

    def checked(path, limit=MAX_FILE):
        body = read(path, limit)
        need(path not in local_inputs or local_inputs[path] == body, 'local input changed between reads')
        local_inputs[path] = body
        return body

    self_raw = checked(Path(__file__).resolve())
    need(sha(self_raw) == args.consumer_sha256, 'local consumer differs from reviewed source')
    receipt_raw = checked(root / 'receipt.json', 65536)
    need(sha(receipt_raw) == args.receipt_sha256
         and int(args.receipt_version.split(':')[2]) == len(receipt_raw), 'original collector receipt identity differs')
    receipt = parse(receipt_raw)
    pins = {'holder': list(HOLDER_PIN), 'collector_sha256': args.collector_sha256,
            'consumer_sha256': args.consumer_sha256}
    need(receipt.get('schema') == 'hepta-r26-mac-companion-receipt/v1'
         and receipt.get('attempt') == '01' and set(receipt.get('groups', {})) == set(GROUPS)
         and all(receipt.get(key) is True for key in ('passed', 'capture_complete', 'source_inputs_unchanged'))
         and all(receipt.get(key) is False for key in ('runtime_adoption_assessed', 'hosted_actions_passed', 'x230_report_bytes_read'))
         and type(receipt.get('automatic_retries')) is int and receipt['automatic_retries'] == 0
         and receipt.get('source_script_pins') == pins and 'error' not in receipt,
         'collector receipt is not a complete capture-only result')
    finished = datetime.datetime.fromisoformat(receipt['finished_utc'])
    need(finished.tzinfo is not None, 'collector receipt lacks a timezone')
    input_owner = source_identity(receipt['input'], NATIVE_INPUTS + '/actual-input-01.json')
    need(receipt['input']['sha256'] == args.input_sha256, 'collector actual input pin differs')
    text_files, versions = {'receipt.json': receipt_raw}, {'receipt.json': args.receipt_version}
    archives, verified, captured_sources, owners = {}, {}, {}, set()
    actual_input_raw, declarations, jobs, common_locks = None, None, None, None
    for group in GROUPS:
        item = receipt['groups'][group]
        metadata = {}
        for key, basename in (('manifest', 'manifest.json'), ('chunks_manifest', 'chunks-manifest.json')):
            name = group + '/' + basename
            body = checked(root / name, 65536)
            row = item[key]
            need(source_identity(row, REMOTE + '/' + name) == input_owner
                 and row['bytes'] == len(body) and row['sha256'] == sha(body), 'group metadata receipt binding differs')
            text_files[name], versions[name], metadata[key] = body, row['version'], parse(body)
        manifest, chunks = metadata['manifest'], metadata['chunks_manifest']
        need(chunks.get('schema') == 'hepta-r26-mac-companion-text-chunks/v1'
             and chunks.get('group') == group and chunks.get('chunk_bytes') == 48000
             and 1 <= len(chunks['chunks']) <= 128 and chunks['archive'] == item['archive']
             and chunks.get('read_multiple_files') == {'host': 'main', 'paths_per_rpc_max': 4,
                 'max_file_bytes': 65536, 'max_response_bytes': 262144}, 'chunk manifest contract differs')
        pieces, offset, chunk_names = [], 0, set()
        for index, row in enumerate(chunks['chunks']):
            name = group + f'/chunks/chunk-{index:04d}.b64'
            need(row['path'] == name and type(row['offset']) is int and row['offset'] == offset
                 and type(row['bytes']) is int and 0 < row['bytes'] <= 48000
                 and (index == len(chunks['chunks']) - 1 or row['bytes'] == 48000),
                 'chunk sequence or boundary differs')
            body = checked(root / name, 64000)
            decoded = base64.b64decode(body, validate=True)
            need(base64.b64encode(decoded) == body and len(decoded) == row['bytes']
                 and sha(decoded) == row['sha256'] and len(body) == row['text_bytes']
                 and sha(body) == row['text_sha256'] and VERSION.fullmatch(row['version'])
                 and int(row['version'].split(':')[2]) == len(body), 'chunk bytes or version differ')
            text_files[name], versions[name] = body, row['version']
            pieces.append(decoded)
            offset += len(decoded)
            chunk_names.add(Path(name).name)
        need({path.name for path in (root / group / 'chunks').iterdir()} == chunk_names,
             'unlisted received chunk or sidecar')
        raw = b''.join(pieces)
        archive_pin = item['archive']
        need(source_identity(archive_pin, REMOTE + '/' + group + '/' + ARCHIVE_NAMES[group]) == input_owner
             and offset == archive_pin['bytes'] and sha(raw) == archive_pin['sha256'],
             'complete reconstructed archive differs')
        restored, gzip_proof = restore_archive(raw, text_files[group + '/manifest.json'], manifest['files'])
        need(type(item['payload_files']) is int and item['payload_files'] == len(manifest['files'])
             and type(item['archive_members']) is int and item['archive_members'] == len(restored)
             and type(item['source_bytes']) is int and item['source_bytes'] == sum(row['bytes'] for row in manifest['files']),
             'complete archive accounting differs')
        current_input = restored['inputs/actual-input-01.json']
        need(len(current_input) == receipt['input']['bytes'] and sha(current_input) == args.input_sha256
             and (actual_input_raw is None or actual_input_raw == current_input),
             'two archive groups do not retain the same exact actual input')
        actual_input_raw = current_input
        declarations, jobs = validate_input(parse(actual_input_raw))
        group_proofs, owner, records = verify_group(restored, manifest, group, actual_input_raw, pins)
        selected = [kind for kind in GROUPS[group] if declarations[kind]['executed']]
        need(item['campaign_names'] == selected, 'receipt group selection differs')
        need({key: records['inputs/actual-input-01.json'][key] for key in receipt['input']} == receipt['input'],
             'archived actual input descriptor differs from collector receipt')
        owners.add(owner)
        need(common_locks is None or common_locks == manifest['input_lock_metadata'], 'global input lock witnesses differ across groups')
        common_locks = manifest['input_lock_metadata']
        for row in manifest['files']:
            if 'original_path' not in row:
                continue
            identity = {key: value for key, value in row.items() if key != 'path'}
            path = row['original_path']
            need(path not in captured_sources or captured_sources[path] == identity,
                 'same original source has inconsistent witnesses across archives')
            captured_sources[path] = identity
        verified.update(group_proofs)
        archives[group] = {'raw': raw, 'proof': {'archive': archive_pin,
            'manifest_sha256': sha(text_files[group + '/manifest.json']), 'payload_files': item['payload_files'],
            'archive_members': item['archive_members'], 'chunks': len(pieces), 'gzip_integrity': gzip_proof}}
    need(owners == {input_owner} and receipt['original_jobs'] == jobs
         and receipt['original_outcomes'] == verified, 'receipt original jobs or outcomes were changed')
    intervals = sorted((datetime.datetime.fromisoformat(row['started_utc']),
                        datetime.datetime.fromisoformat(row['finished_utc']), kind) for kind, row in verified.items())
    need(all(intervals[index - 1][1] <= intervals[index][0] for index in range(1, len(intervals)))
         and all(end <= finished for _, end, _ in intervals), 'original holder intervals overlap or exceed capture completion')
    operation_paths = sorted((root / 'operations').glob('read-*.json'))
    need(operation_paths and len(operation_paths) <= 512
         and all(re.fullmatch(r'read-[0-9]{4}\.json', path.name) for path in operation_paths),
         'original text transport request/reply envelopes absent or unbounded')
    operation_raw = [checked(path) for path in operation_paths]
    transported = transport(operation_raw, text_files, versions)
    capture_terminal = checked(root / 'capture-native-terminal.json')
    capture_read = checked(root / 'capture-native-read.json')
    capture_status, capture_streams = native_proof(capture_terminal, capture_read, args.capture_job_id, require_success=True)
    capture_lines = [parse(line) for line in capture_streams['stdout'].decode().splitlines() if line.strip()]
    need(capture_streams['stderr'] == b'' and capture_lines == [
        {'phase': 'mac_companion_capture_ready', 'collector_sha256': args.collector_sha256,
         'consumer_sha256': args.consumer_sha256, 'input_sha256': args.input_sha256},
        {'passed': True, 'receipt': REMOTE + '/receipt.json', 'archive_groups': list(GROUPS), 'original_jobs': jobs}],
        'actual collector native ready/final sequence differs')
    for path, body in local_inputs.items():
        need(read(path, max(MAX_FILE, len(body))) == body, 'local original input changed across independent verification')
    os.umask(0o077)
    destination.mkdir(mode=0o700)
    for group, row in archives.items():
        write_new(destination / ARCHIVE_NAMES[group], row['raw'])
    result = {'schema': 'hepta-r26-mac-companion-independent-verification/v1', 'passed': True,
        'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'capture_job_id': args.capture_job_id, 'capture_native_state': capture_status['state'],
        'capture_terminal_sha256': sha(capture_terminal), 'capture_read_sha256': sha(capture_read),
        'capture_stdout_bytes': len(capture_streams['stdout']), 'capture_stderr_bytes': len(capture_streams['stderr']),
        'receipt_sha256': args.receipt_sha256, 'receipt_version': args.receipt_version,
        'actual_input_sha256': args.input_sha256, 'declarations': declarations,
        'source_script_pins': pins, 'groups': {key: value['proof'] for key, value in archives.items()},
        'original_outcomes': verified, 'transported_files': transported,
        'original_negative_outcomes_preserved': True, 'capture_success_is_not_workload_success': True,
        'runtime_adoption_assessed': False, 'hosted_actions_passed': False, 'remote_operations': 0,
        'archived_code_executed': False, 'archives_extracted': False, 'current_mac_cleanup_probed': False,
        'cleanup_scope': 'Original source-bound holder closure plus collector original Mac metadata witness; no local live-host probe',
        'x230_report_bytes_read': False, 'cross_package_report_binding_required': True}
    audit_path = destination / 'independent-verification-01.json'
    write_new(audit_path, (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'passed': True, 'audit': str(audit_path), 'audit_sha256': sha(read(audit_path)),
                      'archive_groups': list(GROUPS), 'original_negative_outcomes_preserved': True,
                      'runtime_adoption_assessed': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'error_type': type(error).__name__, 'reason': str(error),
                          'remote_operations': 0, 'archived_code_executed': False}), flush=True)
        raise SystemExit(1)
