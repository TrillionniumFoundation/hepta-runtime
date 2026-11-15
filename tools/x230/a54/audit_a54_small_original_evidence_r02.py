#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline full original-byte audit of the fixed actual A54 small comparison.

The archive pin must come from the operator's completed, exit-zero pack job.
This program never executes a runtime, producer, benchmark, shell or SSH. It
loads only the separately SHA-pinned numeric evaluator definitions and its
already reviewed fixed qualification validator, then independently validates
every original request/reply and every authoritative fixture record.
"""
import argparse
import base64
from collections import Counter
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

BASE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
REMOTE = BASE / 'a54-small-archive-comparison-r01'
ANALYSIS = BASE / 'a54-small-archive-analysis-r01.json'
REPORT_SHA = '9cc15059cc1fc61fcb22a46becd6ad3868229137e9f5f48c68a2d199bfaf7ba0'
ANALYSIS_SHA = '7d29e78fc6dbd78854fe3c5e5120475b0663865f15244459cafc1b0797a78afa'
PROTOCOL_SHA = '02183d4edd86e01d309c2c2fc12b02e12c05662600a69d2220bef423d5477378'
EVALUATOR_SHA = '66da10fc85b1df7bb0fcc7b8a5a22d2bdc42d7c5a06b5dae870481f5c451c7cb'
PACKER_SHA = 'd36d16f1f9a866c77048f2fca8568e7934f8fa03efb2de54f031bbe260dca347'
BLOCKS = ('block-0-r07-A54', 'block-1-A54-r07')
ORDER = ('A', 'B', 'B', 'A')
TOOLS = ('usage_stats', 'request_history', 'request_archive')
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_GZIP = 128 * 1024 * 1024
MAX_RAW = 256 * 1024 * 1024
MAX_LINE = 48 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def canonical(value):
    return compact(value) + b'\n'


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(right, dict):
        return left.keys() == right.keys() and all(exact(left[key], value) for key, value in right.items())
    if isinstance(right, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def document(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def finite_float(text):
        number = float(text)
        need(math.isfinite(number), 'nonfinite JSON number')
        return number
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float,
                      parse_constant=lambda text: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(path):
    need(type(path) is str and '\\' not in path, 'bad original path')
    current = PurePosixPath(path)
    need(current.is_absolute() and str(current) == path and '..' not in current.parts
         and current.is_relative_to(BASE) and current != BASE, 'noncanonical or outside fixed BASE path')
    return current.relative_to(BASE)


def local_stat(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def full_local_hash(path, maximum):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct absolute local input required')
    with path.open('rb') as stream:
        initial = os.fstat(stream.fileno())
        need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= maximum,
             'bounded regular single-link local input required')
        sha, size = hashlib.sha256(), 0
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(raw)
            need(size <= maximum, 'local input exceeded bound')
            sha.update(raw)
        need(size == initial.st_size and local_stat(initial) == local_stat(os.fstat(stream.fileno())) == local_stat(path.lstat()), 'local input changed while hashing')
    return {'path': str(path), 'bytes': size, 'sha256': sha.hexdigest(), 'identity': list(local_stat(initial))}


def receipt_check(receipt, path, raw):
    need(type(receipt) is dict and set(receipt) == {'path', 'bytes', 'sha256', 'identity'}
         and receipt['path'] == path and type(receipt['bytes']) is int and receipt['bytes'] == len(raw)
         and receipt['sha256'] == digest(raw), 'captured original byte receipt differs')
    values = receipt['identity']
    need(type(values) is list and len(values) == 9 and all(type(item) is int for item in values)
         and stat.S_ISREG(values[2]) and values[5] == 1 and values[6] == len(raw),
         'captured original full stat9 is not a single-link regular file')


def projection(receipt):
    return {key: receipt[key] for key in ('bytes', 'sha256')} | {
        'identity': receipt['identity'][:4] + receipt['identity'][5:]}


class Capture:
    def __init__(self, root):
        self.root = root
        self.receipts = {}
        self.categories = {}
        self.raw_bytes = 0

    def path(self, remote):
        return self.root / relative(str(remote))

    def raw(self, remote):
        path = str(remote)
        need(path in self.receipts, 'required original member missing: ' + path)
        value = self.path(path).read_bytes()
        need(len(value) == self.receipts[path]['bytes'] and digest(value) == self.receipts[path]['sha256'], 'extracted original changed')
        return value

    def doc(self, remote):
        return document(self.raw(remote))

    def import_stream(self, archive):
        total, header, footer, count = 0, None, None, 0
        with gzip.open(archive, 'rb') as stream:
            while True:
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                total += len(line)
                need(len(line) <= MAX_LINE and total <= MAX_EXPANDED and line.endswith(b'\n'), 'bounded complete evidence line required')
                row = document(line)
                need(type(row) is dict and footer is None, 'data after terminal footer or invalid row')
                if header is None:
                    need(row.get('type') == 'header' and row['schema'] == 'hepta-a54-small-original-evidence-jsonl/v1', 'fixed capture header required')
                    header = row
                    need(row['base'] == str(BASE) and row['experiment'] == str(REMOTE)
                         and row['report_sha256'] == REPORT_SHA and row['analysis_sha256'] == ANALYSIS_SHA
                         and row['protocol_sha256'] == PROTOCOL_SHA and row['member_count'] == 2023,
                         'actual small capture binding differs')
                    need(row['limits'] == {'max_file_bytes': MAX_FILE, 'max_total_raw_bytes': MAX_RAW, 'max_gzip_bytes': MAX_GZIP}, 'fixed capture limits differ')
                    need(type(row['specifications']) is dict and len(row['specifications']) == 2023, 'all specifications required')
                    for path in row['specifications']:
                        relative(path)
                elif row.get('type') == 'file':
                    path = row['path']
                    relative(path)
                    need(path in header['specifications'] and path not in self.receipts and count < 2023, 'extra or duplicate original member')
                    spec = header['specifications'][path]
                    need(row['category'] == spec['category'] and type(row['data_base64']) is str, 'member category/body differs')
                    raw = base64.b64decode(row['data_base64'], validate=True)
                    self.raw_bytes += len(raw)
                    need(len(raw) <= MAX_FILE and self.raw_bytes <= MAX_RAW, 'decoded original byte bound exceeded')
                    receipt_check(row['receipt'], path, raw)
                    need(all(row['receipt'][key] == value for key, value in spec['expected'].items()), 'original expected receipt mismatch')
                    target = self.path(path)
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    need(target.parent.resolve(strict=True) == target.parent, 'local extraction parent is indirect')
                    with target.open('xb') as output:
                        output.write(raw)
                    self.receipts[path] = row['receipt']
                    self.categories[path] = row['category']
                    count += 1
                else:
                    need(row.get('type') == 'footer' and row.get('capture_complete') is True, 'unique complete capture footer required')
                    footer = row
        need(header is not None and footer is not None and count == len(self.receipts) == 2023
             and set(self.receipts) == set(header['specifications']), 'incomplete fixed capture')
        need(footer['member_count'] == count and footer['total_raw_bytes'] == self.raw_bytes
             and footer['receipts_compact_sha256'] == digest(compact(self.receipts))
             and footer['all_full_byte_receipts_rechecked'] is True and footer['originals_modified'] is False
             and footer['business_or_child_executions'] == footer['ssh_or_signals'] == 0
             and footer['source_bodies_captured'] == 340 and footer['release_elf_bodies_captured'] == 2,
             'complete final capture fence differs')
        return header, footer


def verify_inventory(value, root, expected, receipts):
    need(type(value) is dict and '.' in value and len(value) <= 8192, 'complete directory inventory required')
    files, children = set(), set()
    for name, row in value.items():
        parent = PurePosixPath(name)
        need(name == '.' or (not parent.is_absolute() and '..' not in parent.parts and str(parent) == name), 'directory inventory traversal')
        need(len(row['identity']) == 9 and stat.S_ISDIR(row['identity'][2]), 'directory stat9 required')
        seen = set()
        for entry in row['entries']:
            part = entry['name']
            need(type(part) is str and PurePosixPath(part).name == part and part not in ('', '.', '..') and part not in seen, 'duplicate or invalid directory child')
            seen.add(part)
            full = str(parent / part)
            mode = entry['identity'][2]
            if entry['kind'] == 'directory':
                need(stat.S_ISDIR(mode) and full in value and value[full]['identity'] == entry['identity'], 'directory linkage differs')
                children.add(full)
            else:
                need(entry['kind'] == 'file' and stat.S_ISREG(mode) and full in expected, 'extra original directory member')
                need(receipts[str(root / full)]['identity'] == entry['identity'], 'directory member identity differs')
                files.add(full)
    need(files == set(expected) and children == set(value) - {'.'}, 'complete directory tree inventory differs')


def verify_members(capture, header, footer):
    report, analysis = capture.doc(REMOTE / 'report.json'), capture.doc(ANALYSIS)
    need(capture.receipts[str(REMOTE / 'report.json')]['sha256'] == REPORT_SHA
         and capture.receipts[str(ANALYSIS)]['sha256'] == ANALYSIS_SHA, 'actual original report/evaluation required')
    expected = {}

    def add(path, row):
        path = str(path)
        relative(path)
        need(path in capture.receipts, 'missing derived fixed member')
        receipt = capture.receipts[path]
        need(all(receipt[key] == row[key] for key in ('path', 'bytes', 'sha256', 'identity') if key in row), 'derived original receipt differs: ' + path)
        expected[path] = row

    need(len(analysis['input_receipts']) == 21, '21 fixed numeric inputs required')
    for row in analysis['input_receipts']:
        need(PurePosixPath(row['path']).is_relative_to(REMOTE), 'numeric original outside experiment')
        add(row['path'], row)
    add(ANALYSIS, {'bytes': 22087, 'sha256': ANALYSIS_SHA})
    need(len(report['stages']) == 2, 'two original blocks required')
    need(footer['block_directory_before'] == footer['block_directory_after']
         and set(footer['block_directory_before']) == set(BLOCKS), 'two fixed block directory fences differ')
    for index, stage in enumerate(report['stages']):
        name = BLOCKS[index]
        need(stage['name'] == name and stage['output'] == str(REMOTE / name)
             and stage['original_artifact_count'] == 827, 'fixed block differs')
        manifest_path = REMOTE / (name + '.artifacts.json')
        need(stage['original_artifacts_manifest']['path'] == str(manifest_path), 'original manifest location differs')
        add(manifest_path, stage['original_artifacts_manifest'])
        members = capture.doc(manifest_path)
        need(type(members) is dict and len(members) == 827, 'all 827 original artifact records required')
        for member, row in members.items():
            path = REMOTE / name / member
            need(row['path'] == str(path), 'artifact manifest member path differs')
            add(path, row)
        for kind in ('stdout', 'stderr'):
            path = REMOTE / (name + '.' + kind)
            need(stage[kind]['path'] == str(path), 'fixed block log path differs')
            add(path, stage[kind])
        verify_inventory(footer['block_directory_before'][name], REMOTE / name, members, capture.receipts)
    need(len(expected) == 1678, 'all 1678 original experiment members required')
    for key, name in [('driver', 'native-driver.original.py'), ('helper', 'small-helper.original.py'), ('confirmation_driver', 'confirmation-driver.original.py')]:
        add(REMOTE / name, {field: report[key][field] for field in ('bytes', 'sha256')})
    protocol = capture.doc(REMOTE / 'protocol.original.json')
    need(capture.receipts[str(REMOTE / 'protocol.original.json')]['sha256'] == PROTOCOL_SHA, 'actual frozen protocol bytes required')
    need(footer['source_directory_before'] == footer['source_directory_after']
         and set(footer['source_directory_before']) == {'r07', 'A54'}, 'both qualified source directory fences differ')
    source_rows = {}
    for arm, count in [('r07', 165), ('A54', 175)]:
        bundle = report['qualifications'][arm]
        need(bundle['source_files'] == len(bundle['source_map']) == count
             and bundle['source_map'] == report['final_source_maps'][arm]
             and digest(compact(bundle['source_map'])) == protocol['bindings'][arm]['source_map_compact_sha256']
             and header['source_map_compact_sha256'][arm] == protocol['bindings'][arm]['source_map_compact_sha256'], 'complete qualified source map differs')
        for name, sha in bundle['source_map'].items():
            path = PurePosixPath(bundle['source']) / name
            add(path, {'sha256': sha})
        add(bundle['binary']['path'], bundle['binary'])
        need(bundle['binary']['sha256'] == protocol['bindings'][arm]['release_sha256'] == header['release_sha256'][arm], 'actual qualified ELF binding differs')
        need(capture.raw(bundle['binary']['path'])[:4] == b'\x7fELF', 'qualified release is not an ELF body')
        verify_inventory(footer['source_directory_before'][arm], PurePosixPath(bundle['source']), bundle['source_map'], capture.receipts)
        source_rows[arm] = {'source_files': count, 'source_map_compact_sha256': digest(compact(bundle['source_map'])),
                            'release': capture.receipts[bundle['binary']['path']]}
    need(len(expected) == 2023 and set(expected) == set(capture.receipts), 'missing/extra original source/ELF body')
    return report, analysis, protocol, source_rows


def metadata_oracle(tool, dto, records, page):
    for key, expected in [('ownership_scope', 'native_mcp_session_only'), ('session_scope', 'native_mcp_session_only'),
                          ('authenticated_chatgpt_caller_isolation', False), ('credential_metadata_resume', False), ('cross_session_resume', False)]:
        need(type(dto.get(key)) is type(expected) and dto[key] == expected, 'public owner scope differs')
    if tool == 'usage_stats':
        need(dto.get('schema') == 'hepta-private-usage-v1', 'usage schema differs')
        for key, value in [('total_requests', 64), ('completed', 64), ('failed', 0), ('unknown', 0), ('active', 0)]:
            need(type(dto.get(key)) is int and dto[key] == value, 'complete original usage counter differs')
        need(exact(dto.get('tool_counts'), {'host_list': 64})
             and exact(dto.get('first_accepted_unix_ms'), records[0]['accepted_unix_ms'])
             and exact(dto.get('last_accepted_unix_ms'), records[-1]['accepted_unix_ms'])
             and dto.get('contains_parameters_or_output') is False
             and dto.get('scope') == 'same_verified_credential_or_native_session', 'usage projection differs from originals')
    else:
        need(exact(dto.get('requests'), records[page * 32:(page + 1) * 32])
             and exact(dto.get('next_after_id'), records[31]['request_id'] if page == 0 else None)
             and dto.get('history_is_live') is True and dto.get('automatic_operation_retry') is False,
             'full original metadata page/cursor differs')
        if tool == 'request_archive':
            need(type(dto.get('total')) is int and dto['total'] == 64
                 and dto.get('archive_retention') == 'no_automatic_metadata_eviction'
                 and dto.get('contains_parameters_or_output') is False, 'archive retention/total differs')
        else:
            need(exact(dto.get('retention'), {'global': 512, 'per_owner': 128}), 'history retention differs')


def fixture(capture, directory):
    state = directory / 'state'
    config = capture.doc(directory / 'runtime.json')
    expected_config = {'state_dir': str(state), 'controller_workspace_roots': [], 'hosts': {'fixture': {
        'ssh_target': 'unused.invalid', 'platform': 'linux', 'execution_mode': 'isolated',
        'remote_state_dir': str(state / 'unused'), 'allow_execute': False, 'allow_pty': False,
        'allow_write': False, 'allow_job_network': False, 'privileged_actions': {}}}}
    need(exact(config, expected_config), 'closed no-effect native fixture configuration differs')
    maps, logical = {'hot': {}, 'archive': {}}, {'hot': {}, 'archive': {}}
    for path, receipt in capture.receipts.items():
        original = PurePosixPath(path)
        if not original.is_relative_to(state):
            continue
        parts = original.relative_to(state).parts
        if parts[0] not in ('request-audit', 'request-archive-v11', 'request-archive-v12'):
            continue
        need(len(parts) in (2, 3) and (len(parts) == 2 or re.fullmatch(r'[0-9a-f]{2}', parts[1])), 'unexpected authoritative store layout')
        need(re.fullmatch(r'[0-9a-f]{64}\.json', parts[-1]) and receipt['bytes'] <= 2048, 'unexpected/staging authoritative original')
        record = capture.doc(path)
        key = parts[-1][:-5]
        group = 'hot' if parts[0] == 'request-audit' else 'archive'
        need(set(record) == {'request_id', 'owner', 'tool_name', 'state', 'accepted_unix_ms', 'elapsed_ms'}
             and record['request_id'] == key and key not in logical[group]
             and type(record['owner']) is str and HEX.fullmatch(record['owner'])
             and record['tool_name'] == 'host_list' and record['state'] == 'completed'
             and type(record['accepted_unix_ms']) is int and type(record['elapsed_ms']) is int
             and record['elapsed_ms'] >= 0, 'authoritative original record schema/identity differs')
        logical[group][key] = record
        maps[group][str(original.relative_to(state))] = projection(receipt)
    need(len(logical['hot']) == len(logical['archive']) == 64 and logical['hot'] == logical['archive'], 'complete 64 hot/archive originals differ')
    need(len({row['owner'] for row in logical['hot'].values()}) == 1, 'fixture has mixed native owners')
    records = [{key: value for key, value in row.items() if key != 'owner'} for row in sorted(logical['archive'].values(), key=lambda row: (row['accepted_unix_ms'], row['request_id']))]
    expected = {'logical_records': 64, 'hot_files': 64, 'archive_files': 64, 'files': maps,
                'file_map_sha256': digest(canonical(maps)), 'public_record_projection_sha256': digest(canonical(records))}
    for name in ('originals-after-seed.json', 'originals-before-measured.json', 'originals-after-measured.json', 'originals-after-shutdown.json'):
        need(exact(capture.doc(directory / name), expected), 'four-time original fixture snapshot disagrees with current full bytes')
    need(capture.raw(directory / 'expected-public-records.json') == canonical(records), 'saved full public projection differs')
    return records, set(logical['hot']), next(iter(logical['hot'].values()))['owner'], expected


def schedule(count):
    pages = {'request_history': 0, 'request_archive': 0}
    for index in range(count):
        tool = TOOLS[index % 3]
        page = None
        if tool != 'usage_stats':
            page = pages[tool] % 2
            pages[tool] += 1
        yield index, tool, page


def wire_lines(raw):
    need(raw.endswith(b'\n'), 'incomplete original wire framing')
    answer, offset = [], 0
    for line in raw.splitlines(keepends=True):
        need(line.endswith(b'\n') and len(line) <= 1024 * 1024, 'wire message exceeded original bound')
        answer.append((offset, line, document(line)))
        offset += len(line)
    need(offset == len(raw), 'unaccounted wire bytes')
    return answer


def verify_round(capture, block, round_row, expected_binary, records_seen, owners_seen, pids_seen):
    index, arm = round_row['round'], round_row['arm']
    directory = REMOTE / block / ('round-%d-%s' % (index, arm))
    records, original_ids, owner, fixture_summary = fixture(capture, directory)
    need(records_seen.isdisjoint(original_ids) and owner not in owners_seen, 'native seeds/owner reused between fresh controllers')
    records_seen.update(original_ids)
    owners_seen.add(owner)
    need(projection(capture.receipts[str(directory / 'runtime.json')]) == round_row['config'], 'original config receipt differs')
    controller = directory / 'controller'
    shutdown, startup = round_row['shutdown'], round_row['startup']
    for name in ('requests.jsonl', 'responses.jsonl', 'stderr.log'):
        need(projection(capture.receipts[str(controller / name)]) == shutdown['files'][name], 'original controller wire receipt differs')
    pid = startup['pid']
    need(type(pid) is int and pid > 1 and pid not in pids_seen, 'distinct original controller PID required')
    pids_seen.add(pid)
    need(shutdown['method'] == 'stdin_eof' and shutdown['original_child_reaped'] is True
         and shutdown['waited']['pid'] == pid and shutdown['waited']['exit_code'] == 0
         and shutdown['errors'] == [] and shutdown['reader_error'] is None and shutdown['unmatched'] == [], 'original controller normal wait4/reader completion differs')
    for name in ('process_before_measured', 'process_after_measured'):
        need(round_row[name]['pid'] == pid and round_row[name]['birth_ticks'] == startup['birth_ticks'], 'original measured process generation differs')
    need(startup['argv'] == [expected_binary, 'mcp', '--runtime-config', str(directory / 'runtime.json'), '--runtime-audit-group-commit'], 'native controller command or qualified ELF changed')
    requests = wire_lines(capture.raw(controller / 'requests.jsonl'))
    responses = wire_lines(capture.raw(controller / 'responses.jsonl'))
    need(len(requests) == 1108, 'complete native initialize/notification/1106 calls required')
    init_packet = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
        'protocolVersion': '2025-03-26', 'capabilities': {},
        'clientInfo': {'name': 'hepta-x230-small-archive-abba', 'version': '1'}}}
    need(requests[0][1] == canonical(init_packet) and requests[1][1] == canonical({'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}}), 'exact native initialization wire differs')
    reply_by_id, response_ids, notifications = {}, [], []
    for offset, line, reply in responses:
        need(type(reply) is dict and reply.get('jsonrpc') == '2.0', 'invalid original response envelope')
        if 'id' not in reply:
            need(type(reply.get('method')) is str and 'result' not in reply and 'error' not in reply, 'invalid server notification')
            notifications.append({'offset': offset, 'bytes': len(line), 'sha256': digest(line), 'method': reply['method']})
            continue
        key = reply['id']
        need(type(key) is int and key not in reply_by_id, 'duplicate or invalid original response ID')
        reply_by_id[key] = (offset, line, reply)
        response_ids.append(key)
    need(response_ids == list(range(1, 1108)), 'all original C1 replies must be complete, unique and in request order')
    init_reply = reply_by_id[1][2]
    need('error' not in init_reply and init_reply['result']['serverInfo'] == startup['server_info']
         and init_reply['result']['protocolVersion'] == startup['protocol_version'], 'native original initialization reply differs')
    rows = (round_row['seeds'] + round_row['validation'][:5] + round_row['warmup']
            + round_row['measured'] + round_row['validation'][5:])
    specs = [('seed', i, 'host_list', None) for i in range(64)]
    validations = list(enumerate([('usage_stats', None), ('request_history', 0), ('request_history', 1), ('request_archive', 0), ('request_archive', 1)]))
    specs += [('preflight', i, tool, page) for i, (tool, page) in validations]
    specs += [('warmup', i, tool, page) for i, tool, page in schedule(8)]
    specs += [('measured', i, tool, page) for i, tool, page in schedule(1024)]
    specs += [('postflight', i, tool, page) for i, (tool, page) in validations]
    need(len(rows) == len(specs) == 1106 and len(round_row['validation']) == 10, 'complete original per-round schedule required')
    seed_ids, last_end = set(), None
    all_rpc_rows = [startup['initialize']] + rows
    for ordinal, row in enumerate(all_rpc_rows):
        rpc_id = ordinal + 1
        request_offset, request_line, request = requests[0 if ordinal == 0 else ordinal + 1]
        response_offset, response_line, reply = reply_by_id[rpc_id]
        need(row['rpc_id'] == rpc_id and row['write_attempts'] == 1 and row['sent'] is True
             and row['response_received'] is True and row['automatic_retry'] is False, 'original RPC delivery/attempt fields differ')
        for prefix, offset, raw in [('request', request_offset, request_line), ('response', response_offset, response_line)]:
            need(row[prefix + '_wire_offset'] == offset and row[prefix + '_wire_bytes'] == len(raw)
                 and row[prefix + '_wire_sha256'] == digest(raw), 'original RPC wire slice differs')
        need(type(row['start_monotonic_ns']) is int and type(row['response_received_monotonic_ns']) is int
             and row['response_received_monotonic_ns'] >= row['start_monotonic_ns'], 'original timing order differs')
        if last_end is not None:
            need(row['start_monotonic_ns'] >= last_end, 'observed native C1 requests overlap')
        last_end = row['response_received_monotonic_ns']
        exact_ms = (last_end - row['start_monotonic_ns']) / 1e6
        need(abs(row['elapsed_ms'] - exact_ms) <= 2 * math.ulp(max(exact_ms, 1.0)), 'latency differs from original complete-line time')
        need('error' not in reply and request['id'] == reply['id'] == rpc_id, 'raw RPC error or mismatched identity')
        if ordinal == 0:
            continue
        purpose, call_index, tool, page = specs[ordinal - 1]
        arguments = {} if page is None else {'limit': 32, **({'after_id': records[31]['request_id']} if page else {})}
        need(row['purpose'] == purpose and row['index'] == call_index and row['tool'] == tool
             and row['arguments'] == arguments and row['round'] == index and row['arm'] == arm
             and row['concurrency'] == 1 and row['okay'] is True, 'fixed original tool/page/purpose schedule differs')
        need(request_line == canonical({'jsonrpc': '2.0', 'id': rpc_id, 'method': 'tools/call', 'params': {'name': tool, 'arguments': arguments}}), 'raw native tool request differs from fixed schedule')
        result = reply.get('result')
        need(type(result) is dict and result.get('isError', False) is False, 'raw native tool result failed')
        texts = [part['text'] for part in result.get('content', []) if part.get('type') == 'text']
        need(len(texts) == 1, 'exactly one original JSON text DTO required')
        dto = document(texts[0])
        need(type(dto) is dict and digest(canonical(dto)) == row['dto_sha256'], 'original DTO digest differs')
        if tool == 'host_list':
            need(exact(dto, {'hosts': [{'name': 'fixture', 'platform': 'linux', 'execution_mode': 'isolated', 'operator_tools': False,
                'allow_execute': False, 'allow_pty': False, 'allow_write': False, 'privileged_actions': []}]}), 'raw seed host fixture differs')
            marker = result.get('_meta', {}).get('io.hepta.runtime/request-v8', {})
            ack = result.get('_meta', {}).get('io.hepta.runtime/retention-v8', {})
            key = marker.get('request_id')
            need(type(key) is str and HEX.fullmatch(key) and key == row['native_request_id'] and key not in seed_ids
                 and marker.get('automatic_retry') is False and marker.get('delivery_proven') is False
                 and ack.get('audit_completion_durable') is True and ack.get('result_state') == 'stored'
                 and ack.get('automatic_retry') is False, 'native seed original identity/durable acknowledgement differs')
            seed_ids.add(key)
        else:
            metadata_oracle(tool, dto, records, page)
    need(seed_ids == original_ids and len(seed_ids) == 64, 'all current authoritative originals must come from the 64 raw native replies')
    need(round_row['complete'] is True and round_row['originals_unchanged'] is True, 'original round incomplete')
    return rows, {'block': block, 'round': index, 'cli_arm': arm, 'pid': pid,
                  'birth_ticks': startup['birth_ticks'], 'native_owner': owner,
                  'requests': len(requests), 'responses_with_id': len(reply_by_id),
                  'tool_calls': len(rows), 'measured': 1024, 'seed_records': 64,
                  'authoritative_files': 128, 'four_snapshots_match_full_bytes': True,
                  'original_wait4': shutdown['waited'], 'server_notifications': notifications,
                  'fixture_file_map_sha256': fixture_summary['file_map_sha256'],
                  'public_projection_sha256': fixture_summary['public_record_projection_sha256']}


def replay_numeric(capture, report, protocol, evaluator):
    receipt = full_local_hash(evaluator, MAX_FILE)
    raw = Path(evaluator).read_bytes()
    need(len(raw) == receipt['bytes'] and digest(raw) == receipt['sha256'] == EVALUATOR_SHA,
         'frozen numeric evaluator execution bytes differ')
    module = types.ModuleType('reviewed_frozen_a54_small_numeric_evaluator')
    module.__file__ = str(evaluator)
    exec(compile(raw, str(evaluator), 'exec'), module.__dict__)
    module.final_bindings()
    inputs = module.Inputs(capture.path(REMOTE))
    inputs.read(capture.path(REMOTE / 'report.json'), {'bytes': 133839, 'sha256': REPORT_SHA})
    inputs.read(capture.path(REMOTE / 'protocol.original.json'), {'bytes': 8542, 'sha256': PROTOCOL_SHA})
    result = {}
    module.evaluate(inputs, report, protocol, result)
    inputs.unchanged()
    return module.printable(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--expected-bytes', type=int, required=True)
    parser.add_argument('--pack-job-id', required=True, help='Operator-observed original pack job, successful exit zero.')
    parser.add_argument('--pack-exit-code', type=int, choices=[0], required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--evaluator', type=Path, default=Path(__file__).resolve().parent / 'frozen-r01/evaluate_small_archive_a54_r01.py')
    args = parser.parse_args()
    need(HEX.fullmatch(args.expected_sha256) and 0 < args.expected_bytes <= MAX_GZIP
         and args.pack_job_id and args.pack_exit_code == 0, 'actual successful operator capture binding required')
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent, 'fresh direct audit output required')
    args.out.mkdir(mode=0o700)
    result = {'schema': 'hepta-a54-small-complete-original-byte-audit/v1', 'passed': False,
              'performance_adoption_authorized': False, 'benchmark_or_runtime_executions': 0,
              'remote_calls': 0, 'errors': [], 'packer_sha256': PACKER_SHA,
              'operator_pack_job_id': args.pack_job_id, 'operator_pack_exit_code': args.pack_exit_code,
              'scope': 'Complete fixed small raw fixture/wire/source/ELF and recorded original process custody audit; does not qualify large, multi-host, CI or overall performance adoption.'}
    try:
        initial = full_local_hash(args.archive, MAX_GZIP)
        need(initial['bytes'] == args.expected_bytes and initial['sha256'] == args.expected_sha256, 'archive differs from actual operator pin')
        capture = Capture(args.out / 'evidence')
        capture.root.mkdir(mode=0o700)
        header, footer = capture.import_stream(args.archive)
        report, original_analysis, protocol, qualified = verify_members(capture, header, footer)
        numeric = replay_numeric(capture, report, protocol, args.evaluator)
        for key in ['actual_outer_state', 'all_stage_observations', 'qualification_chain_verification', 'rounds', 'arms', 'all_purpose_counts', 'measured_calls', 'total_tool_calls', 'gates', 'ratios', 'passed', 'numeric_gates_passed', 'report_evaluation_complete']:
            need(numeric[key] == original_analysis[key], 'frozen numeric replay differs: ' + key)
        seen_ids, seen_owners, pids, all_rows, rounds = set(), set(), set(), [], []
        for block_index, block in enumerate(BLOCKS):
            child = capture.doc(REMOTE / block / 'report.json')
            stage = report['stages'][block_index]
            for arm in ('A', 'B'):
                binary = stage['cli_to_actual'][arm]['binary_path']
                expected_input = projection(capture.receipts[binary])
                need(child['inputs'][arm] == {'path': binary, **expected_input}
                     and child['final_inputs'][arm] == expected_input, 'each actual controller binary original full receipt differs')
            need(child['script'] == projection(report['helper']), 'original producer identity differs from the outer original receipt')
            rows = []
            for index, row in enumerate(child['rounds']):
                need(index < 4 and row['round'] == index and row['arm'] == ORDER[index], 'original ABBA round order differs')
                current_rows, current_summary = verify_round(capture, block, row, child['inputs'][row['arm']]['path'], seen_ids, seen_owners, pids)
                rows.extend(current_rows)
                rounds.append(current_summary)
            journal = capture.raw(REMOTE / block / 'calls.jsonl')
            need(journal.endswith(b'\n') and [document(line) for line in journal.splitlines()] == rows and len(rows) == 4424, 'entire raw journal differs from independently audited wire rows')
            all_rows.extend(rows)
        need(len(rounds) == len(pids) == len(seen_owners) == 8 and len(seen_ids) == 512
             and len(all_rows) == 8848 and Counter(row['purpose'] for row in all_rows) == {'seed': 512, 'preflight': 40, 'warmup': 64, 'measured': 8192, 'postflight': 40}, 'full fixed native workload missing')
        need(full_local_hash(args.archive, MAX_GZIP) == initial, 'original local archive changed during audit')
        result.update(passed=True, archive=initial, captured_members=2023, captured_raw_bytes=capture.raw_bytes,
                      complete_raw_wire_and_fixture_audit=True, qualified_source_bodies_rehashed=True,
                      qualified_release_elf_bodies_rehashed=True, original_custody_records_verified=True,
                      qualifier_and_numeric_replay_complete=True, qualified_inputs=qualified,
                      all_purpose_counts=dict(Counter(row['purpose'] for row in all_rows)),
                      authoritative_record_files=1024, original_snapshot_files=32,
                      original_controllers=rounds, numeric=numeric,
                      receipt_manifest_compact_sha256=footer['receipts_compact_sha256'],
                      limitations=['Original controller wait4 records contain exit code, not a separate raw wait status; no additional field is invented.',
                                   'Two block helper raw waitpid statuses and qualified original worker custody are independently checked by the fixed numeric replay.',
                                   'CPU/latency/RSS interpretation and endpoint-only FD scope remain those of the original fixed protocol.',
                                   'Overall adoption remains false until separate required large, multi-host and CI gates are decided.'])
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    raw = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with (args.out / 'audit.json').open('xb') as output:
        output.write(raw)
    print(json.dumps({'path': str(args.out / 'audit.json'), 'bytes': len(raw), 'sha256': digest(raw), 'passed': result['passed'], 'errors': result['errors']}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
