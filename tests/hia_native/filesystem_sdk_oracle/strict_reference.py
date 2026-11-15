"""Read complete original SDK/filesystem evidence without using its live fixture."""
from pathlib import Path
from collections import Counter
import argparse
import errno
import gzip
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import struct
import sys
sys.dont_write_bytecode = True

SOURCES = {
    'run.py': (13360, '1f69ff1e20e3c9df32723cb85c1f21b3dbe6a52867b8731d22a0606f0f5f813a'),
    'cases.py': (17379, '9bb4cc6f0c0afdc520c27b07224b85194eed9bbf3644f7a2450a8831a2ebd3b8'),
    'oracle/Cargo.toml': (566, 'd77389383acbb28b6bfda9cd0bf6ee433c3fbc493cfc90048393d8e26ccb58fb'),
    'oracle/Cargo.lock': (19713, 'f8230631dd6c8095bcca8e30d388450750171cb08e5c386798444610cbed24e1'),
    'oracle/verify_sources.py': (7488, 'cb3f5e7d1c5e78ab8c3194bb418a27f12274ef9292703323e2c8fa3c7f4049a0'),
    'oracle/src/driver.rs': (28609, '0d72cbc158030baf09dd7ec6fcfe35737f96ad918d4bf57a6eb1e02b81e31d23'),
    'oracle/original/Cargo.lock': (90148, '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'),
    'oracle/original/Cargo.toml': (4157, '377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f'),
    'oracle/original/config.rs': (25272, '228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35'),
    'oracle/original/delta.rs': (9765, 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1'),
    'oracle/original/effect_owner_fence.rs': (23890, '1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207'),
    'oracle/original/mcp_mod.rs': (3316, '9e9b7933372418ef361f85d64a1d36567618b13ae77c45d16df16799231b690c'),
    'oracle/original/parity_ops.rs': (11952, '0e608303d16c22b95dc99bae2e6bb00ba0571872f52d15a7fe8e2f021286ccc1'),
    'oracle/original/remote.rs': (48174, 'd87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c'),
    'oracle/original/request_ctx.rs': (2860, '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943'),
    'oracle/original/server.rs': (178908, 'ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d'),
    'oracle/original/text_editing.rs': (63372, 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590'),
}
TOOL = '/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/'
FENCE = ('HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')
TRACE = 'trace=%file,close,write,getpgid,getdents64,flock,fcntl,dup,dup2,dup3'


def need(value, message):
    if not value: raise ValueError('filesystem SDK reference: '+message)
def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()+b'\n'
def same(actual, expected, message): need(canonical(actual) == canonical(expected), message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def uint(value, message): need(type(value) is int and 0 <= value < 1 << 64, message); return value
def positive(value, message): need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 180, message)
def fields(value, names, message): need(type(value) is dict and set(value) == set(names), message)
def hex_bytes(value, message):
    need(type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', value) is not None, message); return bytes.fromhex(value)


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values: need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    def bad(value): raise ValueError('filesystem SDK reference: nonfinite JSON')
    def number(value):
        parsed = float(value); need(math.isfinite(parsed), 'overflowed JSON float'); return parsed
    try: return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=bad)
    except (UnicodeError, json.JSONDecodeError) as error: raise ValueError('filesystem SDK reference: malformed JSON') from error


def pin(path):
    with Path(path).open('rb') as stream: return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
def inside(root, name):
    root, relative = Path(root).absolute(), Path(name)
    need(not relative.is_absolute() and relative.parts and '..' not in relative.parts, 'artifact path escape')
    for folder in [*reversed(root.parents), root]: need(folder.is_dir() and not folder.is_symlink(), 'artifact root symlink')
    path = root
    for part in relative.parts:
        path /= part; value = path.lstat(); need(not stat.S_ISLNK(value.st_mode), 'artifact symlink')
    need(stat.S_ISREG(value.st_mode) and value.st_uid == root.stat().st_uid, 'artifact type/owner')
    return path


class Binder:
    def __init__(self, root): self.root = Path(root).absolute(); self.artifacts = {}
    def file(self, name, expected=None):
        path = inside(self.root, name); actual = pin(path)
        if expected is not None: same(actual, expected, 'complete artifact pin '+str(name))
        same(actual, self.artifacts.setdefault(str(Path(name)), actual), 'artifact changed during admission'); return path
    def data(self, name, expected=None): return self.file(name, expected).read_bytes()
    def json(self, name, expected=None): return strict_json(self.data(name, expected))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
def gzip_evidence(path, expected):
    digest = hashlib.sha256(); total = 0
    with gzip.open(path, 'rb') as stream:
        while block := stream.read(1024*1024): total += len(block); digest.update(block)
    same({'bytes': total, 'sha256': digest.hexdigest()}, expected, 'complete decompressed stream')


def parse_output(raw):
    need(raw[:8] == b'HFSSO001', 'actual output magic'); at = 8; rows = []
    while at < len(raw):
        begin = at; need(len(raw)-at >= 16, 'short output record header')
        length, count = struct.unpack_from('<2Q', raw, at); at += 16
        need(length <= len(raw)-at, 'short metadata body'); metadata_offset = at
        metadata_raw = raw[at:at+length]; metadata = strict_json(metadata_raw); at += length
        need(type(metadata) is dict and metadata.get('kind') in ('scenario_start', 'case', 'scenario_end'), 'output metadata kind')
        blobs = []
        for _ in range(count):
            need(len(raw)-at >= 8, 'short blob length'); length = struct.unpack_from('<Q', raw, at)[0]; at += 8
            need(length <= len(raw)-at, 'short complete blob'); body = raw[at:at+length]
            blobs.append({'offset': at, 'bytes': length, 'sha256': sha(body)}); at += length
        references = set()
        def check_refs(value):
            if type(value) is list:
                for child in value: check_refs(child)
            elif type(value) is dict:
                for key, child in value.items():
                    if key.endswith('_blob'):
                        if key == 'response_blob' and child is None: continue
                        need(type(child) is int and 0 <= child < count, 'blob reference/index'); references.add(child)
                    else: check_refs(child)
        check_refs(metadata); same(sorted(references), list(range(count)), 'complete blob ownership')
        rows.append({'metadata': metadata, 'metadata_span': {'offset': metadata_offset, 'bytes': len(metadata_raw), 'sha256': sha(metadata_raw)},
                     'blobs': blobs, 'record': {'offset': begin, 'bytes': at-begin, 'sha256': sha(raw[begin:at])}})
    need(at == len(raw), 'output trailing bytes'); return rows


def blob(raw, row, index):
    need(type(index) is int and 0 <= index < len(row['blobs']), 'typed blob index')
    span = row['blobs'][index]; body = raw[span['offset']:span['offset']+span['bytes']]
    need(len(body) == span['bytes'] and sha(body) == span['sha256'], 'complete blob span'); return body


def state(value, root):
    fields(value, ('root_hex', 'current_hex', 'effective_hex', 'poisoned', 'session_applied', 'cache'), 'actual session state fields')
    need(hex_bytes(value['root_hex'], 'session root bytes') == root, 'session root identity')
    current = None if value['current_hex'] is None else hex_bytes(value['current_hex'], 'session current bytes')
    need(hex_bytes(value['effective_hex'], 'effective workdir bytes') == (root if current is None else current), 'effective session workdir')
    need(value['poisoned'] is False and type(value['session_applied']) is bool, 'actual lock/latch types')
    fields(value['cache'], ('poisoned', 'entries'), 'actual cache fields')
    need(value['cache']['poisoned'] is False and type(value['cache']['entries']) is dict, 'actual cache mutex/map')
    need(all(type(k) is str and type(v) is str for k, v in value['cache']['entries'].items()), 'actual complete cache text')


def filesystem(value, expected_roots):
    need(type(value) is list and len(value) == len(expected_roots), 'complete observed filesystem roots')
    for tree, root in zip(value, expected_roots):
        fields(tree, ('root_hex', 'nodes'), 'actual tree snapshot fields'); same(tree['root_hex'], root, 'observed root raw bytes')
        need(type(tree['nodes']) is list and tree['nodes'], 'complete tree nodes'); seen = set(); paths = []
        for row in tree['nodes']:
            need(type(row) is dict, 'filesystem node type'); path = hex_bytes(row.get('relative_hex'), 'relative Unix path')
            need(not path.startswith(b'/') and b'..' not in path.split(b'/') and path not in seen, 'unique contained snapshot node')
            need(not path or os.path.dirname(path) in seen, 'snapshot parent before child'); seen.add(path); paths.append(path)
            if 'errno' in row:
                fields(row, ('relative_hex', 'errno'), 'failed lstat observation'); need(0 < uint(row['errno'], 'lstat errno') < 4096, 'lstat errno range'); continue
            required = {'relative_hex', 'device', 'inode', 'mode', 'uid', 'gid', 'links', 'size', 'mtime', 'ctime'}
            need(required <= set(row), 'complete lstat fields')
            for key in required-{'relative_hex', 'mtime', 'ctime'}: uint(row[key], 'lstat '+key)
            for key in ('mtime', 'ctime'):
                need(type(row[key]) is list and len(row[key]) == 2 and all(type(v) is int for v in row[key]) and 0 <= row[key][1] < 1_000_000_000, 'actual '+key)
            mode = row['mode']
            if stat.S_ISREG(mode):
                need(set(row)-required in ({'content_hex'}, {'read_errno'}), 'complete regular file observation')
                if 'content_hex' in row: need(len(hex_bytes(row['content_hex'], 'full file bytes')) == row['size'], 'complete file content')
                else: need(0 < uint(row['read_errno'], 'read errno') < 4096, 'read errno range')
            elif stat.S_ISLNK(mode):
                need(set(row)-required in ({'target_hex'}, {'readlink_errno'}), 'complete link observation')
                if 'target_hex' in row: need(len(hex_bytes(row['target_hex'], 'raw link target')) == row['size'], 'complete symlink target')
                else: need(0 < uint(row['readlink_errno'], 'readlink errno') < 4096, 'readlink errno range')
            elif stat.S_ISDIR(mode):
                need(set(row)-required in (set(), {'readdir_errno'}), 'complete directory observation')
                if 'readdir_errno' in row: need(0 < uint(row['readdir_errno'], 'readdir errno') < 4096, 'readdir errno range')
            else: need(stat.S_ISFIFO(mode) and set(row) == required, 'declared special fixture node')
        need(paths[0] == b'', 'snapshot root first')
        children = {}
        for path in paths[1:]: children.setdefault(os.path.dirname(path), []).append(path)
        need(all(children[key] == sorted(children[key]) for key in children), 'actual byte-ordered tree enumeration')


def descriptors(value):
    need(type(value) is list and len(value) >= 4, 'actual descriptor snapshot')
    fds = []
    for item in value:
        need(type(item) is list and len(item) == 2, 'descriptor entry'); fds.append(uint(item[0], 'descriptor'))
        hex_bytes(item[1], 'descriptor target bytes')
    need(fds == sorted(set(fds)) and fds[:3] == [0, 1, 2], 'actual descriptor order/stdio')


def process(row, command, cwd, old_capture, fence):
    fields(row, ('name', 'command', 'controlled_env', 'cwd', 'elapsed_seconds', 'exit_code', 'pid', 'stderr', 'stdin', 'stdout', 'timed_out', 'timeout_seconds'), 'complete actual process receipt')
    need(row['timed_out'] is False, 'process timeout'); same(row['command'], command, 'actual command'); same(row['cwd'], str(cwd), 'actual cwd')
    same(row['exit_code'], 0, 'actual process exit'); same(row['timeout_seconds'], 180, 'actual process deadline'); positive(row['elapsed_seconds'], 'actual process elapsed')
    need(uint(row['pid'], 'actual PID') > 0, 'actual process PID')
    env = row['controlled_env']; fields(env, ('RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'PATH', 'LC_ALL', *FENCE), 'complete compiler/fence environment')
    expected = {'RUSTC': TOOL+'rustc', 'CARGO_TARGET_DIR': str(old_capture/'target'), 'CARGO_BUILD_JOBS': '2', 'LC_ALL': 'C', **dict.fromkeys(FENCE), **fence}
    same({k: env[k] for k in expected}, expected, 'actual fixed compiler and fence environment')
    need(type(env['PATH']) is str and env['PATH'].startswith(TOOL.rstrip('/')+':'), 'actual compiler PATH')


def error_data(data, raw, row):
    fields(data, ('ok', 'short_blob', 'chain_blob', 'errno'), 'full original error observation')
    need(data['ok'] is False and (data['errno'] is None or type(data['errno']) is int and 0 < data['errno'] < 4096), 'original error/errno types')
    short, chain = blob(raw, row, data['short_blob']), blob(raw, row, data['chain_blob'])
    short.decode('utf-8'); chain.decode('utf-8'); need(short and chain, 'complete nonempty original errors')
    return short, chain


def exchange(value, message, raw, row):
    need(type(value) is dict, 'actual exchange type')
    kind = value.get('transport'); keys = {'request_blob', 'response_blob', 'response_bytes', 'request_bytes_written', 'transport'}
    fields(value, keys | ({'error', 'error_kind', 'errno'} if kind == 'write-error' else set()), 'complete actual transport outcome')
    request = blob(raw, row, value['request_blob']); need(request.endswith(b'\n'), 'complete request newline')
    # Only the declared duplicate-key wire is intentionally decoded last-wins.
    expected = bytes.fromhex(message['wire_hex']) if 'wire_hex' in message else None
    if expected is not None: need(request == expected, 'complete duplicate-key original request'); actual_request = json.loads(request)
    else: actual_request = strict_json(request); same(actual_request, message['message'], 'complete original request Value')
    written = uint(value['request_bytes_written'], 'actual request bytes written'); need(written <= len(request), 'request write overrun')
    response = b'' if value['response_blob'] is None else blob(raw, row, value['response_blob'])
    same(value['response_bytes'], len(response), 'complete response extent')
    if kind == 'response':
        need(written == len(request) and response.endswith(b'\n'), 'complete delivered request/response')
        reply = strict_json(response); need(type(reply) is dict, 'actual SDK response object')
        same(reply.get('id'), actual_request.get('id'), 'SDK response request id'); same(reply.get('jsonrpc'), '2.0', 'SDK response protocol')
        need(set(reply) in ({'jsonrpc', 'id', 'result'}, {'jsonrpc', 'id', 'error'}), 'actual SDK response fields')
    elif kind == 'notification':
        need(written == len(request) and value['response_blob'] is None and not response and 'id' not in actual_request, 'actual notification outcome'); reply = None
    elif kind == 'write-error':
        need(written < len(request) and value['response_blob'] is None and not response, 'actual incomplete transport write')
        need(type(value['error']) is str and value['error'] and value['error_kind'] in ('BrokenPipe', 'WriteZero'), 'actual write error')
        need(value['errno'] is None or type(value['errno']) is int and 0 < value['errno'] < 4096, 'transport errno'); reply = None
    else:
        need(kind == 'eof' and written == len(request) and not response and value['response_blob'] is not None, 'actual EOF outcome'); reply = None
    return actual_request, reply, response


def event_evidence(meta, step, row, raw, policy_installed):
    events = meta['events']; need(type(events) is list and len(events) >= 2, 'complete step event list')
    kinds = [event.get('kind') for event in events]
    need(kinds[0] == 'step_begin' and kinds[-1] == 'step_end' and kinds.count('step_begin') == kinds.count('step_end') == 1, 'step marker scope')
    same(events[0]['data'], {k: step[k] for k in ('case_id', 'name', 'domain')}, 'step begin identity')
    same(events[-1]['data'], {'case_id': step['case_id']}, 'step end identity')
    root = hex_bytes(meta['state_before']['root_hex'], 'event session root')
    current = meta['state_before']; cache_changes = []; stack = []; pending_cache = None
    pairs = {'local_policy_enter': 'local_policy_exit', 'remote_policy_enter': 'remote_policy_exit',
             'directory_guard_enter': 'directory_guard_exit', 'effect_fence_enter': 'effect_fence_exit',
             'filesystem_helper_enter': 'filesystem_helper_exit', 'handler_enter': 'handler_exit',
             'cache_forget_enter': 'cache_forget_exit', 'cache_forget_subtree_enter': 'cache_forget_subtree_exit'}
    known = {'step_begin', 'step_end', 'outer_call_tool_enter', 'policy_lookup', *pairs, *pairs.values()}
    for event in events:
        fields(event, ('kind', 'marker', 'data', 'state'), 'event fields'); need(event['kind'] in known, 'unrecognized original event')
        need(uint(event['marker'], 'actual marker') > 1_000_000_000, 'marker range'); need(type(event['data']) is dict, 'event data type')
        state(event['state'], root)
        need(event['state']['session_applied'] or not current['session_applied'], 'session latch reverted')
        if meta['state_before']['session_applied']:
            same(event['state']['current_hex'], meta['state_before']['current_hex'], 'latched session changed after first application')
        if event['state']['cache'] != current['cache']:
            need(event['kind'] in ('cache_forget_exit', 'cache_forget_subtree_exit') or
                 step['action']['kind'] == 'cache_seed' and event['kind'] == 'step_end', 'cache changed outside actual invalidation/seed')
            if step['action']['kind'] != 'cache_seed':
                old, new = current['cache']['entries'], event['state']['cache']['entries']
                need(all(k in old and old[k] == v for k, v in new.items()), 'invalidation added/changed cache content')
                cache_changes.append({'marker': event['marker'], 'kind': event['kind'], 'removed': sorted(set(old)-set(new))})
        current = event['state']; kind, data = event['kind'], event['data']
        if kind in pairs: stack.append((kind, pairs[kind]))
        elif kind in pairs.values():
            need(stack and stack[-1][1] == kind, 'original nested event ordering'); stack.pop()
        if kind == 'policy_lookup':
            fields(data, ('installed',), 'policy lookup fields'); same(data['installed'], policy_installed, 'actual installed configuration')
        elif kind in ('local_policy_enter', 'directory_guard_enter', 'cache_forget_enter', 'cache_forget_subtree_enter'):
            fields(data, ('path_blob',), 'raw local path observation'); need(blob(raw, row, data['path_blob']), 'empty resolved path observation')
            if kind.startswith('cache_'):
                need(pending_cache is None, 'overlapping original cache invalidations')
                path = blob(raw, row, data['path_blob']); need(path.startswith(b'/'), 'actual cache invalidation local absolute path')
                pending_cache = (kind, os.path.normpath(path).decode('utf-8', errors='replace'), event['state']['cache']['entries'])
        elif kind == 'remote_policy_enter':
            fields(data, ('alias', 'path', 'user_explicit', 'port_explicit', 'write'), 'remote policy observation')
            need(all(type(data[k]) is str for k in ('alias', 'path')) and all(type(data[k]) is bool for k in ('user_explicit', 'port_explicit', 'write')) and data['write'], 'remote policy types')
        elif kind in ('local_policy_exit', 'remote_policy_exit', 'directory_guard_exit', 'effect_fence_exit'):
            if data.get('ok') is True: fields(data, ('ok',), 'successful original admission')
            else: error_data(data, raw, row)
        elif kind in ('effect_fence_enter', 'cache_forget_exit', 'cache_forget_subtree_exit'):
            fields(data, (), 'unit event data')
            if kind.startswith('cache_'):
                need(pending_cache is not None, 'cache completion without actual entry')
                enter_kind, key, old_entries = pending_cache; pending_cache = None
                expected_entries = {k: v for k, v in old_entries.items() if k != key and
                    not (enter_kind == 'cache_forget_subtree_enter' and k.startswith(key.rstrip('/')+'/'))}
                same(event['state']['cache']['entries'], expected_entries, 'exact cache key/subtree boundary invalidation')
        elif kind == 'filesystem_helper_enter':
            fields(data, ('tool', 'parameters_blob', 'workdir_blob', 'request_context_present'), 'actual helper entry')
            need(data['request_context_present'] is True, 'original task-local scope missing in helper')
            need(blob(raw, row, data['workdir_blob']).hex() == event['state']['effective_hex'], 'helper actual workdir')
            strict_json(blob(raw, row, data['parameters_blob']))
        elif kind == 'filesystem_helper_exit':
            if data.get('ok') is True:
                fields(data, ('ok', 'body_blob', 'body_bytes'), 'helper success body'); same(data['body_bytes'], len(blob(raw, row, data['body_blob'])), 'helper full body extent')
            else: error_data(data, raw, row)
        elif kind == 'handler_enter':
            fields(data, ('tool', 'typed_parameters_blob', 'capabilities', 'protocol_version', 'request_id'), 'typed method entry')
            same(data['request_id'], step['case_id'], 'typed handler request id'); strict_json(blob(raw, row, data['typed_parameters_blob']))
        elif kind == 'handler_exit':
            fields(data, ('ok', 'body_blob', 'body_bytes', 'request_context_present'), 'handler final body')
            need(type(data['ok']) is bool and data['request_context_present'] is False, 'original scope not closed at handler exit')
            same(data['body_bytes'], len(blob(raw, row, data['body_blob'])), 'handler complete body extent')
        elif kind == 'outer_call_tool_enter':
            fields(data, ('tool', 'canonical_arguments_blob', 'canonical_arguments_bytes'), 'actual SDK outer dispatch')
            same(data['canonical_arguments_bytes'], len(blob(raw, row, data['canonical_arguments_blob'])), 'canonical arguments extent')
            need(type(strict_json(blob(raw, row, data['canonical_arguments_blob']))) is dict, 'actual canonical SDK arguments object')
    need(not stack and pending_cache is None, 'unfinished original event scope'); same(events[0]['state'], meta['state_before'], 'step initial actual state')
    same(events[-1]['state'], meta['state_after'], 'step final actual state')
    outer, entered = kinds.count('outer_call_tool_enter'), kinds.count('handler_enter')
    need(outer <= 1 and entered <= outer, 'single actual method invocation')
    same(meta['outer_call_tool_entries'], outer, 'actual outer entry counter'); same(meta['handler_entries'], entered, 'actual typed entry counter')
    helper = kinds.count('filesystem_helper_enter'); need(helper <= entered, 'single helper invocation')
    need(kinds.count('effect_fence_enter') == entered, 'actual effect fence before handler work')
    if entered:
        begin = kinds.index('handler_enter'); need(kinds[begin+1:begin+3] == ['effect_fence_enter', 'effect_fence_exit'], 'fence before latch/policy/helper')
        fence_result = events[begin+2]['data']
        if not fence_result['ok']:
            need(kinds[begin:] == ['handler_enter', 'effect_fence_enter', 'effect_fence_exit', 'handler_exit', 'step_end'], 'fence refusal performed later work')
            same(meta['state_before'], meta['state_after'], 'fence rejection changed session/cache')
        else: need(meta['state_after']['session_applied'] is True, 'accepted fence did not execute original session latch')
    elif step['action']['kind'] == 'public':
        need(kinds in (['step_begin', 'step_end'], ['step_begin', 'outer_call_tool_enter', 'step_end']), 'typed/meta/transport refusal ran handler work')
        same(meta['state_before'], meta['state_after'], 'SDK refusal mutated session/cache')
    invalidations = kinds.count('cache_forget_enter')+kinds.count('cache_forget_subtree_enter')
    if invalidations:
        need(invalidations == 2 and helper == 1, 'actual successful move invalidation count')
        helper_end = next(e for e in events if e['kind'] == 'filesystem_helper_exit')
        need(helper_end['data']['ok'] is True, 'failed move invalidated cache')
    if step['action']['kind'] != 'public': need(outer == entered == helper == 0 and kinds == ['step_begin', 'step_end'], 'private fixture control executed SDK')
    return {'outer': outer, 'handler': entered, 'helper': helper, 'invalidations': invalidations, 'cache_changes': cache_changes,
            'event_kinds': kinds, 'markers': [e['marker'] for e in events]}


def rows_evidence(rows, scenarios, raw, policy_installed):
    expected = []
    for scene in scenarios:
        expected.append(('scenario_start', scene['scenario_id'], None))
        expected += [('case', scene['scenario_id'], step['case_id']) for step in scene['steps']]
        expected.append(('scenario_end', scene['scenario_id'], None))
    same([(r['metadata']['kind'], r['metadata'].get('scenario_id'), r['metadata'].get('case_id')) for r in rows], expected, 'all original scenarios/cases/order')
    scene_by_id = {s['scenario_id']: s for s in scenarios}; steps = {s['case_id']: s for scene in scenarios for s in scene['steps']}
    states = {}; trees = {}; markers = []; cases = []; counts = Counter(); initialized = {}
    for row in rows:
        meta = row['metadata']; scene = scene_by_id[meta['scenario_id']]; roots = scene['observed_roots']
        for event in meta['events']:
            need(type(event) is dict and type(event.get('marker')) is int, 'actual typed marker'); markers.append(event['marker'])
        if meta['kind'] == 'scenario_start':
            fields(meta, ('kind', 'scenario_id', 'name', 'policy_id', 'fence_id', 'sessions', 'filesystem', 'events'), 'scenario initial fields')
            same({k: meta[k] for k in ('name', 'policy_id', 'fence_id')}, {k: scene[k] for k in ('name', 'policy_id', 'fence_id')}, 'scenario identity')
            need(len(meta['sessions']) == len(scene['sessions']), 'actual session count')
            for observed, item in zip(meta['sessions'], scene['sessions']):
                fields(observed, ('session', 'exchanges', 'state'), 'session creation observation'); same(observed['session'], item['id'], 'session identity')
                root = hex_bytes(item['root_hex'], 'fixture session root'); state(observed['state'], root)
                same(observed['state'], {'root_hex': item['root_hex'], 'current_hex': None, 'effective_hex': item['root_hex'],
                     'poisoned': False, 'session_applied': False, 'cache': {'poisoned': False, 'entries': {}}}, 'new original session state')
                need(len(observed['exchanges']) == len(item['initial_messages']), 'complete legacy handshake')
                for actual, message in zip(observed['exchanges'], item['initial_messages']): exchange(actual, {'message': message}, raw, row)
                states[(meta['scenario_id'], item['id'])] = observed['state']; initialized[(meta['scenario_id'], item['id'])] = bool(item['initial_messages'])
            filesystem(meta['filesystem'], roots); trees[meta['scenario_id']] = meta['filesystem']
            need([e['kind'] for e in meta['events']] == ['scenario_setup_begin', 'scenario_setup_complete'], 'complete actual setup marker pair')
            for event in meta['events']:
                fields(event, ('kind', 'marker', 'data', 'state'), 'setup event fields'); same(event['data'], {'scenario_id': scene['scenario_id']}, 'setup event scenario'); need(event['state'] is None, 'setup borrowed stale session')
            continue
        if meta['kind'] == 'scenario_end':
            fields(meta, ('kind', 'scenario_id', 'sessions', 'filesystem', 'events'), 'scenario terminal fields')
            same(sorted(meta['sessions']), sorted(item['id'] for item in scene['sessions']), 'all sessions actually terminated')
            for identifier, terminal in meta['sessions'].items():
                fields(terminal, ('state', 'outer_calls', 'handler_calls', 'service'), 'actual session termination')
                same(terminal['state'], states[(meta['scenario_id'], identifier)], 'terminal original session state')
                own = [c for c in cases if c['scenario_id'] == meta['scenario_id'] and c['session'] == identifier]
                same(terminal['outer_calls'], sum(c['outer'] for c in own), 'session total outer calls'); same(terminal['handler_calls'], sum(c['handler'] for c in own), 'session total typed handler calls')
                service = terminal['service']; need(type(service) is dict and type(service.get('initialized')) is bool, 'actual SDK service termination')
                if service['initialized']: fields(service, ('initialized', 'terminated'), 'actual completed SDK service'); need(type(service['terminated']) is str and service['terminated'], 'complete service result')
                else: fields(service, ('initialized', 'error'), 'actual refused SDK service'); need(type(service['error']) is str and service['error'], 'complete initial SDK error')
            same(meta['filesystem'], trees[meta['scenario_id']], 'filesystem changed outside observed steps')
            need(len(meta['events']) == 1 and meta['events'][0]['kind'] == 'scenario_end' and meta['events'][0]['state'] is None, 'actual scenario end marker')
            same(meta['events'][0]['data'], {'scenario_id': scene['scenario_id']}, 'scenario end identity'); continue
        fields(meta, ('kind', 'scenario_id', 'case_id', 'name', 'domain', 'session', 'state_before', 'state_after', 'filesystem_before', 'filesystem_after',
                      'fds_before', 'fds_after', 'result', 'outer_call_tool_entries', 'handler_entries', 'request_context_present_after', 'events'), 'complete original case record')
        step = steps[meta['case_id']]; same({k: meta[k] for k in ('name', 'domain', 'session')}, {k: step[k] for k in ('name', 'domain', 'session')}, 'actual case identity/domain')
        key = (meta['scenario_id'], meta['session']); same(meta['state_before'], states[key], 'cross-call same-session state')
        root = hex_bytes(meta['state_before']['root_hex'], 'session root'); state(meta['state_after'], root); states[key] = meta['state_after']
        same(meta['filesystem_before'], trees[meta['scenario_id']], 'cross-call filesystem continuity')
        filesystem(meta['filesystem_before'], roots); filesystem(meta['filesystem_after'], roots); trees[meta['scenario_id']] = meta['filesystem_after']
        descriptors(meta['fds_before']); descriptors(meta['fds_after']); same(meta['fds_before'], meta['fds_after'], 'actual descriptor cleanup')
        need(meta['request_context_present_after'] is False, 'request scope leaked to caller')
        ev = event_evidence(meta, step, row, raw, policy_installed)
        item = {'scenario_id': meta['scenario_id'], 'case_id': step['case_id'], 'name': step['name'], 'domain': step['domain'], 'session': step['session'],
                **ev, 'record': row['record'], 'metadata_span': row['metadata_span'], 'blobs': row['blobs'], 'state_before_sha256': sha(canonical(meta['state_before'])),
                'state_after_sha256': sha(canonical(meta['state_after'])), 'filesystem_before_sha256': sha(canonical(meta['filesystem_before'])),
                'filesystem_after_sha256': sha(canonical(meta['filesystem_after'])), 'fd_count': len(meta['fds_before'])}
        if step['action']['kind'] == 'public':
            request, reply, response = exchange(meta['result'], step['action'], raw, row)
            item.update(transport=meta['result']['transport'], response_bytes=len(response), response_sha256=sha(response), request_bytes_written=meta['result']['request_bytes_written'])
            counts['public_calls'] += 1; counts['transport_'+meta['result']['transport']] += 1
            if ev['outer']:
                outer = next(e for e in meta['events'] if e['kind'] == 'outer_call_tool_enter')['data']
                same(outer['tool'], request['params']['name'], 'actual outer tool name')
                same(strict_json(blob(raw, row, outer['canonical_arguments_blob'])), request['params'].get('arguments', {}), 'SDK Value arguments projection')
            if ev['handler']:
                enter = next(e for e in meta['events'] if e['kind'] == 'handler_enter')['data']
                finish = next(e for e in meta['events'] if e['kind'] == 'handler_exit')['data']
                typed = strict_json(blob(raw, row, enter['typed_parameters_blob'])); tool = request['params']['name']
                keys = ('path',) if tool == 'directory_create' else ('source', 'destination')
                same(typed, {k: request['params']['arguments'][k] for k in keys}, 'actual typed original parameters')
                need(all(type(typed[k]) is str for k in keys), 'typed handler accepted nonstring')
                same(enter['tool'], tool, 'original handler name'); need(reply is not None and 'result' in reply, 'actual String result must use SDK result envelope')
                content = reply['result']; body = blob(raw, row, finish['body_blob'])
                expected = {'content': [{'type': 'text', 'text': body.decode()}], 'isError': not finish['ok']}
                if not initialized[key]: expected['resultType'] = 'complete'
                same(content, expected, 'actual full SDK String conversion/body/resultType')
                counts['string_successes' if finish['ok'] else 'string_errors'] += 1; counts['complete_method_body_bytes'] += len(body)
                item.update(method_ok=finish['ok'], method_body_bytes=len(body), method_body_sha256=sha(body))
                if ev['helper']:
                    begin = next(e for e in meta['events'] if e['kind'] == 'filesystem_helper_enter')['data']
                    end = next(e for e in meta['events'] if e['kind'] == 'filesystem_helper_exit')['data']
                    same(begin['tool'], tool, 'actual helper tool'); same(strict_json(blob(raw, row, begin['parameters_blob'])), typed, 'actual serialized typed helper input')
                    same(end['ok'], finish['ok'], 'original helper/handler result')
                    helper_body = blob(raw, row, end['body_blob']) if end['ok'] else error_data(end, raw, row)[0]
                    need(helper_body == body, 'actual original helper whole result/error propagated')
                    if end['ok'] and tool != 'directory_create': need(ev['invalidations'] == 2, 'successful move omitted cache invalidation')
                elif finish['ok']: raise ValueError('filesystem SDK reference: successful method did not execute original helper')
                else:
                    fence_end = next(e for e in meta['events'] if e['kind'] == 'effect_fence_exit')['data']
                    if fence_end['ok'] is False: need(body == error_data(fence_end, raw, row)[0], 'exact fence error propagated to SDK body')
                    else:
                        policy_failures = [e['data'] for e in meta['events'] if e['kind'] in ('local_policy_exit', 'remote_policy_exit') and e['data']['ok'] is False]
                        direct_errors = (b'Octofs background resources are disabled in runtime mode', b'path must not contain an empty root')
                        need(body in direct_errors or policy_failures and body == error_data(policy_failures[-1], raw, row)[0], 'exact outer policy error propagated')
            elif reply is not None:
                need('error' in reply, 'SDK typed/metadata rejection envelope'); counts['typed_errors' if ev['outer'] else 'metadata_errors'] += 1
            else: need(ev['outer'] == ev['handler'] == 0, 'closed transport executed handler')
            if not ev['helper']: same(meta['filesystem_before'], meta['filesystem_after'], 'pre-helper refusal changed actual filesystem')
        else:
            counts['private_controls'] += 1
            if step['action']['kind'] == 'cache_seed':
                same(meta['result'], {'private_actual_cache_seed': True}, 'actual private cache seed flag')
                same(meta['filesystem_before'], meta['filesystem_after'], 'cache seed changed filesystem')
                expected_entries = dict(meta['state_before']['cache']['entries'])
                for entry in step['action']['entries']:
                    key = os.path.normpath(hex_bytes(entry['path_hex'], 'cache seed raw path')).decode('utf-8', errors='replace')
                    value = entry['content'].replace('\r\n', '\n'); need(len(value.encode()) <= 1024*1024, 'declared cache seed domain')
                    expected_entries[key] = value
                same(meta['state_after']['cache']['entries'], expected_entries, 'complete actual seeded cache content')
            else: same(meta['result'], {'private_fixture_actions': len(step['action']['actions'])}, 'private actual filesystem action count')
        counts['cases'] += 1
        for name in ('outer', 'handler', 'helper', 'invalidations'): counts[name] += ev[name]
        cases.append(item)
    same(markers, list(range(1_000_000_001, 1_000_000_001+len(markers))), 'complete actual marker sequence')
    return {'counts': dict(sorted(counts.items())), 'cases': cases, 'markers': len(markers), 'records': len(rows)}


def split_arguments(raw):
    result = []; start = 0; depth = 0; quoted = False
    for at, byte in enumerate(raw):
        if byte == '"': quoted = not quoted
        elif not quoted:
            if byte in '([{': depth += 1
            elif byte in ')]}': depth -= 1; need(depth >= 0, 'trace argument nesting')
            elif byte == ',' and depth == 0: result.append(raw[start:at].strip()); start = at+1
    need(not quoted and depth == 0, 'unfinished trace argument'); result.append(raw[start:].strip()); return result


def quoted(raw, limit=4095):
    match = re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"(\.\.\.)?', raw)
    need(match is not None, 'trace string is not complete hex encoding')
    body = bytes.fromhex(match.group(1).replace('\\x', '')); clipped = match.group(2) is not None
    need(not clipped or len(body) == limit, 'trace truncated prefix length'); return body, clipped


def trace_evidence(raw, rows, stdout, stderr, fixture, binary, policy_file):
    """Parse every syscall; bind all markers, operation intervals and complete output extents."""
    need(type(raw) is bytes and raw.endswith(b'\n'), 'unfinished complete strace')
    expected_events = [event for row in rows for event in row['metadata']['events']]
    case_rows = {row['metadata']['case_id']: row for row in rows if row['metadata']['kind'] == 'case'}
    expected_cases = [row['metadata']['case_id'] for row in rows if row['metadata']['kind'] == 'case']
    fixture = str(fixture).encode(); trace_pids = set(); marker_pid = None; offset = 0; counts = Counter()
    open_fds = {}; opened = closed = failed_opens = 0; complete_writes = clipped_writes = write_bytes = 0
    stream_offsets = {1: 0, 2: 0}; streams = {1: stdout, 2: stderr}; active = None; completed = []; markers = []
    truncations = 0; execs = 0; other_count = 0; stack = []; current_event = None; outside_digest = hashlib.sha256()
    names = {'access', 'chmod', 'close', 'execve', 'faccessat2', 'getdents64', 'getpgid', 'linkat', 'mkdir', 'mkdirat',
             'mknodat', 'newfstatat', 'openat', 'readlink', 'renameat2', 'rmdir', 'statx', 'symlink', 'write'}
    path_indices = {'access': (0,), 'chmod': (0,), 'execve': (0,), 'faccessat2': (1,), 'linkat': (1, 3),
                    'mkdir': (0,), 'mkdirat': (1,), 'mknodat': (1,), 'newfstatat': (1,), 'openat': (1,),
                    'readlink': (0,), 'renameat2': (1, 3), 'rmdir': (0,), 'statx': (1,), 'symlink': (0, 1)}
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        match = re.fullmatch(rb'(\d+)\s+([a-z_0-9]+)\((.*)\)\s+=\s+(-?\d+)(?:\s+([A-Z0-9_]+)\s+\([^\n]*\))?\n', line)
        need(match is not None, 'unparsed full trace line '+str(line_number))
        pid, name, args, result = int(match[1]), match[2].decode(), split_arguments(match[3].decode('ascii')), int(match[4])
        error_name = match[5].decode() if match[5] else None
        need(pid > 0 and name in names, 'unexpected actual syscall'); trace_pids.add(pid); counts[name] += 1
        need((result == -1) == (error_name is not None), 'trace return/errno shape')
        error_number = getattr(errno, error_name, None) if error_name else 0
        need(type(error_number) is int and (error_name is None or error_number > 0), 'actual errno name')
        event = {'pid': pid, 'syscall': name, 'return': result, 'errno_name': error_name, 'errno': error_number,
                 'line': line_number, 'offset': offset, 'bytes': len(line), 'sha256': sha(line)}; offset += len(line)
        if name == 'getpgid':
            need(len(args) == 1 and args[0].isdigit() and result == -1 and error_name == 'ESRCH', 'actual marker syscall')
            index = len(markers); need(index < len(expected_events), 'extra actual marker'); expected = expected_events[index]
            need(int(args[0]) == expected['marker'], 'actual marker value/order')
            if marker_pid is None: marker_pid = pid
            need(pid == marker_pid, 'observer marker changed thread'); event.update(marker=int(args[0]), kind=expected['kind'])
            markers.append(event); current_event = event
            if expected['kind'] == 'step_begin':
                need(active is None and not open_fds and len(completed) < len(expected_cases), 'actual step starts with owned descriptor')
                cid = expected['data']['case_id']; same(cid, expected_cases[len(completed)], 'actual step order')
                active = {'case_id': cid, 'begin': event, 'events': [], 'markers': []}
            if active is not None: active['markers'].append(event)
            if expected['kind'] == 'step_end':
                need(active is not None and active['case_id'] == expected['data']['case_id'] and not open_fds, 'actual descriptor/step cleanup')
                active['end'] = event; completed.append(active); active = None
            continue
        paths = []
        for position in path_indices.get(name, ()):
            need(len(args) > position, 'syscall path argument count'); body, clipped = quoted(args[position])
            normalized = b'@fixture'+body[len(fixture):] if body == fixture or body.startswith(fixture+b'/') else body
            paths.append({'argument': position, 'raw_hex': body.hex(), 'normalized_hex': normalized.hex(), 'truncated': clipped})
            truncations += int(clipped)
        if paths: event['paths'] = paths
        if name == 'execve':
            need(line_number == 1 and result == 0 and execs == 0 and len(args) == 3, 'actual single executable entry')
            need(quoted(args[0]) == (str(binary).encode(), False), 'actual trace binary path')
            argv = split_arguments(args[1][1:-1]); need(len(argv) == 3, 'actual original argv extent')
            same([quoted(x)[0].decode() for x in argv], [str(binary), fixture.decode(), str(policy_file)], 'actual original argv')
            need(all(not quoted(x)[1] for x in argv) and re.fullmatch(r'0x[0-9a-f]+ /\* \d+ vars \*/', args[2]), 'actual argv/environment trace')
            execs += 1
        elif name == 'openat':
            need(len(args) in (3, 4), 'actual open arguments'); flags = args[2].split('|'); event.update(dirfd=args[0], flags=flags)
            if len(args) == 4: event['mode'] = args[3]
            if result >= 0:
                need(result >= 3 and result not in open_fds, 'actual descriptor ownership reuse')
                open_fds[result] = {'event': event, 'serial': opened}; event['fd'] = result; event['fd_serial'] = opened; opened += 1
            else: failed_opens += 1
        elif name == 'close':
            need(len(args) == 1 and args[0].isdigit() and result == 0, 'actual close result')
            fd = int(args[0]); need(fd in open_fds, 'actual close without owned open')
            event.update(fd=fd, fd_serial=open_fds.pop(fd)['serial']); closed += 1
        elif name == 'write':
            need(len(args) == 3 and args[0].isdigit() and args[2].isdigit(), 'actual write arguments')
            fd = int(args[0]); body, clipped = quoted(args[1], 4096); requested = int(args[2])
            need(result == requested and requested >= len(body) and (clipped or requested == len(body)), 'complete actual write return')
            event.update(fd=fd, requested=requested, buffer_prefix_bytes=len(body), buffer_prefix_sha256=sha(body), buffer_truncated=clipped)
            if fd in streams:
                at = stream_offsets[fd]; need(result <= len(streams[fd])-at and streams[fd][at:at+len(body)] == body, 'actual stdout/stderr write span')
                event.update(stream_offset=at, complete_stream_span_sha256=sha(streams[fd][at:at+result])); stream_offsets[fd] += result
                need(active is None, 'output published before observed step completed')
                write_bytes += result; clipped_writes += int(clipped); complete_writes += int(not clipped)
            else: need(fd in open_fds and active is None or fd in open_fds and case_rows[active['case_id']]['metadata']['domain'] == 'private-fixture-control', 'unexpected original filesystem content write')
        elif name == 'getdents64':
            need(len(args) == 3 and args[0].isdigit() and int(args[0]) in open_fds and result >= 0, 'actual directory enumeration descriptor')
            if active is not None: need(case_rows[active['case_id']]['metadata']['domain'] == 'private-fixture-control', 'original method traversed directory contents')
        elif name == 'readlink':
            need(len(args) == 3 and args[2].isdigit(), 'actual readlink arguments'); capacity = int(args[2]); event['capacity'] = capacity
            if result >= 0:
                body, clipped = quoted(args[1], 4096); need(result == len(body) and not clipped and result <= capacity, 'actual readlink result extent'); event['target_hex'] = body.hex()
            else: need(re.fullmatch(r'0x[0-9a-f]+', args[1]) is not None, 'actual failed readlink pointer')
        elif name in ('mkdirat', 'renameat2', 'newfstatat'):
            need(active is not None, 'fd-relative original effect outside declared call')
            event['arguments'] = args
            if name == 'renameat2': need(len(args) == 5 and args[-1] == 'RENAME_NOREPLACE' and result in (0, -1), 'actual atomic noreplace flags')
            if name == 'mkdirat': need(len(args) == 3 and args[-1] == '0700' and result in (0, -1), 'actual original mkdir permissions')
        if active is not None:
            event['after_marker'] = current_event['marker']; event['after_event_kind'] = current_event['kind']; active['events'].append(event)
        else: other_count += 1; outside_digest.update(line)
    need(execs == 1 and not open_fds and opened == closed and active is None, 'full trace descriptor/process closure')
    need(len(markers) == len(expected_events) and [c['case_id'] for c in completed] == expected_cases, 'complete trace markers/cases')
    need(stream_offsets == {1: len(stdout), 2: len(stderr)}, 'complete actual stdout/stderr extent')
    for case in completed:
        meta = case_rows[case['case_id']]['metadata']; kinds = [e['kind'] for e in meta['events']]
        if meta['domain'] == 'public-sdk-original-method':
            if 'handler_enter' not in kinds or 'effect_fence_exit' in kinds and not next(e for e in meta['events'] if e['kind'] == 'effect_fence_exit')['data']['ok']:
                need(not case['events'], 'SDK/fence early refusal performed filesystem effects')
            need(all(e['syscall'] not in ('write', 'mkdir', 'symlink', 'linkat', 'mknodat', 'rmdir', 'chmod') for e in case['events']), 'unexpected fallback/mutation in original public method')
    return {'trace_bytes': len(raw), 'trace_sha256': sha(raw), 'lines': sum(counts.values()), 'syscall_counts': dict(sorted(counts.items())),
            'actual_thread_ids': sorted(trace_pids), 'observer_thread': marker_pid, 'markers': len(markers), 'cases': completed,
            'owned_open_successes': opened, 'failed_open_attempts': failed_opens, 'owned_close_successes': closed,
            'outside_case_syscalls': other_count, 'outside_case_lines_sha256': outside_digest.hexdigest(),
            'stdout_complete_extent_bound': len(stdout), 'stderr_complete_extent_bound': len(stderr), 'trace_string_limit': 4096,
            'truncated_path_prefix_bytes': 4095, 'truncated_path_arguments': truncations, 'truncated_write_prefix_bytes': 4096,
            'full_streams_separately_bound': True, 'stdout_stderr_untruncated_write_calls': complete_writes,
            'stdout_stderr_truncated_write_calls': clipped_writes, 'stdout_stderr_written_bytes': write_bytes}


def reference_evidence(source_root, capture_root):
    source, capture = Binder(source_root), Binder(capture_root)
    for name, (size, digest) in SOURCES.items(): source.file(name, {'bytes': size, 'sha256': digest})
    factory = load(source.file('oracle/verify_sources.py'), '_filesystem_sdk_source_verify')
    materialized, original = factory.assemble(source.root/'oracle')
    source_report, report = capture.json('SOURCE.json'), capture.json('RESULT.json')
    same(report.get('schema'), 'hepta.runtime.filesystem-sdk-original-capture.v1', 'capture schema'); same(report.get('status'), 'PASS', 'capture status')
    old_source, old_fixture = Path(report['source_root']), Path(report['fixture_root']); old_capture = old_fixture.parent
    need(old_source.is_absolute() and old_fixture.is_absolute() and old_fixture.name == 'fixtures' and
         '..' not in old_source.parts and '..' not in old_fixture.parts, 'actual execution root paths')
    fields(source_report, ('source_root', 'source_files', 'original'), 'complete source report')
    same(source_report['source_root'], str(old_source), 'source execution provenance'); same(source_report['source_files'], source.artifacts, 'exact seventeen-file source graph')
    same(source_report['original'], original, 'unchanged original closure/normalized original dependency subset')
    for name, raw in materialized.items(): need(capture.data('crate/'+name) == raw, 'byte-exact actual compiled crate '+name)
    cases_factory = load(source.file('cases.py'), '_filesystem_sdk_cases'); replay = load(source.file('run.py'), '_filesystem_sdk_producer')
    corpus = cases_factory.materialized(old_fixture); same(capture.json('CORPUS.json'), corpus, 'complete regenerated input corpus')
    same(corpus['counts'], {'groups': 12, 'scenarios': 28, 'steps': 332, 'public_calls': 323, 'private_controls': 9}, 'fixed declared input domains')
    names = ['SOURCE.json', 'HOST.json', 'CORPUS.json', 'GROUPS.json', 'processes.json', 'remote-process.json']
    names += [name+'.'+kind for name in ('rustc-version', 'cargo-version', 'strace-version', 'locked-build') for kind in ('stdout', 'stderr')]
    for group in corpus['groups']:
        names += [group['name']+'.'+suffix for suffix in ('input.jsonl', 'policy.json', 'strace', 'stdout', 'stderr', 'observations.jsonl', 'input.jsonl.gz', 'stdout.gz', 'strace.gz')]
    same(sorted(report.get('artifact_bytes', {})), sorted(names), 'all actual captured files/byte lengths')
    same(sorted(report.get('artifact_sha256', {})), sorted(names), 'all actual captured file hashes')
    for name in names:
        size = uint(report['artifact_bytes'][name], 'typed artifact byte count'); digest = report['artifact_sha256'][name]
        need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'artifact hash type')
        capture.file(name, {'bytes': size, 'sha256': digest})
    processes = capture.json('processes.json'); need(type(processes) is list and len(processes) == 16, 'all sixteen actual subprocesses')
    commands = [[TOOL+'rustc', '-Vv'], [TOOL+'cargo', '-Vv'], ['/usr/bin/strace', '-V'],
                [TOOL+'cargo', 'build', '--release', '--locked', '--manifest-path', str(old_capture/'crate/Cargo.toml')]]
    process_names = ['rustc-version', 'cargo-version', 'strace-version', 'locked-build']
    binary_relative = 'target/release/hepta-filesystem-sdk-original'; binary_path = old_capture/binary_relative
    for group in corpus['groups']:
        name = group['name']; process_names.append(name)
        commands.append(['/usr/bin/strace', '-f', '-qq', '-s', '4096', '-xx', '-e', TRACE, '-o', str(old_capture/(name+'.strace')),
                         '--', str(binary_path), str(old_fixture), str(old_capture/(name+'.policy.json'))])
    for number, (actual, command, name) in enumerate(zip(processes, commands, process_names)):
        same(actual.get('name'), name, 'actual process order/name')
        fence = {} if number < 4 else corpus['fence_environments'][corpus['groups'][number-4]['fence_id']]
        process(actual, command, old_capture/'crate' if number < 4 else old_fixture, old_capture, fence)
        for kind in ('stdout', 'stderr'):
            key = name+'.'+kind; same(actual[kind], {'path': str(old_capture/key), **capture.artifacts[key]}, 'actual full '+name+' '+kind)
        key = name+'.input.jsonl'
        same(actual['stdin'], None if number < 4 else {'path': str(old_capture/key), **capture.artifacts[key]}, 'actual full process stdin')
    need(len({p['pid'] for p in processes}) == len(processes), 'actual process PIDs reused')
    rustc, cargo = capture.data('rustc-version.stdout'), capture.data('cargo-version.stdout')
    need(rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc, 'actual fixed Rust version/target')
    need(cargo.startswith(b'cargo 1.95.0 ') and b'release: 1.95.0\n' in cargo, 'actual fixed Cargo version')
    need(capture.data('strace-version.stdout').startswith(b'strace -- version '), 'actual strace version')
    for name in ('rustc-version', 'cargo-version', 'strace-version'): need(not capture.data(name+'.stderr'), 'version process stderr')
    tools = {'rustc': (644784, 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'),
             'cargo': (42185192, '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'),
             'strace': (2370264, 'f47342683309e807bca57d6d89b82f94a9b39aa614e9c28c2b67cefbc35eee58')}
    for name, (size, digest) in tools.items():
        same(report.get(name+'_executable'), {'path': '/usr/bin/strace' if name == 'strace' else TOOL+name, 'bytes': size, 'sha256': digest}, 'actual fixed executable '+name)
    binary = capture.file(binary_relative)
    same(report.get('binary'), {'path': str(binary_path), **capture.artifacts[binary_relative]}, 'actual fresh original binary')
    need(binary.stat().st_mode & 0o111 and binary.read_bytes().startswith(b'\x7fELF'), 'actual replay ELF')
    rustc_info = capture.json('target/.rustc_info.json', report.get('target_rustc_info')); info = rustc_info.get('outputs')
    need(type(info) is dict, 'target compiler identity')
    need(any(type(row) is dict and row.get('success') is True and type(row.get('code')) is int and row['code'] == 0 and
             row.get('stderr') == '' and row.get('stdout', '').encode() == rustc for row in info.values()), 'full actual compiler identity matches executed version')
    need(any('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu\n' in row.get('stdout', '') for row in info.values()), 'actual fixed toolchain sysroot')
    host = capture.json('HOST.json'); fields(host, ('uid', 'euid', 'gid', 'egid', 'uname', 'status', 'cwd', 'USER'), 'complete actual host observation')
    for name in ('uid', 'euid', 'gid', 'egid'): need(uint(host[name], 'host '+name) > 0, 'unprivileged original filesystem execution')
    same(host['uid'], host['euid'], 'host UID'); same(host['gid'], host['egid'], 'host GID'); same(host['cwd'], str(old_fixture), 'actual fixture cwd')
    need(type(host['uname']) is list and len(host['uname']) == 5 and host['uname'][0] == 'Linux' and host['uname'][-1] == 'x86_64', 'actual Linux host')
    need(type(host['status']) is str and '\nCapEff:\t0000000000000000\n' in host['status'] and '\nUmask:\t0077\n' in host['status'], 'actual unprivileged permission/umask conditions')
    producer = capture.json('remote-process.json'); fields(producer, ('argv', 'cgroup', 'pid'), 'actual producer identity fields')
    same(producer['argv'], [str(old_source/'run.py'), '--output', str(old_capture)], 'actual producer command')
    need(uint(producer['pid'], 'producer PID') > 0 and '\nPid:\t'+str(producer['pid'])+'\n' in host['status'], 'actual producer PID/host link')
    need(type(producer['cgroup']) is str and re.search(r'hepta-runtime-job-[a-z0-9-]+\.service\n', producer['cgroup']), 'actual durable producer cgroup')
    groups = []; summaries = []; totals = Counter(); trace_counts = Counter(); all_ids = []
    for group in corpus['groups']:
        name = group['name']; expected_input = b''.join(cases_factory.canonical(scene) for scene in group['scenarios'])
        need(capture.data(name+'.input.jsonl') == expected_input, 'complete original input regeneration '+name)
        need(capture.data(name+'.policy.json') == cases_factory.canonical(corpus['policies'][group['policy_id']]), 'actual policy bytes '+name)
        stdout, stderr = capture.data(name+'.stdout'), capture.data(name+'.stderr'); need(not stderr, 'actual original replay stderr')
        rows = parse_output(stdout); observed = [strict_json(line) for line in capture.data(name+'.observations.jsonl').split(b'\n') if line]
        same(rows, observed, 'full decoded output/span projection '+name)
        semantics = rows_evidence(rows, group['scenarios'], stdout, corpus['policies'][group['policy_id']] is not None)
        summary = replay.validate_rows(rows, group['scenarios'], stdout)
        summaries.append({'name': name, 'policy_id': group['policy_id'], 'fence_id': group['fence_id'], **summary,
                          'complete_stdout_bytes': len(stdout), 'complete_input_bytes': len(expected_input), 'fulltrace': capture.artifacts[name+'.strace']})
        trace = trace_evidence(capture.data(name+'.strace'), rows, stdout, stderr, old_fixture, binary_path, old_capture/(name+'.policy.json'))
        same(trace['markers'], semantics['markers'], 'trace/semantic complete marker count')
        for suffix in ('input.jsonl', 'stdout', 'strace'): gzip_evidence(capture.file(name+'.'+suffix+'.gz'), capture.artifacts[name+'.'+suffix])
        totals.update(semantics['counts']); totals['markers'] += semantics['markers']; totals['records'] += len(rows)
        totals['complete_input_bytes'] += len(expected_input); totals['complete_stdout_bytes'] += len(stdout)
        all_ids += [case['case_id'] for case in semantics['cases']]; trace_counts.update(trace['syscall_counts'])
        groups.append({'name': name, 'policy_id': group['policy_id'], 'fence_id': group['fence_id'], 'semantics': semantics, 'trace': trace})
    same(sorted(all_ids), list(range(70000, 70332)), 'all unique fixed case identifiers')
    same(capture.json('GROUPS.json'), summaries, 'complete capture summaries re-derived from raw original streams')
    flags = {'actual_local_filesystem_operations': True, 'actual_request_context_and_cache': True, 'actual_sdk_method_adapter': True,
             'actual_sdk_parameters_extractor': True, 'actual_unconfigured_fence_and_early_refusals': True, 'full_configured_fence_acquisition_executed': False,
             'original_config_loader_executed': False, 'original_full_router_executed': False, 'remote_io_executed': False,
             'source_files_unchanged': True, 'new_native_calls': 0}
    derived = {**flags, 'actual_processes': len(processes), 'actual_replays': len(groups), 'fresh_locked_builds': 1, 'version_processes': 3,
               'counts': corpus['counts'], 'complete_input_bytes': totals['complete_input_bytes'], 'complete_stdout_bytes': totals['complete_stdout_bytes'],
               'marker_events': totals['markers'], 'trace_string_limit': 4096}
    same({key: report.get(key) for key in derived}, derived, 'all derived capture counts/scope')
    fields(report, (*derived, 'schema', 'status', 'source_root', 'fixture_root', 'elapsed_seconds', 'artifact_bytes', 'artifact_sha256',
                    'rustc_executable', 'cargo_executable', 'strace_executable', 'binary', 'target_rustc_info'), 'complete original capture report')
    positive(report['elapsed_seconds'], 'actual whole capture duration')
    need(report['elapsed_seconds'] >= sum(p['elapsed_seconds'] for p in processes), 'capture duration below process time')
    for binder in (source, capture):
        for name, expected in list(binder.artifacts.items()): same(pin(inside(binder.root, name)), expected, 'artifact changed during strict reading')
    artifacts = {**{'source/'+k: v for k, v in source.artifacts.items()}, **{'capture/'+k: v for k, v in capture.artifacts.items()}}
    return {'schema': 'hepta.runtime.filesystem-sdk-original-evidence.v1', 'status': 'PASS', **derived,
            'observed_counts': dict(sorted(totals.items())), 'actual_syscall_counts': dict(sorted(trace_counts.items())),
            'original_source': original, 'groups': groups, 'actual_process_receipts': processes, 'actual_producer': producer,
            'actual_execution_roots': {'source': str(old_source), 'capture': str(old_capture)}, 'original_binary': report['binary'],
            'artifacts': len(artifacts), 'artifact_bytes': {k: v['bytes'] for k, v in sorted(artifacts.items())},
            'artifact_sha256': {k: v['sha256'] for k, v in sorted(artifacts.items())},
            'live_fixture_required': False, 'new_rust_processes': 0, 'new_filesystem_operations': 0}


def main():
    p = argparse.ArgumentParser()
    for name in ('source', 'capture', 'output'): p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); value = reference_evidence(a.source, a.capture)
    with a.output.open('x') as stream: json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False); stream.write('\n')
    print(json.dumps({'status': value['status'], 'counts': value['observed_counts'], 'actual_processes': value['actual_processes'],
          'artifacts': value['artifacts'], 'evidence_bytes': a.output.stat().st_size, 'evidence_sha256': pin(a.output)['sha256'],
          'new_rust_processes': 0, 'new_native_calls': 0}, sort_keys=True))


if __name__ == '__main__': main()
