"""Compare complete actual Local four-command gateway state and effects."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--profile", required=True, choices=("baseline", "capabilities", "configured", "denied", "fence_required", "smoke", "body"))
for name in ("source", "reference", "original", "manifest", "members", "output"):
    parser.add_argument("--" + name, required=True, type=Path)
args = parser.parse_args()
SOURCE = args.source.resolve(strict=True)
REFERENCE = args.reference.resolve(strict=True)
ORIGINAL = args.original.resolve(strict=True)
BUILD_MANIFEST = args.manifest.resolve(strict=True)
MEMBERS = args.members.resolve(strict=True)
OUT = args.output.resolve()
assert not OUT.exists() and not OUT.is_relative_to(SOURCE) and not OUT.is_relative_to(REFERENCE)
PROFILE = args.profile
CONFIGURED = PROFILE in ("configured", "denied")
FENCE_REQUIRED = PROFILE == "fence_required"
EFFECTS = OUT / "effects"
sys.path.insert(0, str(Path(__file__).resolve().parent))
Q = lambda *v: struct.pack('<' + 'Q' * len(v), *v)
U = lambda b, at: struct.unpack_from('<Q', b, at)[0]
sha = lambda b: hashlib.sha256(b).hexdigest()
encode = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identities(root):
    return {str(p.relative_to(root)): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
            for p in sorted(root.rglob('*')) if p.is_file()}


def cache_frame(op, key='', value=''):
    key, value = key.encode(), value.encode()
    return b'HVCACH01' + Q(op, 0, len(key), len(value), 0) + key + value


def legacy_cases():
    rows = []
    invalid = [{}, {'path':'x'}, {'command':'create'},
               {'command':None,'path':'x'}, {'command':4,'path':'x'},
               {'command':'unknown','path':'x'}, {'command':'create','path':None},
               {'command':'create','path':4}, {'command':'create','path':[]},
               {'command':'create','path':'x','content':4},
               {'command':'create','path':'x','old_text':False},
               {'command':'create','path':'x','new_text':[]},
               {'command':'create','path':'x','replace_all':'false'}]
    for sid in (0, 1):
        for index, params in enumerate(invalid):
            rows.append(dict(id='typed-refusal-%d-%d' % (sid,index),kind='call',session=sid,
                             parameters=params,typed_refusal=True))

    def call(name, path, content, sid=0, missing=False):
        params = dict(command='create', path=path)
        if not missing:
            params['content'] = content
        rows.append(dict(id=name, kind='call', session=sid, parameters=params, workdir=str(EFFECTS)))

    def cache(name, sid, op, key='', value=''):
        rows.append(dict(id=name, kind='cache', session=sid, wire_hex=cache_frame(op, key, value).hex()))

    key = str(EFFECTS / 'rewrite-cache')
    cache('seed-own-cache', 0, 2, key, 'stale\r\nvalue')
    cache('seed-other-cache', 1, 2, key, 'foreign')
    call('missing-content', 'missing-content', '', missing=True)
    call('null-content', 'null-content', None, sid=1)
    call('create-replaces-own-cache', 'rewrite-cache', 'new\r\ncache')
    cache('read-created-own-cache', 0, 1, key)
    cache('read-isolated-other-cache', 1, 1, key)
    call('existing-cross-session', 'rewrite-cache', 'overwrite denied', sid=1)
    call('empty-content', 'empty', '')
    call('create-parents', 'nested/deep/file.txt', 'nested\n', sid=1)
    call('unicode-path-content', '目录/文档-😀.txt', '中文\r\nΔ🙂\n')
    call('nul-content', 'nul-content', 'a\x00b\n', sid=1)
    call('nul-path-error', 'bad\x00path', 'untouched')
    call('parent-file-error', 'parent-file/child', 'untouched', sid=1)
    call('existing-directory-error', 'already-dir', 'untouched')
    call('existing-symlink-error', 'link-existing', 'untouched', sid=1)
    call('dangling-symlink-create', 'link-dangling', 'through symlink\r\n')
    call('absolute-path', str(EFFECTS / 'absolute'), 'absolute', sid=1)
    call('dot-components', './dotparent/../dot-created', 'dots')
    call('trailing-separator-error', 'trailing/', 'untouched', sid=1)
    call('long-file-name-error', 'x' * 256, 'untouched')
    call('lone-cr-preserved', 'lone-cr', 'a\rb\r\nend', sid=1)
    call('multi-write-chunks', 'chunks', ('0123456789abcdef\r\n' * 16384))
    cache('read-multi-chunk-cache', 0, 1, str(EFFECTS / 'chunks'))
    call('cache-exact-limit', 'cache-exact-limit', 'a' * 1048576, sid=1)
    cache('read-exact-limit-cache', 1, 1, str(EFFECTS / 'cache-exact-limit'))
    call('cache-over-limit', 'cache-over-limit', 'b' * 1048577)
    cache('read-over-limit-cache', 0, 1, str(EFFECTS / 'cache-over-limit'))
    call('normalized-cache-at-limit', 'normalized-cache-at-limit', '\r\n' * 1048576)
    cache('read-normalized-limit-cache', 0, 1, str(EFFECTS / 'normalized-cache-at-limit'))
    cache('poison-own-cache', 0, 9)
    call('create-with-poisoned-cache', 'poisoned-create', 'file still created\r\n')
    cache('read-poisoned-cache', 0, 1, str(EFFECTS / 'poisoned-create'))
    cache('other-session-cache-survives-poison', 1, 1, key)
    if PROFILE == 'capabilities':
        rows = [row for row in rows if row.get('typed_refusal')]
        key = 'io.modelcontextprotocol/clientCapabilities'
        meta = lambda name: {key:{'experimental':{'session':{'workdir':str(EFFECTS / name)}}}}
        for row in rows:
            row['metadata'] = meta('workdir-a')
        call('first-context-missing-content', 'missing', '', missing=True)
        rows[-1]['metadata'] = meta('workdir-a')
        call('relative-in-applied-context', 'created', 'first context\r\n')
        rows[-1]['metadata'] = meta('workdir-b')
        call('other-context-accepted', 'created', 'second context\n', sid=1)
        rows[-1]['metadata'] = meta('workdir-b')
        cache('first-context-cache', 0, 1, str(EFFECTS / 'workdir-a/created'))
        cache('second-context-cache', 1, 1, str(EFFECTS / 'workdir-b/created'))
        cache('first-cannot-see-second-cache', 0, 1, str(EFFECTS / 'workdir-b/created'))
        call('later-context-ignored', 'created', 'not overwritten', sid=1)
        rows[-1]['metadata'] = meta('workdir-a')
    return rows


def setup_effects():
    EFFECTS.mkdir()
    (EFFECTS / 'workdir-a').mkdir()
    (EFFECTS / 'workdir-b').mkdir()
    (EFFECTS / 'parent-file').write_bytes(b'parent sentinel\n')
    (EFFECTS / 'already-dir').mkdir()
    (EFFECTS / 'existing-target').write_bytes(b'original target\n')
    (EFFECTS / 'link-existing').symlink_to('existing-target')
    (EFFECTS / 'link-dangling').symlink_to('dangling-target')


def filesystem_snapshot(label):
    destination = OUT / (label + '-filesystem')
    destination.mkdir()
    result = []
    hardlink_groups = {}
    for p in sorted(EFFECTS.rglob('*')):
        relative = p.relative_to(EFFECTS)
        info = p.lstat()
        row = dict(path=str(relative), mode=stat.S_IMODE(info.st_mode))
        if p.is_symlink():
            row.update(kind='symlink', target=os.readlink(p))
        elif p.is_dir():
            row.update(kind='directory')
        else:
            assert stat.S_ISREG(info.st_mode), str(p)
            raw = p.read_bytes()
            saved = destination / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(raw)
            row.update(kind='file', bytes=len(raw), sha256=sha(raw), links=info.st_nlink)
            hardlink_groups.setdefault((info.st_dev,info.st_ino),[]).append(row)
        result.append(row)
    for group in hardlink_groups.values():
        paths = sorted(row['path'] for row in group)
        for row in group:row['hardlink_peers'] = paths
    (OUT / (label + '-filesystem.json')).write_bytes(encode(result))
    return result


def execute(label, command, wire, timeout, cwd):
    (OUT / (label + '.stdin')).write_bytes(wire)
    environment = {k:v for k,v in os.environ.items() if not k.startswith('HEPTA_EFFECT_OWNER_')}
    if FENCE_REQUIRED:
        environment['HEPTA_EFFECT_OWNER_FENCE_REQUIRED'] = '1'
    start = time.monotonic()
    timed = False
    with (OUT / (label + '.stdout')).open('xb') as stdout, (OUT / (label + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(list(map(str, command)), cwd=cwd, stdin=subprocess.PIPE,
                                   stdout=stdout, stderr=stderr, env=environment, start_new_session=True)
        try:
            process.communicate(wire, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed = True
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    row = dict(name=label, command=list(map(str, command)), cwd=str(cwd), pid=process.pid,
               exit_code=process.returncode, timed_out=timed, timeout_seconds=timeout,
               elapsed_seconds=time.monotonic() - start, controlled_effect_fence={k:v for k,v in environment.items() if k.startswith('HEPTA_EFFECT_OWNER_')})
    for stream in ('stdin', 'stdout', 'stderr'):
        p = OUT / (label + '.' + stream)
        raw = p.read_bytes()
        row[stream] = dict(path=p.name, bytes=len(raw), sha256=sha(raw))
    (OUT / (label + '-process.json')).write_bytes(encode(row))
    print(json.dumps({k: row[k] for k in ('name', 'exit_code', 'timed_out', 'elapsed_seconds')}), flush=True)
    assert not timed and process.returncode == 0, row
    return (OUT / (label + '.stdout')).read_bytes()


class TypedInput:
    def __init__(self):
        sys.path.insert(0, str(SOURCE / 'scripts'))
        from hia_native_loader import NativeModule
        metadata = json.loads(MEMBERS.read_bytes())
        self.members = {name: metadata[name] for name in ('serde_json_span',)}
        self.modules = {name: NativeModule(row['manifest'], manifest_sha256=row['manifest_sha256'])
                        for name, row in self.members.items()}
        self.capture = gzip.open(OUT / 'typed-calls.bin.gz', 'wb', compresslevel=1)
        self.index = []
        self.offset = 0

    def leaf(self, name, case, wire):
        header = 32 if name == 'serde_json_span' else 128
        needed_at = 24 if header == 32 else 80
        before = bytes(16512 if header == 32 else 32768)
        capacity = header
        for _ in range(24):
            with self.modules[name].session(workspace_capacity=len(before), output_capacity=capacity) as session:
                ctypes.memmove(session._workspace, before, len(before))
                ctypes.memset(session._output, 0xa5, capacity)
                code, output, after = session.invoke_raw(wire)
            record = Q(code, len(wire), len(before), capacity) + wire + before + b'\xa5' * capacity + output + after
            self.capture.write(record)
            self.index.append(dict(case=case, owner=name, offset=self.offset, bytes=len(record), sha256=sha(record), return_code=code))
            self.offset += len(record)
            assert code == header, (case, name, code)
            status = U(output, 8)
            if status == 2:
                needed = U(output, needed_at)
                assert needed > len(before)
                before = after + bytes(needed - len(after))
                continue
            if status == 3:
                needed = U(output, needed_at)
                assert needed > capacity
                capacity, before = needed, after
                continue
            assert status == 0, (case, name, status)
            body = U(output, 16) if header == 32 else sum(U(output, a) for a in (24, 40, 48, 56))
            assert output[header + body:] == b'\xa5' * (capacity - header - body)
            return output[:header + body]
        raise AssertionError(('typed growth did not complete', case))

    def request(self, row):
        raw = encode(row['parameters']).rstrip(b'\n')
        value = self.leaf('serde_json_span', row['id'], b'HJSMS002' + Q(1, len(raw)) + raw)[32:]
        metadata = row.get('metadata')
        meta = b''
        if metadata is not None:
            raw = encode(metadata).rstrip(b'\n')
            meta = raw
        return b'HTEWGQ03' + Q(1, len(value), int(metadata is not None), len(meta), 0) + value + meta

    def close(self):
        self.capture.close()
        (OUT / 'typed-calls-index.json').write_bytes(encode(self.index))
        (OUT / 'typed-members.json').write_bytes(encode(self.members))


def decode_records(raw):
    cursor = 0
    result = []
    while cursor < len(raw):
        assert raw[cursor:cursor + 8] == b'HFSFXR02'
        assert cursor + 104 <= len(raw)
        fields = struct.unpack_from('<12Q', raw, cursor + 8)
        sid, slot, code, size = fields[:4]
        assert cursor + 104 + size <= len(raw)
        body = raw[cursor + 104:cursor + 104 + size]
        result.append(dict(session=sid, slot=slot, code=code, output=body,
                           counters=fields[4:10], workspace_capacity=fields[10], output_capacity=fields[11]))
        cursor += 104 + size
    assert cursor == len(raw)
    return result


def canonical_snapshot(record):
    assert record['slot'] == 33 and record['code'] == 0
    raw = record['output']
    assert raw[:8] == b'HFSOBS02' and raw[48:64] == bytes(16)
    sizes = [U(raw, at) for at in (8, 16, 24, 32, 40)]
    assert sizes[2:] == [64, 256, 256] and sum(sizes) + 64 == len(raw)
    cursor, parts = 64, []
    for size in sizes:
        parts.append(raw[cursor:cursor + size])
        cursor += size
    session, cache, context, scope, lease = parts
    assert session[:8] == b'HRSWST02' and U(session,48) == 1 and U(session,56) == 0
    root_size, current_size = U(session,8), U(session,16)
    present, poisoned_session, applied = (U(session,at) for at in (24,32,40))
    assert present in (0,1) and poisoned_session in (0,1) and applied in (0,1)
    assert len(session) == 64 + root_size + current_size
    assert present or current_size == 0
    root = session[64:64+root_size].decode()
    current = session[64+root_size:].decode() if present else None
    session_state = dict(root=root,current=current,poisoned=bool(poisoned_session),
                         session_applied=bool(applied),effective=root if poisoned_session or current is None else current)
    assert context == bytes(64)
    assert U(scope, 24) == U(scope, 56) == U(scope, 64) == 0
    assert lease[:8] == b'HRCLST01' and U(lease, 24) == 1 and U(lease, 32) == 1
    assert cache[:8] == b'HVCSTA01' and U(cache, 8) == 1 and U(cache, 16) == len(cache)
    assert cache[40:64] == bytes(24)
    count, poisoned = U(cache, 24), U(cache, 32)
    assert poisoned in (0, 1)
    entries, cursor = [], 64
    for _ in range(count):
        key_len, value_len = U(cache, cursor), U(cache, cursor + 8)
        cursor += 16
        assert cursor + key_len + value_len <= len(cache)
        key = cache[cursor:cursor + key_len]
        value = cache[cursor + key_len:cursor + key_len + value_len]
        key.decode(); value.decode()
        entries.append((key, value))
        cursor += key_len + value_len
    assert cursor == len(cache) and len({key for key, _ in entries}) == count
    body = b''.join(Q(len(key), len(value)) + key + value for key, value in sorted(entries))
    canonical = b'HLCSCS01' + Q(48 + len(body), 1, poisoned, count, len(body)) + body
    return canonical, dict(scope_generation=U(scope, 16), scope_phase=U(scope, 24),
                           lease_count=U(lease, 32), cache_bytes=len(cache), cache_entries=count,
                           cache_poisoned=poisoned, session_sha256=sha(session), session_state=session_state)


def main():
    OUT.mkdir(exist_ok=False)
    source_before = identities(SOURCE)
    reference_before = identities(REFERENCE)
    manifest = BUILD_MANIFEST
    metadata = json.loads(manifest.read_bytes())
    binary = manifest.parent / metadata['elf']
    assert sha(binary.read_bytes()) == metadata['elf_sha256']
    original_build = json.loads((ORIGINAL / 'BUILD.json').read_bytes())
    original_binary = Path(original_build['binary'])
    assert sha(original_binary.read_bytes()) == original_build['sha256']
    (OUT / 'source-closure.json').write_bytes(encode(source_before))
    (OUT / 'reference-closure.json').write_bytes(encode(reference_before))
    rows = cases()
    (OUT / 'cases.jsonl').write_bytes(b''.join(encode(row) for row in rows))
    typed = TypedInput()
    requests = []
    for row in rows:
        slot = 37 if row['kind'] == 'call' else 32
        wire = typed.request(row) if slot == 37 else bytes.fromhex(row['wire_hex'])
        requests.append(b'HFSFXQ02' + Q(row['session'], slot, len(wire)) + wire)
        requests.extend(b'HFSFXQ02' + Q(sid, 33, 0) for sid in (0, 1))
        requests.append(b'HFSFXQ02' + Q(0, 41, 0))
    typed.close()
    setup_effects()
    config = OUT / 'runtime-config.json'
    if CONFIGURED:
        config.write_bytes(encode(dict(state_dir=str(OUT / 'controller-state'), controller_workspace_roots=[str(EFFECTS)] if PROFILE == 'configured' else [], hosts={'fixture':dict(ssh_target='uncontacted-gateway-reference',remote_state_dir='/unused-runtime-state',allow_write=True,allowed_read_path_prefixes=['/allowed'],allowed_write_path_prefixes=['/allowed'],protected_path_prefixes=['/allowed/protected'])})))
        config.chmod(0o600)
    native_command = [binary] + (['--runtime-config', config] if CONFIGURED else [])
    native_output = execute('native', native_command, b''.join(requests), 60, EFFECTS)
    native_files = filesystem_snapshot('native')
    # Only the newly created, task-owned fixture directory is reset.
    assert EFFECTS.parent == OUT and EFFECTS.name == 'effects'
    shutil.rmtree(EFFECTS)
    setup_effects()
    original_command = [original_binary] + ([config] if CONFIGURED else [])
    original_output = execute('original', original_command, b''.join(encode(row) for row in rows), 60, EFFECTS)
    original_files = filesystem_snapshot('original')
    assert native_files == original_files
    file_bytes = 0
    for row in native_files:
        if row['kind'] == 'file':
            a = (OUT / 'native-filesystem' / row['path']).read_bytes()
            b = (OUT / 'original-filesystem' / row['path']).read_bytes()
            assert a == b, row['path']
            file_bytes += len(a)
    if PROFILE == 'smoke':
        assert (OUT/'native-filesystem/sequence').read_bytes() == b'alpha\r\nline\r\n'
        assert (OUT/'original-filesystem/sequence').read_bytes() == b'alpha\r\nline\r\n'
    native = decode_records(native_output)
    original = [json.loads(line) for line in original_output.splitlines()]
    assert len(native) == 4 * len(rows) and len(original) == len(rows)
    compared, observations = 0, []
    for index, (row, expected) in enumerate(zip(rows, original)):
        primary = native[index * 4]
        assert expected['id'] == row['id'] and primary['session'] == expected['session'] == row['session']
        assert primary['code'] == expected['code'], (row['id'], primary['code'], expected['code'])
        actual = primary['output']; wanted = bytes.fromhex(expected['output_hex'])
        assert actual == wanted, (row['id'], actual[:256], wanted[:256])
        if PROFILE == 'smoke':
            assert U(actual,8) == (0 if index < 5 else 1), ('expected successful declared command',row['id'],U(actual,8))
        compared += len(actual)
        if row.get('typed_refusal'):
            assert actual[:8] == b'HRCFGM01' and U(actual,8) == 2
        assert expected['scope_unbound_after_call'] is True and expected['live_session_arcs'] == [1, 1]
        history = bytes.fromhex(expected['history_snapshot_hex'])
        locks = bytes.fromhex(expected['lock_snapshot_hex'])
        from qualification_support import observations as original_observations
        from qualification_support import native_observations
        shared = native[index * 4 + 3]
        assert shared['slot'] == 41 and shared['code'] == 0
        state = shared['output']
        assert state[:8] == b'HLTBSH01' and U(state,24) in (0,1,2)
        lock_size, history_size = U(state,8), U(state,16)
        assert len(state) == 32 + lock_size + history_size
        actual_locks = native_observations.locks(state[32:32 + lock_size],1,index + 1)
        actual_history = native_observations.history(state[32 + lock_size:],1,index + 1)
        assert actual_locks == original_observations.locks(locks), ('locks',row['id'])
        assert actual_history == original_observations.history(history), ('history',row['id'])
        compared += len(state) + len(history) + len(locks)
        snapshots = []
        for sid in (0, 1):
            record = native[index * 4 + 1 + sid]
            assert record['session'] == sid
            canonical, observation = canonical_snapshot(record)
            wanted = bytes.fromhex(expected['cache_snapshots_hex'][sid])
            assert canonical == wanted, (row['id'], sid, len(canonical), len(wanted))
            compared += len(canonical)
            assert observation['session_state'] == expected['sessions'][sid], (row['id'],sid,observation['session_state'],expected['sessions'][sid])
            if row.get('typed_refusal'):
                assert observation['session_state']['session_applied'] is False
                assert observation['scope_generation'] == 0 and observation['cache_entries'] == 0
            snapshots.append(observation)
        observations.append(dict(id=row['id'], code=primary['code'], result_bytes=len(actual),
                                 counters=primary['counters'], workspace_capacity=primary['workspace_capacity'],
                                 output_capacity=primary['output_capacity'], sessions=snapshots))
    assert source_before == identities(SOURCE) and reference_before == identities(REFERENCE)
    cache_capacities = [r['workspace_capacity'] for r in native if r['slot'] == 32]
    if PROFILE == 'baseline':
        assert max(cache_capacities) > 131072, cache_capacities
    (OUT / 'observations.json').write_bytes(encode(observations))
    summary = dict(status='SERIAL_LOCAL_FOUR_COMMAND_GATEWAY_COMPARISON_PASS', profile=PROFILE, cases=len(rows),
                   typed_refusals=sum(bool(row.get('typed_refusal')) for row in rows),
                   gateway_requests=sum(row['kind'] == 'call' for row in rows), typed_admitted_text_requests=sum(row['kind'] == 'call' and not row.get('typed_refusal') for row in rows), actual_native_records=len(native),
                   typed_native_calls=len(typed.index), typed_full_record_bytes=typed.offset,
                   complete_compared_response_and_cache_bytes=compared, complete_compared_file_bytes=file_bytes,
                   files=len(native_files), maximum_cache_arena=max(cache_capacities,default=0),
                   native_elf=dict(bytes=binary.stat().st_size, sha256=sha(binary.read_bytes())),
                   original_elf=dict(bytes=original_binary.stat().st_size, sha256=sha(original_binary.read_bytes())),
                   exact_target_commit='d3d75c30719db966b004756f610007a7c723729e',
                   original_build_receipts=str(ORIGINAL / 'processes.json'), original_replay_receipt='original-process.json',
                   actual_gateway=True, actual_hia_typed_owner=True, actual_hia_client_context=True, actual_sdk_3_9_context=True,
                   actual_session_state_compared=True, actual_file_effects=True, actual_same_session_cache=True, actual_path_source=True,
                   actual_scope_lease_context=True, complete_files_compared=True, complete_shared_history_compared=True, complete_shared_lock_state_compared=True,
                   serial_domain=True, fixture_transport=True, config_installed=CONFIGURED, fence_required=FENCE_REQUIRED, original_configuration_loader_qualified=False,
                   native_built_members=75, strict_cache_capacity_provenance=True,
                   request_scope_input_over_8mib_qualified=False, full_sdk_router_qualified=False, gateway_arguments_map_domain=True, client_context_mode=0, legacy_peer_info=False, process_wide_statx_cache_qualified=False,
                   cancellation_fence_publication_timing_qualified=False, cancellation_worker_drain_qualified=False,
                   public_text_editor_route=False, production_handler_qualified=False, production_activated=False,
                   whole_runtime_replaced=False)
    (OUT / 'SUMMARY.json').write_bytes(encode(summary))
    print(json.dumps(summary, sort_keys=True), flush=True)



def cases():
    if PROFILE not in ('smoke','body'):
        return legacy_cases()
    rows=[]
    def call(name,command,path,sid=0,**fields):
        rows.append(dict(id=name,kind='call',session=sid,parameters=dict(command='undo_edit' if command=='undo' else command,path=path,**fields)))
    def cache(name,sid,op,key='',value=''):
        rows.append(dict(id=name,kind='cache',session=sid,wire_hex=cache_frame(op,key,value).hex()))
    call('create-sequence','create','sequence',content='alpha\r\nline\r\n')
    call('replace-cross-session','str_replace','sequence',sid=1,old_text='alpha',new_text='beta')
    call('delete-sequence','delete','sequence')
    call('undo-deleted-cross-session','undo','sequence',sid=1)
    call('undo-replaced-cross-session','undo','sequence')
    call('undo-no-more','undo','sequence',sid=1)
    if PROFILE=='smoke':return rows
    call('missing-old','str_replace','sequence',new_text='beta')
    call('missing-new','str_replace','sequence',old_text='alpha')
    call('replace-not-found','str_replace','sequence',old_text='absent',new_text='new')
    call('create-repeat','create','repeat',sid=1,content='same same\nrepeat\n')
    call('multiple-refusal','str_replace','repeat',old_text='same',new_text='unique')
    call('multiple-all','str_replace','repeat',sid=1,old_text='same',new_text='all',replace_all=True)
    call('repeat-undo-cross','undo','repeat')
    call('create-unicode','create','文档😀',content='αβ中文\r\n行二\r\n')
    call('replace-unicode','str_replace','文档😀',sid=1,old_text='αβ中文',new_text='🙂中文')
    call('undo-unicode','undo','文档😀')
    call('create-tabs','create','tabs',content='\tstart\n\tvalue = 1\nend\n')
    call('replace-tabs','str_replace','tabs',sid=1,old_text='value = 1',new_text='value = 2')
    call('undo-tabs','undo','tabs')
    call('literal-create','create','literal',content='a[0].x+(y)\n')
    call('literal-replace','str_replace','literal',sid=1,old_text='[0].x+',new_text='[1].y*')
    call('literal-undo','undo','literal')
    call('empty-create','create','empty-body',content='')
    call('empty-delete','delete','empty-body',sid=1)
    call('empty-undo','undo','empty-body')
    call('missing-delete','delete','does-not-exist',sid=1)
    call('missing-undo','undo','no-history')
    call('directory-delete','delete','already-dir',sid=1)
    call('directory-replace','str_replace','already-dir',old_text='x',new_text='y')
    call('alias-replace','str_replace','link-existing',old_text='original',new_text='modified',sid=1)
    call('alias-undo-target','undo','existing-target')
    call('hardlink-replace','str_replace','hard-a',old_text='alpha',new_text='beta')
    call('hardlink-undo','undo','hard-a',sid=1)
    call('readonly-replace','str_replace','read-only',old_text='alpha',new_text='beta',sid=1)
    call('readonly-undo','undo','read-only')
    call('cache-create','create','cache-cross',content='old\r\nvalue\r\n')
    key=str(EFFECTS/'cache-cross')
    cache('seed-foreign-cache',1,2,key,'foreign\n')
    call('cache-replace-own','str_replace','cache-cross',old_text='old',new_text='new')
    cache('cache-read-own',0,1,key)
    cache('cache-read-other',1,1,key)
    call('cache-undo-other','undo','cache-cross',sid=1)
    cache('cache-read-own-after-foreign-undo',0,1,key)
    cache('cache-read-other-after-undo',1,1,key)
    call('cache-delete-own','delete','cache-cross')
    cache('cache-read-own-after-delete',0,1,key)
    call('cache-undo-delete-other','undo','cache-cross',sid=1)
    call('large-create','create','large',content='a'*1048576+'\n'+'tail\n'*262144)
    call('large-replace','str_replace','large',sid=1,old_text='a'*1048576,new_text='b'*1048576)
    call('large-undo','undo','large')
    call('history-create','create','history',content='value-00\n')
    for i in range(12):
        call('history-replace-%02d'%i,'str_replace','history',sid=i%2,old_text='value-%02d'%i,new_text='value-%02d'%(i+1))
    for i in range(12):
        call('history-undo-%02d'%i,'undo','history',sid=(i+1)%2)
    cache('poison-first-cache',0,9)
    call('poison-replace','str_replace','sequence',old_text='alpha',new_text='beta')
    call('poison-delete','delete','sequence')
    call('poison-undo','undo','sequence',sid=1)
    return rows

_original_setup_effects=setup_effects
def setup_effects():
    _original_setup_effects()
    if PROFILE=='body':
        (EFFECTS/'hard-a').write_bytes(b'alpha\n')
        os.link(EFFECTS/'hard-a',EFFECTS/'hard-b')
        (EFFECTS/'read-only').write_bytes(b'alpha\n')
        (EFFECTS/'read-only').chmod(0o440)

if __name__ == '__main__':
    main()
