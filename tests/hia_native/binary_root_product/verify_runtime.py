"""Actual baseline/product public regression and installed binary-root ABI checks.

All child stdin/stdout/stderr and process outcomes are retained. This domain
does not claim public binary_write or full runtime semantic qualification.
"""
from pathlib import Path
import argparse, gzip, hashlib, json, math, os, re, struct, subprocess, sys, time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests/hia_native'))
from runtime_mcp_public_capture import Public
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *words: struct.pack('<' + 'Q' * len(words), *words)
INVALID = 0xffffffff
ENV = {'PATH': '', 'LC_ALL': 'C'}
TOOLS = ['host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir',
         'directory_create', 'file_move', 'directory_move', 'text_editor', 'batch_edit',
         'extract_lines', 'weight_bellman_plan', 'text_file_write']

def encode(value): return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
def save(path, value): path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
def pin(raw): return {'bytes': len(raw), 'sha256': SHA(raw)}
def executable(manifest):
    model = json.loads(manifest.read_bytes()); binary = manifest.parent / model['elf']
    assert pin(binary.read_bytes()) == {'bytes': model['elf_bytes'], 'sha256': model['elf_sha256']}
    assert model['physical_images'] == 117 and model['runtime_hia_images'] == 124
    assert len(model['members']) == 116 and len(model['extra_table']) == 69
    return binary, model
def host(**extra):
    return dict(ssh_target='private-target', remote_state_dir='/remote', execution_mode='operator',
                allow_write=True, allowed_read_path_prefixes=['/data'], allowed_write_path_prefixes=['/write'], **extra)
def config(path, workspace, hosts):
    value = {'state_dir': str(path.parent / 'state'), 'controller_workspace_roots': [str(workspace)], 'hosts': hosts}
    save(path, value)
    return path
def snapshot(root):
    rows = {}
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        rows[str(p.relative_to(root))] = {'mode': st.st_mode, 'inode': st.st_ino,
             'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns,
             'content': pin(p.read_bytes()) if p.is_file() else None}
    return rows

def public_inputs():
    invalid = [
      {'unexpected': True}, {'unexpected': True}, {'record': False}, {'path': False}, {'reset': 'yes'},
      {'path': False}, {'source': False, 'destination': 'dest'}, {'source': False, 'destination': 'dest'},
      {'command': False, 'path': 'seed.txt'}, {'path': 'seed.txt', 'operations': False},
      {'from_path': False, 'from_start': 1, 'append_path': 'occupied.txt', 'append_line': -1},
      {'states': False}, {'path': False, 'mode': 'create', 'content': '', 'expected_sha256': 'absent'}]
    body = [
      {}, {}, {'record': {}}, {'path': 'seed.txt', 'full': True}, {'reset': True}, {'path': 'existing'},
      {'source': 'missing', 'destination': 'dest'}, {'source': 'missing', 'destination': 'dest'},
      {'command': 'str_replace', 'path': 'seed.txt', 'old_text': 'absent needle', 'new_text': 'value'},
      {'path': 'seed.txt', 'operations': []},
      {'from_path': 'seed.txt', 'from_start': 0, 'append_path': 'occupied.txt', 'append_line': -1},
      {'states': [{'actions': [{'kind': 'terminal', 'value': 1.0}, None, None, None, None, None]}]},
      {'path': 'seed.txt', 'mode': 'create', 'content': 'new', 'expected_sha256': 'absent'}]
    return [(name + '-typed', name, args) for name, args in zip(TOOLS, invalid, strict=True)] + [
           (name + '-body', name, args) for name, args in zip(TOOLS, body, strict=True)] + [
           ('binary-write-remains-unrouted', 'binary_write',
            {'host': 'h', 'path': '/write/file', 'data_base64': '', 'expected_version': 'absent'})]

def public_regression(out, baseline, candidate):
    area = out / 'public'; area.mkdir()
    workspace = area / 'workspace'; workspace.mkdir()
    (workspace / 'seed.txt').write_bytes(b'alpha\nbeta\n')
    (workspace / 'occupied.txt').write_bytes(b'occupied\n')
    (workspace / 'existing').mkdir()
    cfg = config(area / 'config.json', workspace, {'h': host()})
    initial = snapshot(workspace); records = []; timing_observations = []
    for profile in ('configured', 'absent'):
        for era in ('legacy', 'modern'):
            replies = {}
            for lane, binary in (('baseline', baseline), ('candidate', candidate)):
                folder = area / (profile + '-' + era + '-' + lane)
                client = Public(folder, binary, workspace, cfg if profile == 'configured' else None)
                response_rows = []; success = False
                def exchange(value, expected=1):
                    raw = client.exchange(encode(value) + b'\n', expected)
                    response_rows.extend(raw)
                    return json.loads(raw[0]) if expected else None
                meta = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                        'io.modelcontextprotocol/clientInfo': {'name': 'binary-root-regression', 'version': '1'},
                        'io.modelcontextprotocol/clientCapabilities': {}}
                try:
                    exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                       'protocolVersion': '2025-11-25', 'capabilities': {},
                       'clientInfo': {'name': 'binary-root-regression', 'version': '1'}}})
                    exchange({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, 0)
                    listing = exchange({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list',
                                        'params': {'_meta': meta} if era == 'modern' else {}})
                    assert len(listing['result']['tools']) == (11 if profile == 'configured' else 8)
                    cases = []
                    for index, (label, name, arguments) in enumerate(public_inputs(), 10):
                        params = {'name': name, 'arguments': arguments}
                        if era == 'modern': params['_meta'] = meta
                        result = exchange({'jsonrpc': '2.0', 'id': index, 'method': 'tools/call', 'params': params})
                        assert result['id'] == index
                        if name == 'binary_write':
                            assert result.get('error') == {'code': -32602, 'message': 'Unknown tool'}
                        else:
                            assert result.get('error', {}).get('message') != 'Unknown tool', label
                            if label.endswith('-typed'):
                                assert 'error' in result or result.get('result', {}).get('isError') is True, label
                        cases.append({'name': label, 'tool': name, 'response': result})
                    assert snapshot(workspace) == initial, 'Read/refusal regression changed workspace bytes or identities'
                    save(folder / 'cases.json', cases)
                    success = True
                finally:
                    client.close(failed=not success)
                replies[lane] = response_rows
                records.append({'profile': profile, 'era': era, 'lane': lane, 'responses': len(response_rows),
                                'process': client.receipt, 'cases': str((folder / 'cases.json').relative_to(out))})
            assert len(replies['baseline']) == len(replies['candidate'])
            for index, (before, after) in enumerate(zip(replies['baseline'], replies['candidate'], strict=True)):
                # The actual Bellman worker deliberately reports its own elapsed
                # duration. Retain both values and admit exactly this one numeric
                # token in the one successful Bellman request, never arbitrary
                # numbers, timing fields, PIDs, whitespace, or JSON normalization.
                if index == 26:
                    values = []
                    normalized = []
                    for raw in (before, after):
                        response = json.loads(raw)
                        assert response['id'] == 34 and response['result']['isError'] is False
                        content = response['result']['content']
                        assert len(content) == 1 and content[0]['type'] == 'text'
                        body = json.loads(content[0]['text'])
                        elapsed = body['native_operation_wall_seconds']
                        assert type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed < 60
                        pattern = rb'(\\"native_operation_wall_seconds\\":)([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
                        hits = list(re.finditer(pattern, raw)); assert len(hits) == 1
                        assert float(hits[0][2]) == elapsed
                        normalized.append(re.sub(pattern, rb'\g<1>0', raw, count=1))
                        values.append(elapsed)
                    assert normalized[0] == normalized[1], (profile, era, 'Bellman result differs beyond its measured duration')
                    timing_observations.append({'profile': profile, 'era': era, 'request_id': 34,
                       'field': 'result.content[0].text.native_operation_wall_seconds',
                       'baseline': values[0], 'candidate': values[1]})
                else:
                    assert before == after, (profile, era, index, 'complete wire differs')
    return {'status': 'PASS', 'routed_tools': TOOLS, 'processes': len(records),
            'response_pairs': sum(r['responses'] for r in records if r['lane'] == 'baseline'),
            'profiles': ['configured', 'absent'], 'eras': ['legacy', 'modern'],
            'complete_wire_equal_except_one_bellman_duration_token': True,
            'retained_bellman_duration_observations': timing_observations,
            'workspace_identity_unchanged': True, 'records': records}

def query(name='h', path='/data', write=0, op=9):
    a, b = name.encode(), path.encode()
    return b'HRCFGQ01' + PACK(op, 40 + len(a) + len(b), 0, 0, write, len(a), len(b)) + a + b
def answer(status, payload):
    raw = payload.encode(); return b'HRCFGM01' + PACK(status, 0, len(raw)) + raw
def exact(name, path, root, write=0): return (name, query(path=path, write=write), answer(0, root))
def error(name, path, text, write=0, host_name='h'):
    return (name, query(host_name, path, write), answer(1, text))
def malformed():
    base = query(); rows = []
    for name, at, value in [('user', 24, 1), ('port', 32, 1), ('write', 40, 2),
        ('host-overflow', 48, (1 << 64) - 1), ('path-overflow', 56, (1 << 64) - 1),
        ('host-length', 48, 0), ('path-length', 56, 0), ('payload-length', 16, 0), ('opcode10', 8, 10)]:
        raw = bytearray(base); struct.pack_into('<Q', raw, at, value); rows.append((name, bytes(raw), None))
    for name, at in [('host-utf8', 64), ('path-utf8', len(base) - 1), ('magic', 0)]:
        raw = bytearray(base); raw[at] = 0xff; rows.append((name, bytes(raw), None))
    rows += [('short-bridge', b'HRCFGQ01', None), ('short-owner', b'HRCFGQ01' + PACK(9, 0), None)]
    return rows
def old_queries():
    return [('old-op' + str(op), b'HRCFGQ01' + PACK(op, 0), 'compare') for op in (1, 2, 6, 7)] + [
       ('old-path-read', query(path='/data/x', op=8), 'compare'),
       ('old-path-traversal', query(path='/data/../x', op=8), 'compare')]
def root_domains():
    h = host(); h['allowed_read_path_prefixes'] = ['/data', '/data/nested', '/data/nested/', '/é', '/é/文']
    h['allowed_write_path_prefixes'] = ['/write', '/write/nest', '/write/nest//']
    rows = [exact('read-root', '/data', '/data'), exact('read-child', '/data/nested/file', '/data/nested/'),
            exact('write-child', '/write/nest/file', '/write/nest//', 1), exact('unicode', '/é/文/x', '/é/文'),
            exact('embedded-nul', '/data/\0file', '/data'),
            error('relative', 'relative', 'remote file access requires an absolute target path'),
            error('traversal', '/data/../x', 'remote path traversal is not allowed'),
            error('prefix-boundary', '/database', 'path `/database` is outside configured read roots on host `h`'),
            error('unknown-before-path', 'relative', 'unknown host `missing`; call host_list for configured names', host_name='missing'),
            error('alias-not-name', '/data', 'unknown host `private-target`; call host_list for configured names', host_name='private-target')]
    yield 'operator', {'h': h}, rows + malformed() + old_queries()
    yield 'absent', None, [error('missing-config', '/data', 'runtime tools are disabled; start with --runtime-config <file>'),
                          error('missing-before-host', 'relative', 'runtime tools are disabled; start with --runtime-config <file>', host_name='missing')] + malformed()[:3] + old_queries()
    isolated = host(); isolated['execution_mode'] = 'isolated'
    yield 'isolated', {'h': isolated}, [error('operator-before-path', 'relative', 'native binary tools require an operator host'),
       error('operator-before-write', '/write', 'native binary tools require an operator host', 1)] + old_queries()
    disabled = host(); disabled['allow_write'] = False
    yield 'disabled', {'h': disabled}, [error('disabled-write', '/write/x', 'remote writes are disabled for host `h`', 1),
        error('path-before-disabled', 'relative', 'remote file access requires an absolute target path', 1),
        error('traversal-before-disabled', '/write/../x', 'remote path traversal is not allowed', 1)] + old_queries()
    a, z = host(), host(); a.update(ssh_target='z', execution_mode='isolated', allow_write=False,
        allowed_read_path_prefixes=['/alias', '/named', '/secret'], protected_path_prefixes=['/secret'])
    z.update(ssh_target='z-alias', allowed_read_path_prefixes=['/named', '/secret'])
    yield 'alias-collision', {'a': a, 'z': z}, [
       ('named-root', query('z', '/named/x'), answer(0, '/named')),
       error('named-roots-after-alias-policy', '/alias/x', 'file outside configured roots', host_name='z'),
       error('protected-alias', '/secret/x', 'path `/secret/x` is protected by prefix `/secret` on host `a`', host_name='z'),
       error('write-policy-alias', '/write/x', 'remote writes are disabled for host `a`', 1, 'z')]
    raw = host(); raw['allowed_read_path_prefixes'] = ['/', '/a', '/a/', '/a//', '/a///', '/é', '/é/文']
    yield 'raw-prefix', {'h': raw}, [exact('exact-path', '/a', '/a'), exact('raw-longest', '/a/x', '/a///'),
          exact('utf8-length', '/é/文/x', '/é/文'), exact('root-slash', '/other', '/')]
    long = '/' + 'p' * 18000
    large = host(); large['allowed_read_path_prefixes'] = [long]
    yield 'growth', {'h': large}, [exact('growing-root', long + '/x', long), exact('same-owner-second-session', long, long)]

def fixture_run(out, binary, workspace, cfg, rows):
    out.mkdir()
    wire = b''.join(b'HFSFXQ02' + PACK(i % 2, 11, len(row[1])) + row[1] for i, row in enumerate(rows))
    command = [str(binary)] + ([] if cfg is None else ['--runtime-config', str(cfg)])
    started = time.monotonic(); code = None; timed = False; stdout = stderr = b''
    try:
        p = subprocess.run(command, input=wire, cwd=workspace, env=ENV, capture_output=True, timeout=60)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        timed = True; stdout, stderr = exc.stdout or b'', exc.stderr or b''
        raise
    finally:
        for name, raw in [('stdin', wire), ('stdout', stdout), ('stderr', stderr)]:
            (out / (name + '.bin.gz')).write_bytes(gzip.compress(raw, mtime=0))
        save(out / 'process.json', {'command': command, 'cwd': str(workspace), 'environment': ENV,
            'exit_code': code, 'timed_out': timed, 'timeout_seconds': 60, 'elapsed_seconds': time.monotonic() - started,
            'stdin': pin(wire), 'stdout': pin(stdout), 'stderr': pin(stderr)})
    assert code == 0 and not timed
    parsed = []; at = 0
    for i, row in enumerate(rows):
        head = stdout[at:at + 104]; assert len(head) == 104 and head[:8] == b'HFSFXR02'
        words = struct.unpack('<13Q', head); assert words[1:3] == (i % 2, 11)
        extent = words[4]; body = stdout[at + 104:at + 104 + extent]
        assert len(body) == extent and extent <= words[12]
        parsed.append({'name': row[0], 'code': words[3], 'extent': extent, 'body': body.hex(),
                       'counters': list(words[5:11]), 'workspace_capacity': words[11], 'output_capacity': words[12]})
        at += 104 + extent
    assert at == len(stdout)
    assert len(stderr) % 224 == 0
    traces = []
    for at in range(0, len(stderr), 224):
        trace = stderr[at:at + 224]; assert trace[:8] == b'HRGTR002'
        traces.append(struct.unpack('<9Q', trace[8:80]))
    save(out / 'responses.json', parsed)
    return parsed, traces

def root_regression(out, baseline, candidate):
    area = out / 'root'; area.mkdir(); records = []
    for name, hosts, rows in root_domains():
        folder = area / name; folder.mkdir(); workspace = folder / 'workspace'; workspace.mkdir()
        cfg = None if hosts is None else config(folder / 'config.json', workspace, hosts)
        save(folder / 'inputs.json', [{'name': r[0], 'frame_hex': r[1].hex(),
              'expectation': r[2].hex() if isinstance(r[2], bytes) else r[2]} for r in rows])
        actual, traces = fixture_run(folder / 'candidate', candidate, workspace, cfg, rows)
        retained = [r for r in rows if r[2] == 'compare']
        old = []
        if retained: old, _ = fixture_run(folder / 'baseline', baseline, workspace, cfg, retained)
        old_by_name = {r['name']: r for r in old}
        for spec, result in zip(rows, actual, strict=True):
            expected = spec[2]
            if expected == 'compare':
                before = old_by_name[spec[0]]
                assert [result[k] for k in ('code', 'extent', 'body')] == [before[k] for k in ('code', 'extent', 'body')], (name, spec[0])
            elif expected is None:
                assert result['code'] == INVALID and result['extent'] == 0, (name, spec[0], result)
            else:
                assert result['code'] == result['extent'] == len(expected) and result['body'] == expected.hex(), (name, spec[0], result)
        if name == 'growth':
            assert actual[0]['output_capacity'] > 4096 and actual[1]['output_capacity'] > 4096
            assert any(t[1] == 11 and t[3] == 0xffffffd0 for t in traces), 'No actual owner growth observed'
        records.append({'group': name, 'candidate_queries': len(rows), 'retained_operation_pairs': len(retained),
                        'trace_records': len(traces), 'responses': str((folder / 'candidate/responses.json').relative_to(out))})
    # The old product rejects the same ordinary op9 that the candidate executes.
    control = [('previously-unrouted-op9', query(), None)]
    folder = area / 'old-op9-rejection'; folder.mkdir(); workspace = folder / 'workspace'; workspace.mkdir()
    cfg = config(folder / 'config.json', workspace, {'h': host()})
    previous, _ = fixture_run(folder / 'baseline', baseline, workspace, cfg, control)
    assert previous[0]['code'] == INVALID and previous[0]['extent'] == 0
    return {'status': 'PASS', 'groups': records,
            'candidate_queries': sum(r['candidate_queries'] for r in records),
            'retained_operation_pairs': sum(r['retained_operation_pairs'] for r in records),
            'actual_output_growth': True, 'shared_installed_config_two_sessions': True,
            'baseline_rejects_operation9': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'baseline-fixture', 'candidate-fixture', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(exist_ok=False)
    report = {'status': 'RUNNING', 'public_binary_write_qualified': False, 'full_runtime_qualified': False}
    try:
        binaries = {}
        for name in ('baseline', 'candidate', 'baseline_fixture', 'candidate_fixture'):
            binary, model = executable(getattr(args, name).resolve())
            binaries[name] = binary
            report[name] = {'manifest': str(getattr(args, name).resolve()), 'elf': pin(binary.read_bytes())}
        assert report['baseline']['elf']['sha256'] == 'cfc51c7004da6dd45d7d42314188563b6e83c6b03df4478a2281ef0b5d750755'
        report['public'] = public_regression(out, binaries['baseline'], binaries['candidate'])
        report['root'] = root_regression(out, binaries['baseline_fixture'], binaries['candidate_fixture'])
        report['status'] = 'PASS'
    except BaseException as exc:
        report.update(status='FAIL', error=repr(exc))
        raise
    finally:
        save(out / 'RESULT.json', report)
    print(json.dumps({k: v for k, v in report.items() if k not in ('public', 'root')}, sort_keys=True))
if __name__ == '__main__': main()
