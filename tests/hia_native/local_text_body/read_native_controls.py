"""Strict readers for every complete native compatibility/capability record."""
from pathlib import Path
import argparse
import gzip
import hashlib
import io
import itertools
import json
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_support import ROOT, PIN, SHA, decode, require, regular, source_evidence
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_local_text_body_build import verify_build

Q = lambda *values: struct.pack('<' + 'Q' * len(values), *values)
U = lambda raw, offset: struct.unpack_from('<Q', raw, offset)[0]


def read_compat(folder):
    folder = Path(folder)
    report_raw = regular(folder, 'result.json'); report = decode(report_raw)
    stream = regular(folder, 'complete-calls.bin.gz')
    require(report['status'] == 'PASS' and report['legacy_cases'] == 384
            and report['namespace_controls'] == 15 and report['metadata_cases'] == 21
            and report['actual_native_calls'] == 4808 and report['original_processes'] == 0
            and report['complete_output_and_workspace_compared'] is True
            and report['full_body_async_qualified'] is False
            and report['old_source'] == 'f538f3c484922f54d776f757c94b98c66cc616bd4668006b0380530eae72bc12'
            and report['new_source'] == 'a4eacfcdae04233097a2d37ae15447b2e6e99dd5325e98b409b4404896786df0'
            and PIN(stream) == dict(bytes=report['stream_bytes'], sha256=report['stream_sha256']),
            'body complete read compatibility receipt differs')
    paths = [b'file', b'', b'raw-\xff', b'bad\0path', b'long/' + b'x' * 129]
    frames = []
    for ordinal, (op, cache, plan, content) in enumerate(itertools.product((1, 2), range(3), range(8), range(8))):
        path = paths[ordinal % len(paths)]
        frames.append((b'HFLRIO01' + Q(op, len(path), 0, 0, 0, 0, 0) + path, 2, None))
    for op in (0, 3, 4, 5, 7, 15, 255, 65536, (1 << 64) - 1):
        frames.append((b'HFLRIO01' + Q(op, 1, 0, 0, 0, 0, 0) + b'x', 2, 'invalid'))
    for op in (0, 1, 2, 4, 5, (1 << 64) - 1):
        frames.append((b'HFLRMQ01' + Q(op, 1, 0, 0, 0, 0, 0) + b'x', 1, 'invalid'))
    for _plan, mode in itertools.product(range(7), (0, 0o100644, 0o40755)):
        frames.append((b'HFLRMQ01' + Q(3, 4, 0, 0, 0, 0, 0) + b'file', 1,
                       b'HFLRO001' + Q(3, 0, 16, 7, mode)))
    calls = records = total = 0
    digest = hashlib.sha256()
    with gzip.GzipFile(fileobj=io.BytesIO(stream), mode='rb') as source:
        for frame, weight, expected in frames:
            for _step in range(1000):
                header = source.read(32)
                require(len(header) == 32, 'body read trace omitted a complete call')
                extent, code, out_size, work_size = struct.unpack('<4Q', header)
                require(extent == len(frame) and code <= 0xffffffff
                        and 0 <= out_size <= 134217728 and 0 <= work_size <= 268435456,
                        'body read trace span differs')
                raw = source.read(extent + out_size + work_size)
                require(len(raw) == extent + out_size + work_size and raw[:extent] == frame,
                        'body read complete input/buffers differ')
                digest.update(header); digest.update(raw); total += 32 + len(raw)
                out = raw[extent:extent + out_size]; work = raw[extent + out_size:]
                records += 1; calls += weight
                if code in (0xffffffef, 0xffffffe8, 0xfffffff0):
                    require(expected != 'invalid' and work_size >= 2048, 'invalid read namespace executed an effect')
                    continue
                if expected == 'invalid':
                    require(code == 0xffffffff and out == b'\xa7' * 97 and work == bytes(2048),
                            'body read namespace refusal mutated complete buffers')
                elif expected is not None:
                    require(code == len(expected) and out[:code] == expected, 'body metadata result differs')
                else:
                    require(code < 0xffff0000 and code <= len(out), 'body ordinary read did not complete')
                break
            else:
                raise ValueError('body read trace exceeded its unchanged effect bound')
        require(source.read(1) == b'', 'body read trace retained an extra source case/call')
    require(calls == 4808, 'body actual read call accounting differs')
    return dict(legacy_cases=384, namespace_controls=15, metadata_cases=21,
                actual_native_calls=calls, full_trace_records=records, full_trace_bytes=total,
                full_trace_sha256=digest.hexdigest(), artifact_sha256={
                    'result.json': SHA(report_raw), 'complete-calls.bin.gz': SHA(stream)})


def capabilities(folder, manifest):
    folder = Path(folder)
    raw = regular(folder, 'result.json'); report = decode(raw)
    events_raw = regular(folder, 'events.json'); events = decode(events_raw)
    build = verify_build(manifest, source_root=ROOT)
    require(report['status'] == 'PASS' and report['original_processes'] == 0
            and report['actual_export_calls'] == 45 and report['actual_explicit_owner_calls'] == 11
            and report['complete_retained_blobs'] == 82 and report['callback_exception'] is None
            and report['build_verification'] == build and report['full_body_async_qualified'] is False
            and report['public_handler_qualified'] is False, 'body export capability report differs')
    artifacts = {'result.json': SHA(raw), 'events.json': SHA(events_raw)}
    blobs = set()
    def blob(value):
        require(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}, 'body full capability span differs')
        name = 'blobs/' + value['path']; raw = regular(folder, name)
        require(value == dict(path=SHA(raw) + '.bin', **PIN(raw)), 'body complete capability bytes differ')
        artifacts[name] = SHA(raw); blobs.add(value['path']); return raw
    expected = [('owner', 3, 64), ('owner', 6, 64), ('owner', 8, 32)]
    expected += [('export', 'run', 0xffffffff)] * 14
    expected += [('export', name, code) for _ in range(4) for name, code in (('run', 0xffffffff), ('release', 0))]
    expected += [('owner', 3, 64), ('owner', 3, 64), ('export', 'run', 0xffffffdf),
        ('export', 'release', 16), ('export', 'run', 0xffffffff),
        *[('export', 'resume', 0xffffffdf)] * 3, ('export', 'cancel_wait', 0xfffffff7),
        ('export', 'release', 0), ('export', 'resume', 0xffffffff), ('export', 'cancel_wait', 0xffffffff),
        ('owner', 3, 64), ('owner', 3, 64), ('owner', 3, 64), ('export', 'run', 0xffffffdf),
        ('owner', 3, 64), ('owner', 8, 32), ('export', 'resume', 57), ('export', 'release', 0)]
    expected += [('export', name, code) for _ in range(4) for name, code in (('run', 0xfffffffc), ('release', 0))]
    expected += [('owner', 8, 32), ('export', 'run', 8255), ('export', 'release', 0)]
    require([(e['kind'], e.get('function', e.get('owner')), e['code']) for e in events] == expected,
            'body actual capability call order/return differs')
    import native_observations
    request_lengths = []
    for index, event in enumerate(events):
        source = blob(event['input']); out = blob(event['output'])
        if event['kind'] == 'owner':
            before = blob(event['workspace_before']); after = blob(event['workspace_after'])
            require(event['code'] == len(out) and len(after) >= len(before), 'body complete explicit owner span differs')
        else:
            before = blob(event['context_before']); after = blob(event['context_after'])
            require(len(before) == len(after) == 192, 'body complete callable context size differs')
            lock = blob(event['lock_state']); history = blob(event['history_state']); cache = blob(event['cache_state'])
            native_observations.history(history, 0, 1); native_observations.cache(cache, 0, 1)
            require(lock[:8] == b'HFLSTATE' and len(lock) >= 256, 'body complete capability lock arena differs')
            if 3 <= index < 17:
                require(before == after and not out, 'body refused binding mutated its complete context')
            if index in (17, 19, 21, 23): request_lengths.append(len(source))
            if event['code'] < 0xffff0000 and event['function'] in ('run', 'resume'):
                require(event['code'] == len(out) and out[:8] == b'HLTBRP01', 'body completed borrowed reply differs')
            if event['code'] == 0xffffffdf:
                require(len(out) == 48 and out[:8] == b'HLTBWT01' and U(after, 136) == U(after, 144) == 0,
                        'body real wait completed or lost its borrowed wait frame')
    counts = list(range(4, 18)) + [19, 21, 23, 25, 38, 45, 47, 49, 51, 53, 56]
    names = ['binding-refusal-' + str(i) for i in (0, 1, 2, 3, 5, 7, 8, 9, 11, 12, 13, 14, 17, 21)]
    names += ['request-refusal-' + str(n) for n in request_lengths]
    names += ['wait-three-resumes-cancel-drain-release', 'existing-waiter-resumes-to-completion',
              'callback-refusal-drains-lease-1', 'callback-refusal-drains-lease-2', 'shared-growth-refuse',
              'shared-growth-lie', 'shared-growth-preserves-complete-history']
    require(report['cases'] == [dict(name=name, status='PASS', actual_calls=count)
            for name, count in zip(names, counts, strict=True)] and len(blobs) == 82,
            'body capability case groups/full blob accounting differs')
    proof_raw = regular(folder, 'code-proof.json'); proof = decode(proof_raw)
    require(report['code_proof'] == proof and proof['mapping_kernel_sealed'] is True
            and proof['source_sha256'] == '5120f566fe8e4ace6c441d2dd110188663cb29bcc28af26a759b44a6f86b15b6'
            and len(proof['commands']) == 5 and all(row['exit_code'] == 0 for row in proof['commands']),
            'body actual exported-code provenance differs')
    code = regular(folder, 'export.bin')
    require(PIN(code) == dict(bytes=proof['code_bytes'], sha256=proof['code_sha256'])
            == dict(bytes=11593, sha256='aefeeffa3944983d685fa20066cc2d4cc2ad18a738652fd961a41fdfa5e6f666'),
            'body sealed source-derived code bytes differ')
    require(b'There are no relocations' in bytes.fromhex(proof['commands'][3]['stdout_hex']),
            'body callable retained a relocation')
    symbols = {row.split()[-1]: int(row.split()[0], 16)
               for row in bytes.fromhex(proof['commands'][4]['stdout_hex']).decode().splitlines() if len(row.split()) == 3}
    require(proof['exports'] == {name: symbols['local_text_body_' + name]
            for name in ('run', 'resume', 'cancel_wait', 'release')}
            == dict(run=0, resume=656, cancel_wait=1027, release=2167), 'body export symbol locations differ')
    artifacts.update({'code-proof.json': SHA(proof_raw), 'export.bin': SHA(code)})
    final_file = regular(folder, 'fixtures/file')
    require(final_file == b'beta\n' + b'x' * 8192, 'body final capability filesystem bytes differ')
    artifacts['fixtures/file'] = SHA(final_file)
    return dict(groups=25, actual_export_calls=45, actual_explicit_owner_calls=11,
                complete_retained_blobs=82, artifact_sha256=artifacts)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--read-compat', type=Path, required=True)
    parser.add_argument('--capabilities', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = dict(status='BODY_NATIVE_COMPLETE_RECORDS_PASS', source_inputs=source_evidence(),
        build=verify_build(args.manifest, source_root=ROOT), read_compat=read_compat(args.read_compat),
        capabilities=capabilities(args.capabilities, args.manifest), process_launches=0)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'process_launches')}, sort_keys=True))
