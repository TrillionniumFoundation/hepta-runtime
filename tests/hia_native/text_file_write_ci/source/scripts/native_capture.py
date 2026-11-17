"""Actual HIA-only parameter producer; never reads original result streams."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(__file__).resolve().parent
SOURCE = ROOT
OUT = None
QUALIFICATION = None
sys.path.insert(0, str(ROOT / 'scripts'))
from common import source_evidence
INVALID, CAPACITY = 0xffffffff, 0xfffffffe
sha = lambda raw: hashlib.sha256(raw).hexdigest()
word = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]

def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()

def pin(path):
    path = Path(path)
    with path.open('rb') as stream:
        return {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}

def load_cases():
    spec = importlib.util.spec_from_file_location('text_publisher_cases', BASE / 'params_cases.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class Recorder:
    def __init__(self):
        sys.path.insert(0, str(SOURCE / 'scripts'))
        from hia_native_loader import NativeModule
        self.members = json.loads((QUALIFICATION / 'build/typed-params.json').read_bytes())['members']
        self.modules = {owner: NativeModule(QUALIFICATION / self.members[name]['manifest'],
                         manifest_sha256=self.members[name]['manifest_sha256'])
                        for owner, name in ((1, 'serde_json_span'), (2, 'text_file_write_params'))}
        self.stream = gzip.open(OUT / 'calls.bin.gz', 'wb', compresslevel=1)
        self.rows_stream = (OUT / 'native-results.jsonl').open('xb')
        self.index = []
        self.rows = []
        self.controls = []
        self.offset = 0
        self.artifacts = {'build/typed-params.json': pin(QUALIFICATION / 'build/typed-params.json')}
        for member in self.members.values():
            path = QUALIFICATION / member['manifest']
            meta = json.loads(path.read_bytes())
            for artifact in (path, path.parent / meta['source'], path.parent / meta['image']):
                self.artifacts[str(artifact.relative_to(QUALIFICATION))] = pin(artifact)

    def invoke(self, owner, cid, label, wire, before, capacity):
        with self.modules[owner].session(workspace_capacity=len(before), output_capacity=capacity) as session:
            if before:
                ctypes.memmove(session._workspace, before, len(before))
            ctypes.memset(session._output, 0xa5, capacity)
            code, out, after = session.invoke_raw(wire)
        old = b'\xa5' * capacity
        index = len(self.index) + 1
        header = struct.pack('<8Q', index, owner, cid, code, len(wire), capacity, len(before), 0)
        digest = hashlib.sha256()
        size = 0
        for raw in (header, wire, before, old, out, after):
            self.stream.write(raw)
            digest.update(raw)
            size += len(raw)
        self.index.append({'call': index, 'owner': owner, 'case_id': cid, 'label': label,
                           'offset': self.offset, 'bytes': size, 'return_code': code,
                           'input_bytes': len(wire), 'output_capacity': capacity,
                           'workspace_capacity': len(before), 'record_sha256': digest.hexdigest(),
                           'input_sha256': sha(wire), 'before_sha256': sha(before),
                           'output_before_sha256': sha(old), 'output_sha256': sha(out),
                           'after_sha256': sha(after)})
        self.offset += size
        return code, out, after, index

    def complete(self, owner, cid, wire, *, before=None, capacity=None, label='semantic'):
        header = 32 if owner == 1 else 128
        needed_at = 24 if owner == 1 else 80
        magic = b'HJSVR002' if owner == 1 else b'HTPPRR01'
        before = bytes(16512 if owner == 1 else 65536) if before is None else before
        capacity = header if capacity is None else capacity
        calls = []
        for _ in range(12):
            code, out, after, index = self.invoke(owner, cid, label, wire, before, capacity)
            calls.append(index)
            assert code == header and out[:8] == magic, (owner, cid, code, out[:128].hex())
            status, needed = word(out, 8), word(out, needed_at)
            if status in (2, 3):
                assert out[header:] == b'\xa5' * (capacity - header)
                if status == 2:
                    assert len(before) < needed <= self.modules[owner].metadata['workspace_capacity']
                    before = after + bytes(needed - len(after))
                else:
                    assert capacity < needed <= self.modules[owner].metadata['output_capacity']
                    capacity, before = needed, after
                continue
            assert status in ((0, 1, 5) if owner == 1 else (0, 1)) and needed == 0, (owner, cid, status)
            if owner == 1:
                size = header + word(out, 16)
            elif status == 0:
                size = header + sum(word(out, at) for at in (24, 32, 40))
            else:
                size = header + word(out, 72)
            assert size <= capacity and out[size:] == b'\xa5' * (capacity - size)
            return out[:size], calls
        raise AssertionError(('nonterminating capacity negotiation', owner, cid))

    def semantic(self):
        cases = load_cases()
        encoded = cases.encoded()
        (OUT / 'input.jsonl').write_bytes(encoded)
        for row in cases.cases():
            cid = row['case_id']
            raw = row['raw_json'].encode()
            value, value_calls = self.complete(1, cid, b'HJSMS002' + struct.pack('<2Q', 1, len(raw)) + raw)
            admitted = word(value, 8) == 0
            result = {'value_admitted': admitted}
            params_calls = []
            if admitted:
                canonical = value[32:]
                params, params_calls = self.complete(2, cid,
                    b'HTPPRQ01' + struct.pack('<2Q', len(canonical), 0) + canonical)
                result.update(canonical=canonical.decode(), ok=word(params, 8) == 0,
                              frame_hex=params.hex())
            output = {'case_id': cid, 'name': row['name'], 'result': result}
            self.rows_stream.write(json_bytes(output))
            self.rows.append({'case_id': cid, 'name': row['name'], 'input_sha256': sha(raw),
                              'value_calls': value_calls, 'params_calls': params_calls,
                              'value_admitted': admitted, 'typed_success': result.get('ok', False)})

    def boundary_controls(self):
        values = [b'{"content":"a\\nb","expected_sha256":"absent","mode":"create","path":"p"}',
                  b'{"content":"x","expected_sha256":"absent","mode":"?","path":"p"}']
        for number, raw in enumerate(values):
            cid = 10000 + number * 100
            wire = b'HTPPRQ01' + struct.pack('<2Q', len(raw), 0) + raw
            full, calls = self.complete(2, cid, wire, label='control-reference')
            self.controls.append({'kind': 'reference', 'calls': calls, 'response_sha256': sha(full)})
            for cap in (0, 1, 127):
                before = b'\x7b' * (len(wire) + 65536)
                code, out, after, index = self.invoke(2, cid + 1, 'short-output', wire, before, cap)
                assert (code, out, after) == (CAPACITY, b'\xa5' * cap, before)
                self.controls.append({'kind': 'short-output', 'call': index})
            for capacity in (128, len(full) - 1, len(full), len(full) + 17):
                code, out, after, index = self.invoke(2, cid + 2, 'output-boundary', wire,
                    b'\x7b' * (len(wire) + 65536), capacity)
                assert code == 128
                if capacity < len(full):
                    assert word(out, 8) == 3 and word(out, 80) == len(full)
                    assert out[128:] == b'\xa5' * (capacity - 128)
                else:
                    assert out == full + b'\xa5' * (capacity - len(full))
                self.controls.append({'kind': 'output-boundary', 'call': index, 'required': len(full)})
            for size in (0, 1, len(wire) + 65535):
                before = b'\x7b' * size
                code, out, after, index = self.invoke(2, cid + 3, 'workspace-growth', wire, before, len(full) + 11)
                assert code == 128 and word(out, 8) == 2 and word(out, 80) == len(wire) + 65536
                assert after == before and out[128:] == b'\xa5' * (len(full) + 11 - 128)
                resumed, calls = self.complete(2, cid + 4, wire, before=after + bytes(word(out, 80) - size),
                                               capacity=len(full), label='growth-resume')
                assert resumed == full
                self.controls.append({'kind': 'workspace-growth', 'call': index, 'resume_calls': calls})
            dirty = b'\x7b' * (len(wire) + 65536)
            for repeat in range(3):
                code, out, dirty, index = self.invoke(2, cid + 5, 'dirty-workspace', wire, dirty, len(full) + 7)
                assert code == 128 and out == full + b'\xa5' * 7
                self.controls.append({'kind': 'dirty-workspace', 'call': index})
        raw = values[0]
        wire = b'HTPPRQ01' + struct.pack('<2Q', len(raw), 0) + raw
        invalid = [b'', wire[:7], wire[:24], b'XXXXXXXX' + wire[8:],
                   wire[:8] + struct.pack('<Q', len(raw) + 1) + wire[16:],
                   wire[:16] + struct.pack('<Q', 1) + wire[24:]]
        for number, bad in enumerate(invalid):
            before = b'\x7b' * 40000
            code, out, after, index = self.invoke(2, 12000 + number, 'invalid-frame', bad, before, 256)
            assert (code, out, after) == (INVALID, b'\xa5' * 256, before)
            self.controls.append({'kind': 'invalid-frame', 'call': index})

    def finish(self, success):
        self.stream.close()
        self.rows_stream.close()
        for module in self.modules.values():
            module.close()
        assert self.artifacts == {p: pin(QUALIFICATION / p) for p in self.artifacts}
        for name, rows in (('calls.jsonl', self.index), ('native-cases.jsonl', self.rows), ('controls.jsonl', self.controls)):
            (OUT / name).write_bytes(b''.join(json_bytes(row) for row in rows))
        result = {'status': 'PASS' if success else 'FAIL',
                  'cases': len(self.rows), 'native_calls': len(self.index), 'controls': len(self.controls),
                  'value_admitted': sum(r['value_admitted'] for r in self.rows),
                  'typed_successes': sum(r['typed_success'] for r in self.rows),
                  'full_record_bytes': self.offset, 'artifacts': self.artifacts,
                  'pid': os.getpid(), 'python': sys.executable, 'original_results_read': False,
                  'source_inputs': source_evidence(ROOT),
                  'origin': {'source_root': str(ROOT), 'output': str(QUALIFICATION)},
                  'original_handler_executed': False, 'public_route_replaced': False}
        (OUT / 'capture-result.json').write_bytes(json_bytes(result))
        print(json.dumps(result), flush=True)


def capture():
    recorder = Recorder()
    success = False
    try:
        recorder.semantic()
        recorder.boundary_controls()
        success = True
    finally:
        recorder.finish(success)


def run(qualification):
    global OUT, QUALIFICATION
    QUALIFICATION = Path(qualification).resolve(strict=True)
    OUT = QUALIFICATION / 'native'
    OUT.mkdir(parents=True, exist_ok=False)
    frozen = source_evidence(ROOT)
    capture()
    assert source_evidence(ROOT) == frozen


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification", required=True)
    args = parser.parse_args()
    run(args.qualification)
