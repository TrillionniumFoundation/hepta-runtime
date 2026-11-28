"""Real HIA request-context state; model assertions are not original Rust receipts."""
from __future__ import annotations
import base64
import copy
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT = Path(os.environ.get('HIA_REQUEST_CONTEXT_ROOT', Path(__file__).resolve().parents[2]))
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path.insert(0, str(REFERENCE / 'scripts'))
from hia_native_loader import NativeModule
INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffffd
COUNTS = {'native_calls': 0, 'semantic_rows': 0, 'frame_refusals': 0,
          'capacity_refusals': 0, 'state_refusals': 0, 'sessions': 0}
EVENTS = None
CORPUS = None

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def request(op, payload=b'', reserved=0):
    return struct.pack('<8s3Q', b'HRCXQ001', op, len(payload), reserved) + payload

def response(tag=0, scalar=0, payload=b''):
    return struct.pack('<8s3Q', b'HRCXR001', tag, scalar, len(payload)) + payload

def list_response(values):
    return response(1, len(values), b''.join(struct.pack('<Q', len(v)) + v for v in values))

def record(value):
    if EVENTS is not None:
        EVENTS.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())

class Session:
    """Private qualification workspace; its number never enters the HIA ABI."""
    def __init__(self, module, *, workspace=1 << 18, output=1 << 18, initialize=True):
        COUNTS['sessions'] += 1
        self.sid = COUNTS['sessions']
        self.native = module.session(workspace_capacity=workspace, output_capacity=output)
        self.stack = []
        self.initialized = False
        if initialize: self.do(1)

    def do(self, op, payload=b''):
        raw = request(op, payload)
        if op == 1:
            assert not self.initialized
            self.initialized = True; self.stack.clear(); expected = response()
        elif op == 8:
            self.initialized = False; self.stack.clear(); expected = response()
        elif op == 2:
            self.stack.append((struct.unpack('<Q', payload)[0], [])); expected = response()
        elif op == 3:
            assert self.stack
            self.stack.pop(); expected = response()
        elif op == 4:
            payload.decode('utf-8', 'strict')
            if self.stack: self.stack[-1][1].append(payload)
            expected = response()
        elif op in (5, 6):
            hints = list(dict.fromkeys(self.stack[-1][1])) if self.stack else []
            expected = list_response(hints)
            if op == 5 and self.stack: self.stack[-1][1].clear()
        elif op == 7:
            expected = (response(3, 1, struct.pack('<Q', self.stack[-1][0]))
                        if self.stack else response(3, 0))
        else:
            raise AssertionError('unexpected successful model operation')
        actual = self.native.invoke(raw)
        COUNTS['native_calls'] += 1; COUNTS['semantic_rows'] += 1
        if actual != expected:
            raise AssertionError((self.sid, op, len(actual), len(expected), sha(actual), sha(expected)))
        record({'ordinal': COUNTS['native_calls'], 'session': self.sid,
                'classification': 'independent-model-native-state', 'operation': op,
                'input_base64': base64.b64encode(raw).decode(),
                'output_base64': base64.b64encode(actual).decode(),
                'input_sha256': sha(raw), 'output_sha256': sha(actual)})
        return actual

    def refuse(self, raw, code):
        before = self.workspace()
        ctypes.memset(self.native._output, 0xa5, self.native.output_capacity)
        actual, output, work = self.native.invoke_raw(raw)
        COUNTS['native_calls'] += 1
        if actual != code or output != b'\xa5' * len(output) or work != before:
            raise AssertionError(('refusal modified state/output or returned wrong code', actual, code,
                                  sha(before), sha(work), sha(output)))
        COUNTS[{INVALID: 'frame_refusals', CAPACITY: 'capacity_refusals', STATE: 'state_refusals'}[code]] += 1
        record({'ordinal': COUNTS['native_calls'], 'session': self.sid,
                'classification': 'native-boundary-refusal', 'expected_code': code, 'actual_code': actual,
                'input_base64': base64.b64encode(raw).decode(), 'workspace_sha256': sha(work),
                'output_sha256': sha(output), 'workspace_bytes': len(work), 'output_bytes': len(output)})

    def workspace(self):
        return self.native._workspace.raw[:self.native.workspace_capacity]

    def inspect(self):
        raw = self.workspace()
        assert raw[:8] == b'HRCXST01'
        version, arena, used, top, depth, r1, r2 = struct.unpack_from('<7Q', raw, 8)
        assert version == 1 and r1 == r2 == 0 and depth == len(self.stack)
        expected_frames = []; boundary = used
        while top:
            previous, cache, count, reserved = struct.unpack_from('<4Q', raw, top)
            assert reserved == 0
            values = []; pos = top + 32
            while pos < boundary:
                _, size = struct.unpack_from('<2Q', raw, pos)
                values.append(raw[pos + 16:pos + 16 + size]); pos += 16 + size
            assert pos == boundary and count == len(values)
            expected_frames.append((cache, values)); boundary, top = top, previous
        assert boundary == 64 and list(reversed(expected_frames)) == self.stack
        assert not any(raw[used:arena * 2]), 'retired hints or scratch remained in private state'

    def close(self):
        if self.initialized:
            self.do(8)
            assert not any(self.workspace())
        self.native.close()

    def __enter__(self): return self
    def __exit__(self, *_args): self.close()

class RequestContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ['HIA_REQUEST_CONTEXT_MANIFEST']); raw = path.read_bytes()
        cls.manifest = json.loads(raw)
        assert cls.manifest['source_sha256'] == sha((ROOT / 'native/request_context.hepta').read_bytes())
        cls.module = NativeModule(path, manifest_sha256=sha(raw))

    @classmethod
    def tearDownClass(cls): cls.module.close()

    def test_01_outside_scope_is_noop(self):
        with Session(self.module) as s:
            for hint in [b'', b'not retained', b'\x00', '提示🙂'.encode()]:
                s.do(4, hint); self.assertEqual(s.do(5), list_response([])); s.do(7)
            s.do(2, struct.pack('<Q', 0)); self.assertEqual(s.do(5), list_response([]))
            self.assertEqual(s.do(7), response(3, 1, b'\0' * 8)); s.do(3); s.inspect()

    def test_02_first_insertion_order_and_exact_bytes(self):
        values = [b'', b'first', b'first', b'', b'\0', b'\r\n', b'\n', b'\r',
                  '⚠️ '.encode(), 'é'.encode(), 'e\u0301'.encode(), '🙂\U0010ffff'.encode(), b'last']
        with Session(self.module) as s:
            s.do(2, struct.pack('<Q', 7))
            for hint in values: s.do(4, hint)
            before = s.workspace()
            self.assertEqual(s.do(6), list_response(list(dict.fromkeys(values))))
            self.assertEqual(s.workspace(), before); s.inspect()
            self.assertEqual(s.do(5), list_response(list(dict.fromkeys(values))))
            self.assertEqual(s.do(5), list_response([])); s.do(4, b'first')
            self.assertEqual(s.do(5), list_response([b'first'])); s.inspect()

    def test_03_nested_cache_and_hint_restoration(self):
        with Session(self.module) as s:
            for depth in range(65):
                s.do(2, struct.pack('<Q', depth % 3)); s.do(4, ('parent-' + str(depth)).encode())
                s.do(4, b'common'); s.do(7)
            for depth in reversed(range(65)):
                self.assertEqual(s.do(6), list_response([('parent-' + str(depth)).encode(), b'common']))
                s.do(7)
                if depth % 2: s.do(5)
                s.do(3)
            self.assertEqual(s.do(5), list_response([])); s.inspect()

    def test_04_interleaved_tasks_keep_private_queues(self):
        a, b, spawned = [Session(self.module) for _ in range(3)]
        try:
            a.do(2, struct.pack('<Q', 99)); b.do(2, struct.pack('<Q', 99))
            for i in range(50):
                a.do(4, ('A-' + str(i)).encode()); b.do(4, ('B-' + str(i)).encode())
                spawned.do(4, b'has no inherited context')
            spawned.do(5); spawned.do(7); a.do(7); b.do(7); a.do(5); b.do(5)
            for s in (a, b, spawned): s.inspect()
        finally:
            for s in (a, b, spawned): s.close()

    def test_05_failed_cancelled_or_destroyed_scope_discards_hints(self):
        # Native lifecycle transitions only. Actual Tokio panic/cancel is a
        # separately compiled original recipe, not simulated evidence here.
        with Session(self.module) as s:
            s.do(2, struct.pack('<Q', 12)); s.do(4, b'parent remains')
            s.do(2, struct.pack('<Q', 13)); s.do(4, b'failed child must disappear'); s.do(3)
            self.assertEqual(s.do(5), list_response([b'parent remains']))
            s.do(4, b'cancelled request must disappear'); s.do(3)
            s.do(2, struct.pack('<Q', 12)); s.do(5)
            s.do(4, b'private discarded bytes'); s.do(8); self.assertFalse(any(s.workspace()))
            s.do(1); s.do(2, struct.pack('<Q', 12)); s.do(5); s.inspect()

    def test_06_interleaving_against_independent_list_model(self):
        rng = random.Random(0x48524358)
        sessions = [Session(self.module, workspace=1 << 19) for _ in range(4)]
        hints = [b'', b'x', b'X', b'\0', b'one\r\ntwo', '中文'.encode(), '🙂'.encode()]
        try:
            for step in range(1600):
                s = rng.choice(sessions); op = rng.choice([2, 3, 4, 4, 4, 5, 6, 7])
                if op == 2 and len(s.stack) < 32: s.do(2, struct.pack('<Q', rng.randrange(4)))
                elif op == 3 and s.stack: s.do(3)
                elif op == 4: s.do(4, rng.choice(hints) if step % 4 else str(step).encode())
                elif op in (5, 6, 7): s.do(op)
            for s in sessions:
                while s.stack: s.do(3)
                s.inspect()
        finally:
            for s in sessions: s.close()

    def test_07_exact_capacity_and_transactional_refusal(self):
        with Session(self.module, workspace=512, output=128) as s:
            s.do(2, struct.pack('<Q', 2)); s.do(4, b'a' * 16); s.refuse(request(4, b''), CAPACITY)
            self.assertEqual(s.do(6), list_response([b'a' * 16]))
            for cap in [0, 31, 32, 55]:
                s.native.output_capacity = cap; s.refuse(request(5), CAPACITY)
            s.native.output_capacity = 56; self.assertEqual(s.do(5), list_response([b'a' * 16]))
            s.native.output_capacity = 128
            s.do(2, struct.pack('<Q', 3)); s.refuse(request(2, b'\0' * 8), CAPACITY)
            s.do(3); s.do(3); s.inspect()
        for size in [0, 63, 255, 511]:
            with Session(self.module, workspace=size, output=32, initialize=False) as s:
                s.refuse(request(1), CAPACITY)

    def test_08_malformed_frames_never_mutate(self):
        with Session(self.module, workspace=4096, output=256) as s:
            invalid = [b'', b'HRCXQ001', request(1)[:-1], b'wrong!!!' + request(1)[8:],
                       request(0), request(9), request(4, b'valid', 1), request(2),
                       request(2, b'\0' * 7), request(2, b'\0' * 9), request(1, b'x'),
                       request(3, b'x'), request(5, b'x'), request(6, b'x'), request(7, b'x'),
                       request(8, b'x'), request(4, b'\xff'), request(4, b'\xc0\x80'),
                       request(4, b'\xed\xa0\x80'), request(4, b'\xf4\x90\x80\x80'),
                       request(4, b'\xe2\x82'), request(4, b'\x80')]
            invalid += [request(4)[:16] + struct.pack('<Q', (1 << 64) - 1) + b'\0' * 8]
            for raw in invalid: s.refuse(raw, INVALID)
            s.refuse(request(1), STATE); s.refuse(request(3), STATE); s.do(8)
            for op, payload in [(2, b'\0' * 8), (3, b''), (4, b'good'), (5, b''), (6, b''), (7, b'')]:
                s.refuse(request(op, payload), STATE)

    def test_09_damaged_private_state_is_not_imported(self):
        with Session(self.module, workspace=4096, output=256) as s:
            s.do(2, struct.pack('<Q', 5)); s.do(4, b'valid'); good = s.workspace()
            mutations = [(0, b'x'), (8, struct.pack('<Q', 2)), (16, struct.pack('<Q', 999)),
                         (24, struct.pack('<Q', 63)), (24, struct.pack('<Q', (1 << 64) - 1)),
                         (32, struct.pack('<Q', 0)), (32, struct.pack('<Q', (1 << 64) - 1)),
                         (40, struct.pack('<Q', 2)), (48, b'\x01'), (56, b'\x01'),
                         (64, struct.pack('<Q', 64)), (80, struct.pack('<Q', 9)), (88, b'\x01'),
                         (96, b'\x00'), (104, struct.pack('<Q', (1 << 64) - 1)), (112, b'\xff')]
            for at, value in mutations:
                address = ctypes.addressof(s.native._workspace)
                ctypes.memmove(address, good, len(good)); ctypes.memmove(address + at, value, len(value))
                s.refuse(request(5), STATE)
            ctypes.memmove(ctypes.addressof(s.native._workspace), good, len(good)); s.do(5); s.inspect()

    def test_10_lifecycle_keeps_bridge_tail_untouched(self):
        s = Session(self.module, workspace=2000, output=128, initialize=False)
        try:
            # arena=512 and scratch=512; 976 remaining bytes include the
            # fixed bridge footer and are outside this owner's memory authority.
            ctypes.memset(ctypes.addressof(s.native._workspace) + 1024, 0xd3, 976)
            s.do(1); s.do(2, struct.pack('<Q', (1 << 64) - 1)); s.do(4, b'a')
            s.do(6); s.do(5); s.do(3); s.do(8)
            self.assertEqual(s.workspace()[:1024], b'\0' * 1024)
            self.assertEqual(s.workspace()[1024:], b'\xd3' * 976)
            ctypes.memset(s.native._workspace, 0xff, 1024); s.do(8)
            self.assertEqual(s.workspace()[:1024], b'\0' * 1024)
            self.assertEqual(s.workspace()[1024:], b'\xd3' * 976)
        finally: s.native.close()

    def test_11_more_than_4096_hints(self):
        with Session(self.module, workspace=1 << 21, output=1 << 20) as s:
            s.do(2, struct.pack('<Q', 1))
            values = [('hint-' + str(i)).encode() for i in range(4097)]
            for value in values + values[::32]: s.do(4, value)
            self.assertEqual(s.do(5), list_response(values)); s.inspect()

    def test_12_full_arena_boundary_without_truncation(self):
        with Session(self.module, workspace=32 << 20, output=8 << 20) as s:
            s.do(2, struct.pack('<Q', 2)); text = b'A' * ((8 << 20) - 112)
            s.do(4, text); s.refuse(request(4, b''), CAPACITY)
            self.assertEqual(s.do(5), list_response([text])); s.inspect()

    def test_13_complete_unicode_scalar_domain(self):
        text = ''.join(chr(cp) for cp in range(0x110000) if not 0xd800 <= cp <= 0xdfff).encode()
        with Session(self.module, workspace=32 << 20, output=8 << 20) as s:
            s.do(2, struct.pack('<Q', 3)); s.do(4, text)
            self.assertEqual(s.do(5), list_response([text])); s.inspect()

    def test_14_source_identity_and_unchanged_imports(self):
        sys.path.insert(0, os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        proof = json.loads((ROOT / 'native/request_context_composition.json').read_bytes())
        raw = (ROOT / 'native/request_context.hepta').read_bytes()
        self.assertEqual(proof['source_sha256'], sha(raw))
        self.assertEqual(proof['original_runtime_commit'], '2173a00ec314ebc0c5ada21e4cb60d8efdccb99a')
        for flag in ('production_activated', 'legacy_call_sites_replaced', 'native_scheduler_qualified'):
            self.assertIs(proof[flag], False)
        functions = {fn['name']: fn for fn in assemble_program(raw).as_dict()['functions']}
        for imported in proof['imports']:
            source = (REFERENCE / imported['path']).read_bytes(); self.assertEqual(sha(source), imported['sha256'])
            original = {fn['name']: fn for fn in assemble_program(source).as_dict()['functions']}
            reverse = {new: old for old, new in imported['function_relocation'].items()}
            for old, new in imported['function_relocation'].items():
                fn = copy.deepcopy(functions[new]); fn['name'] = old
                for block in fn['blocks']:
                    for op in block['ops']:
                        if op['op'] == 'call': op['attrs']['function'] = reverse[op['attrs']['function']]
                self.assertEqual(fn, original[old])
        for relative, pin in proof['original_sources'].items():
            source = (REFERENCE / relative).read_bytes(); self.assertEqual(sha(source), pin['sha256'])
            self.assertEqual(hashlib.sha1(b'blob '+str(len(source)).encode()+b'\0'+source).hexdigest(), pin['blob'])

def main():
    global EVENTS, CORPUS
    if os.environ.get('HIA_REQUEST_CONTEXT_CORPUS_DIR'):
        CORPUS = Path(os.environ['HIA_REQUEST_CONTEXT_CORPUS_DIR']); CORPUS.mkdir(parents=True, exist_ok=False)
        EVENTS = gzip.open(CORPUS / 'native-events.jsonl.gz', 'xb')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RequestContextTests))
    if EVENTS is not None: EVENTS.close()
    path = Path(os.environ['HIA_REQUEST_CONTEXT_MANIFEST'])
    report = {'schema': 'hepta.runtime.request-context-native-test.v1', 'tests_run': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'status': 'PASS' if result.wasSuccessful() and result.testsRun == 14 and not result.skipped else 'FAIL',
              'counts': COUNTS, 'manifest_sha256': sha(path.read_bytes()),
              'source_sha256': sha((ROOT / 'native/request_context.hepta').read_bytes()),
              'source_root': str(ROOT.resolve()), 'native_scheduler_qualified': False,
              'original_rust_execution': False}
    if CORPUS:
        report['corpus_sha256'] = sha((CORPUS / 'native-events.jsonl.gz').read_bytes())
        (CORPUS / 'summary.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__': raise SystemExit(main())
