"""Actual HIA entropy backend selection, continuation and private-state tests."""
from pathlib import Path
import ctypes, hashlib, json, os, struct, sys, unittest

ROOT = Path(os.environ.get("HIA_REFERENCE_RUNTIME", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
sys.path.insert(0, str(Path(__file__).resolve().parent))
from entropy_test_support import completion_counts

CALL, INVALID, CAPACITY, ENTROPY, STATE = 0xfffffff0, 0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc
COUNTS = {"native_calls": 0, "synthetic_effect_completions": 0, "completed_outputs": 0,
          "entropy_refusals": 0, "state_refusals": 0, "admission_refusals": 0, "capacity_refusals": 0}
ACTIONS = {str(i): 0 for i in range(1, 8)}

def frame(size):
    return b"HRENT001" + struct.pack("<QQ", size, 0)

def word(buffer, offset):
    return struct.unpack("<Q", ctypes.string_at(ctypes.addressof(buffer) + offset, 8))[0]

def put(buffer, offset, value):
    ctypes.memmove(ctypes.addressof(buffer) + offset, struct.pack("<Q", value), 8)

class EntropyBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = Path(os.environ["HIA_ENTROPY_MANIFEST"])
        cls.metadata = json.loads(manifest.read_text())
        path = manifest.parent / cls.metadata["policy_manifest"]
        cls.module = NativeModule(path, manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        assert cls.module.metadata["source_sha256"] == cls.metadata["policy_source_sha256"]
        assert cls.module.metadata["image_sha256"] == cls.metadata["policy_image_sha256"]
    @classmethod
    def tearDownClass(cls):
        cls.module.close()
    def fresh(self, capacity=147):
        session = self.module.session(output_capacity=capacity, workspace_capacity=1041)
        self.addCleanup(session.close)
        ctypes.memset(session._output, 0xa5, capacity)
        ctypes.memset(ctypes.addressof(session._workspace) + 1024, 0x5a, 17)
        return session
    def call(self, session, request, expected):
        code, output, work = session.invoke_raw(request)
        COUNTS["native_calls"] += 1
        self.assertEqual(code, expected)
        self.assertEqual(work[1024:], b"\x5a" * 17)
        if code >= 0xffff0000:
            self.assertEqual(output, b"\xa5" * session.output_capacity)
            if code != CALL:
                COUNTS[{ENTROPY: "entropy_refusals", STATE: "state_refusals", INVALID: "admission_refusals",
                        CAPACITY: "capacity_refusals"}[code]] += 1
        else:
            self.assertEqual(output[code:], b"\xa5" * (session.output_capacity - code))
            COUNTS["completed_outputs"] += 1
        return output, work
    def clean(self, session, poisoned=False):
        work = session._workspace.raw[:1024]
        self.assertEqual(work[:24], struct.pack("<QQQ", 8 if poisoned else 0, 0, 0))
        self.assertEqual(work[48:], bytes(976))
    def action(self, session, expected):
        self.assertEqual(word(session._workspace, 0), expected)
        self.assertEqual(word(session._workspace, 296), expected)
    def completion(self, session, value=b"", error=0, result=None):
        work = session._workspace
        self.assertEqual(ctypes.string_at(ctypes.addressof(work) + 256, 8), b"HIAENT02")
        action, sequence, destination, requested = (word(work, p) for p in (296, 264, 272, 280))
        self.assertEqual(action, word(work, 0))
        self.assertEqual(sequence, word(work, 24))
        self.assertEqual(word(work, 288), 0)
        self.assertEqual(ctypes.string_at(ctypes.addressof(work) + 304, 32), bytes(32))
        if action in (2, 7):
            self.assertGreater(requested, 0)
            self.assertGreaterEqual(destination, 512)
            self.assertLessEqual(destination + requested, 640)
        else:
            self.assertEqual((destination, requested), (512 if action == 1 else 0, 0))
        self.assertLessEqual(len(value), requested)
        if value:
            ctypes.memmove(ctypes.addressof(work) + destination, value, len(value))
        default = (1 if action == 4 else len(value)) if not error else 0
        put(work, 304, default if result is None else result)
        put(work, 312, error)
        put(work, 320, sequence)
        put(work, 328, 1)
        COUNTS["synthetic_effect_completions"] += 1
        ACTIONS[str(action)] += 1
    def direct(self, session, size):
        request = frame(size)
        self.call(session, request, CALL)
        if word(session._workspace, 0) == 1:
            self.completion(session)
            self.call(session, request, CALL)
        self.action(session, 2)
        return request
    def fallback(self, session, size, probe_error=38):
        request = frame(size)
        self.call(session, request, CALL)
        if word(session._workspace, 0) == 1:
            self.completion(session, error=probe_error)
            self.call(session, request, CALL)
        if word(session._workspace, 0) != 7:
            for action in (3, 4, 5, 6):
                self.action(session, action)
                self.completion(session)
                self.call(session, request, CALL)
        self.action(session, 7)
        return request
    def test_all_bounded_sizes_and_probe_cache(self):
        session = self.fresh()
        for size in range(129):
            ctypes.memset(session._output, 0xa5, session.output_capacity)
            expected = bytes((i * 37 + size) & 255 for i in range(size))
            request = frame(size)
            if size:
                self.direct(session, size)
                self.completion(session, expected)
            output, _ = self.call(session, request, size)
            self.assertEqual(output[:size], expected)
            self.clean(session)
        self.assertEqual(word(session._workspace, 24), 129)
        self.assertEqual(word(session._workspace, 32), 1)
        self.assertEqual(word(session._workspace, 40), 0)
    def test_partial_reads_and_eintr_for_both_backends(self):
        for fallback in (False, True):
            for size in [1, 2, 7, 8, 12, 31, 32, 33, 64, 127, 128]:
                session = self.fresh()
                request = (self.fallback if fallback else self.direct)(session, size)
                expected = bytes((i * 13 + size) & 255 for i in range(size))
                for i in range(size):
                    if i % 3 == 0:
                        self.completion(session, error=4)
                        self.call(session, request, CALL)
                    self.completion(session, expected[i:i + 1])
                    output, _ = self.call(session, request, size if i == size - 1 else CALL)
                self.assertEqual(output[:size], expected)
                self.clean(session)

    def test_probe_errors_and_cached_backend_selection(self):
        for error in [0, 1, 4, 5, 11, 38, 4095]:
            session = self.fresh()
            self.call(session, frame(0), 0)
            self.assertEqual(word(session._workspace, 24), 0)
            self.call(session, frame(12), CALL)
            self.action(session, 1)
            self.completion(session, error=error)
            self.call(session, frame(12), CALL)
            self.action(session, 3 if error in (1, 38) else 2)
            if error in (1, 38):
                for action in (3, 4, 5, 6):
                    self.action(session, action)
                    self.completion(session)
                    self.call(session, frame(12), CALL)
                self.action(session, 7)
            self.completion(session, b"x" * 12)
            output, _ = self.call(session, frame(12), 12)
            self.assertEqual(output[:12], b"x" * 12)
            self.clean(session)
            ctypes.memset(session._output, 0xa5, session.output_capacity)
            self.call(session, frame(12), CALL)
            self.action(session, 7 if error in (1, 38) else 2)

    def test_partial_error_clears_bytes_and_keeps_selected_backend(self):
        for fallback in (False, True):
            for error in [1, 5, 11, 12, 38, 4095]:
                session = self.fresh()
                request = (self.fallback if fallback else self.direct)(session, 32)
                self.completion(session, b"synthetic private prefix")
                self.call(session, request, CALL)
                self.completion(session, error=error)
                self.call(session, request, ENTROPY)
                self.clean(session)
                self.assertEqual(word(session._workspace, 32), 2 if fallback else 1)
                self.assertEqual(word(session._workspace, 40), int(fallback))
                self.call(session, frame(12), CALL)
                self.action(session, 7 if fallback else 2)
                self.completion(session, b"r" * 12)
                output, _ = self.call(session, frame(12), 12)
                self.assertEqual(output[:12], b"r" * 12)

    def test_open_random_retry_error_and_new_attempt(self):
        session = self.fresh()
        self.call(session, frame(32), CALL)
        self.completion(session, error=38)
        self.call(session, frame(32), CALL)
        for _ in range(3):
            self.action(session, 3)
            self.completion(session, error=4)
            self.call(session, frame(32), CALL)
        self.completion(session, error=13)
        self.call(session, frame(32), ENTROPY)
        self.clean(session)
        self.call(session, frame(32), CALL)
        self.action(session, 3)

    def test_poll_retries_and_failed_poll_always_closes(self):
        session = self.fresh()
        self.call(session, frame(32), CALL)
        for error in [38, 0]:
            self.completion(session, error=error)
            self.call(session, frame(32), CALL)
        self.action(session, 4)
        for error in [4, 11, 4, 11]:
            self.completion(session, error=error)
            self.call(session, frame(32), CALL)
            self.action(session, 4)
        self.completion(session, error=5)
        self.call(session, frame(32), CALL)
        self.action(session, 5)
        self.assertEqual(word(session._workspace, 48), 1)
        self.assertEqual(word(session._workspace, 56), 1)
        self.completion(session, error=4)
        self.call(session, frame(32), ENTROPY)
        self.clean(session)
        self.call(session, frame(32), CALL)
        self.action(session, 3)

    def test_close_not_retried_and_urandom_open_retry_initialization(self):
        session = self.fresh()
        self.call(session, frame(32), CALL)
        for error in [38, 0, 0]:
            self.completion(session, error=error)
            self.call(session, frame(32), CALL)
        self.action(session, 5)
        self.completion(session, error=4)
        self.call(session, frame(32), CALL)
        self.action(session, 6)
        self.assertEqual(word(session._workspace, 48), 0)
        self.completion(session, error=4)
        self.call(session, frame(32), CALL)
        self.action(session, 6)
        self.completion(session, error=13)
        self.call(session, frame(32), ENTROPY)
        self.clean(session)
        self.call(session, frame(32), CALL)
        self.action(session, 3)

    def test_four_ordered_fills_share_cached_urandom(self):
        session = self.fresh()
        for index in range(4):
            ctypes.memset(session._output, 0xa5, session.output_capacity)
            request = self.fallback(session, 32, probe_error=1)
            self.completion(session, bytes([index + 1]) * 32)
            output, _ = self.call(session, request, 32)
            self.assertEqual(output[:32], bytes([index + 1]) * 32)
            self.clean(session)
        self.assertEqual(word(session._workspace, 24), 9)

    def test_zero_oversized_and_contradictory_completions(self):
        for fallback in (False, True):
            for result, error, expected in [(0, 0, ENTROPY), (33, 0, ENTROPY), (1, 4, STATE),
                                            (0, 4096, STATE), (1, 5, STATE)]:
                session = self.fresh()
                request = (self.fallback if fallback else self.direct)(session, 32)
                self.completion(session, result=result, error=error)
                self.call(session, request, expected)
                self.clean(session, poisoned=expected == STATE)

    def test_identity_changes_poison_and_clear_the_context(self):
        cases = [(0, 8), (8, 31), (16, 32), (32, 3), (40, 1), (48, 1), (56, 1),
                 (256, 0), (264, 3), (272, 511), (280, 31), (288, 1), (296, 1),
                 (320, 0), (328, 0), (328, 2)]
        for offset, value in cases:
            session = self.fresh()
            self.direct(session, 32)
            self.completion(session, b"x" * 32)
            put(session._workspace, offset, value)
            self.call(session, frame(32), STATE)
            self.clean(session, poisoned=True)
            self.call(session, frame(0), STATE)
        for request in [b"", frame(32)[:-1], frame(32) + b"x", b"x" * 24, frame(31), frame(129)]:
            session = self.fresh()
            self.direct(session, 32)
            self.completion(session, b"private")
            self.call(session, frame(32), CALL)
            self.call(session, request, STATE)
            self.clean(session, poisoned=True)
        for phase in (3, 4, 5, 6):
            session = self.fresh()
            self.call(session, frame(32), CALL)
            self.completion(session, error=38)
            self.call(session, frame(32), CALL)
            for action in range(3, phase):
                self.action(session, action)
                self.completion(session)
                self.call(session, frame(32), CALL)
            self.action(session, phase)
            self.call(session, b"", STATE)
            self.clean(session, poisoned=True)

    def test_admission_capacities_and_sequence_exhaustion(self):
        session = self.fresh()
        cases = [frame(32)[:n] for n in range(24)] + [frame(32) + b"x", frame(129), frame((1 << 64) - 1)]
        for offset in list(range(8)) + list(range(16, 24)):
            request = bytearray(frame(32))
            request[offset] ^= 1
            cases.append(bytes(request))
        for request in cases:
            before = session._workspace.raw[:1041]
            self.call(session, request, INVALID)
            self.assertEqual(session._workspace.raw[:1041], before)
        for output, workspace in [(31, 1024), (128, 0), (128, 1), (128, 1023)]:
            code, out, work = self.module.invoke_raw(frame(32), output_capacity=output,
                                                    workspace_capacity=workspace, output_fill=0xa5, workspace_fill=0)
            COUNTS["native_calls"] += 1
            COUNTS["capacity_refusals"] += 1
            self.assertEqual((code, out, work), (CAPACITY, b"\xa5" * output, bytes(workspace)))
        put(session._workspace, 24, (1 << 64) - 1)
        self.call(session, frame(0), 0)
        self.call(session, frame(32), STATE)
        self.clean(session, poisoned=True)
        self.assertEqual(word(session._workspace, 24), (1 << 64) - 1)
        last = self.fresh()
        put(last._workspace, 32, 1)
        put(last._workspace, 24, (1 << 64) - 2)
        self.direct(last, 12)
        self.completion(last, b"z" * 12)
        self.call(last, frame(12), 12)
        self.clean(last)
        pending = self.fresh()
        self.direct(pending, 32)
        withdrawn = self.fresh(31)
        ctypes.memmove(withdrawn._workspace, pending._workspace, 1041)
        self.call(withdrawn, frame(32), STATE)
        self.clean(withdrawn, poisoned=True)

if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2)
    report = {"schema": "hepta.runtime.entropy-backend-test.v1",
              **completion_counts(result.result, 11),
              "scope": "actual HIA with synthetic Linux entropy effect completions",
              "counts": COUNTS, "actions": ACTIONS}
    target = os.environ.get("HIA_ENTROPY_BACKEND_REPORT")
    if target:
        path = Path(target)
        assert not path.exists(), "entropy evidence must not overwrite a previous run"
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
