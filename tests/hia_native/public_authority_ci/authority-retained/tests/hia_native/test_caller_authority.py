"""Exact native caller authority tests, with an explicitly synthetic entropy leaf.

This suite never promotes a supplied owner hash or serialized authority flag.
The full OS profile and actual original Rust replay are separate required gates.
"""
from pathlib import Path
import hashlib
import gzip
import ctypes
import json
import os
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_native_harness import Modules, Harness, frame, response, FATAL

FORBIDDEN, UNAUTHORIZED = 0xffffffdf, 0xffffffde
MISSING_EXTENSION, OWNER_ENTROPY = 0xffffffdd, 0xffffffdc
AUTH_CHANGED, CRYPTO_UNAVAILABLE, BINDING_INPUT = 0xffffffdb, 0xffffffda, 0xffffffd9
TOKEN = b"X" * 32
GOOD = [(b"x-hepta-runtime-token", TOKEN)]
COUNTS = {"native_entries": [0] * 9, "native_public_requests": 0, "native_lifecycle_calls": 0,
          "native_contexts": 0, "synthetic_entropy_contexts": 0, "synthetic_ack_controls": 0,
          "fixture_os_effects": 0, "trusted_extension_fixture_transfers": 0, "original_rust_replays": 0}
CORPUS = []
CONTROL_CONTEXTS = []


class AuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = Modules(os.environ["HIA_AUTHORITY_MANIFEST"],
                              os.environ["HIA_AUTHORITY_LOADER_MANIFEST"],
                              os.environ["HIA_SCOPE_MANIFEST"])
        cls.temp = tempfile.TemporaryDirectory(prefix="hia-caller-authority-fixtures-")
        cls.root = Path(cls.temp.name)
        cls.token = cls.root / "credential"
        cls.token.write_bytes(TOKEN + b"\n")
        cls.token.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.modules.close()
        cls.temp.cleanup()

    def setUp(self):
        self.instances = []

    def tearDown(self):
        for h in self.instances:
            for i, count in enumerate(h.native_entries):
                COUNTS["native_entries"][i] += count
            COUNTS["fixture_os_effects"] += len(h.effects)
            h.close()

    def fresh(self, *, export=True, token=TOKEN, **kwargs):
        h = Harness(self.modules, **kwargs)
        self.instances.append(h)
        COUNTS["native_contexts"] += 1
        COUNTS["synthetic_entropy_contexts"] += 1
        h.reference_context = COUNTS["native_contexts"]
        h.reference_export = export
        if not export:
            CONTROL_CONTEXTS.append({"context": h.reference_context, "reason": self._testMethodName,
                "selected_before_startup": True})
        h.reference_config = {"context": h.reference_context, "mode": h.mode,
            "entropy_seed": kwargs.get("entropy_seed", 7), "entropy_fail": kwargs.get("entropy_fail", 0),
            "owner_failure": bool(kwargs.get("owner_error", 0)), "token_file_hex": (token + b"\n").hex(),
            "file_mode": 0o600, "missing_file": False}
        return h

    def start(self, h):
        COUNTS["native_lifecycle_calls"] += 1
        path = self.token
        if h.reference_config["token_file_hex"] != (TOKEN + b"\n").hex():
            path = self.root / ("credential-" + str(h.reference_context))
            path.write_bytes(bytes.fromhex(h.reference_config["token_file_hex"]))
            path.chmod(0o600)
        result = h.startup(path)
        self.assertEqual(result, (0, b""))
        if h.reference_export:
            CORPUS.append(dict(h.reference_config, operation="start", code=0, output_hex=""))
        return h

    def query(self, h, op=1, headers=GOOD, payload=b"", expected=0, body=None):
        COUNTS["native_public_requests"] += 1
        code, raw = h.request(frame(op, headers, payload))
        self.assertEqual(code, len(raw))
        result, value = response(raw)
        self.assertEqual(result, expected)
        if body is not None:
            self.assertEqual(value, body)
        if result:
            self.assertEqual(value, b"")
        if h.reference_export:
            CORPUS.append({"context": h.reference_context, "operation": "request", "request_op": op,
                "headers": [[name.hex(), value.hex()] for name, value in headers], "payload_hex": payload.hex(),
                "code": result, "output_hex": value.hex()})
        return value

    def test_http_origin_priority_and_exact_header_bytes(self):
        h = self.start(self.fresh())
        for headers in [[], [(b"x-hepta-runtime-token", b"")], [(b"x-hepta-runtime-token", b"wrong")],
                        [(b"x-hepta-runtime-token", TOKEN + b" ")], [(b"x-hepta-runtime-token", b" " + TOKEN)],
                        [(b"x-hepta-runtime-token", b"\xff" * 32)]]:
            self.query(h, headers=headers, expected=UNAUTHORIZED)
            for origin in [b"", b"null", b"https://owned.invalid", b"\t"]:
                self.query(h, headers=headers + [(b"OrIgIn", origin)], expected=FORBIDDEN)
        for origin in [b"", b"null", b"https://owned.invalid"]:
            self.query(h, headers=GOOD + [(b"origin", origin)], expected=FORBIDDEN)
        self.assertEqual(h.get(0, 80), 0)
        self.query(h, headers=[(b"X-HePtA-RuNtImE-ToKeN", TOKEN)], body=b"\x01")
        self.query(h, headers=GOOD + [(b"x-hepta-runtime-token", b"wrong")], body=b"\x01")
        self.query(h, headers=[(b"x-hepta-runtime-token", b"wrong")] + GOOD, expected=UNAUTHORIZED)
        self.query(h, headers=[(b"x-hepta-caller", b"a" * 64), (b"mcp-session-id", b"b" * 64)], expected=UNAUTHORIZED)

    def test_scope_custody_reconnect_and_first_tool_binding(self):
        h = self.start(self.fresh())
        owner = hashlib.sha256(b"hepta-runtime/private-operator-credential/v1\0" + TOKEN).digest()
        self.assertEqual(h.bytes(0, 288, 32), owner)
        self.assertEqual(h.get(0, 80), 0)
        self.query(h, op=0, body=b"")
        self.assertEqual(h.get(0, 80), 0)
        binding = self.query(h, op=2, payload=b"canonical owner fixture")
        self.assertEqual(len(binding), 64)
        self.assertEqual(h.bytes(0, 352, 32), owner)
        self.assertEqual(h.get(0, 80), 1)
        self.query(h, headers=[(b"x-hepta-runtime-token", b"Y" * 32)], expected=UNAUTHORIZED)
        self.assertEqual(h.bytes(0, 352, 32), owner)
        other = self.start(self.fresh(token=b"Y" * 32))
        self.assertNotEqual(other.bytes(0, 288, 32), owner)
        # Qualification-only trusted extension replacement: both owners came
        # from complete native private-file verification. No public frame can
        # perform this transfer or supply these private bytes.
        ctypes.memmove(h.address(0) + 288, other.address(0) + 288, 32)
        COUNTS["trusted_extension_fixture_transfers"] += 1
        CORPUS.append({"context": h.reference_context, "operation": "replace_verified_extension",
            "source_context": other.reference_context, "adapter_only": True, "code": 0, "output_hex": ""})
        self.query(h, expected=AUTH_CHANGED)
        self.assertEqual(h.bytes(0, 352, 32), owner)
        ctypes.memmove(h.address(0) + 288, owner, 32)
        COUNTS["trusted_extension_fixture_transfers"] += 1
        CORPUS.append({"context": h.reference_context, "operation": "restore_verified_extension",
            "adapter_only": True, "code": 0, "output_hex": ""})
        self.query(h, body=b"\x01")
        self.query(other, headers=[(b"x-hepta-runtime-token", b"Y" * 32)], body=b"\x01")
        COUNTS["native_lifecycle_calls"] += 1
        self.assertEqual(other.shutdown(), (0, b""))
        CORPUS.append({"context": other.reference_context, "operation": "shutdown", "code": 0, "output_hex": ""})
        before = h.bytes(6, 0, 160)
        COUNTS["native_lifecycle_calls"] += 1
        self.assertEqual(h.reconnect(), (0, b""))
        CORPUS.append({"context": h.reference_context, "operation": "reconnect", "code": 0, "output_hex": ""})
        self.assertEqual(h.get(0, 80), 0)
        self.assertEqual(h.bytes(6, 0, 160), before)
        self.assertEqual(self.query(h, op=2, payload=b"canonical owner fixture"), binding)
        self.assertEqual(h.bytes(0, 352, 32), owner)
        self.assertNotEqual(h.bytes(0, 320, 32), owner)
        self.assertNotIn(TOKEN, binding)
        self.assertNotIn(owner.hex().encode(), binding)
        COUNTS["native_lifecycle_calls"] += 1
        self.assertEqual(h.shutdown(), (0, b""))
        CORPUS.append({"context": h.reference_context, "operation": "shutdown", "code": 0, "output_hex": ""})
        self.assertEqual(h.get(6, 0), 3)
        self.assertEqual(h.bytes(0, 8, (16 << 20) - 264), bytes((16 << 20) - 264))

    def test_stdio_and_http_without_extension_are_distinct(self):
        h = self.start(self.fresh(mode=1))
        self.query(h, headers=[], body=b"\0")
        self.query(h, headers=GOOD + [(b"origin", b"null"), (b"x-hepta-caller", b"a" * 64)], body=b"\0")
        self.assertEqual(h.get(0, 88), 0)
        self.assertEqual(h.bytes(0, 352, 32), h.bytes(0, 320, 32))
        self.assertEqual(len(self.query(h, op=2, headers=[], payload=b"stdio canonical fixture")), 64)
        h = self.start(self.fresh(mode=3))
        for headers in [[], GOOD, GOOD + [(b"origin", b"null")]]:
            self.query(h, headers=headers, expected=MISSING_EXTENSION)
        self.assertEqual(h.get(0, 64), 1)
        self.assertEqual(h.get(0, 72), 1)
        self.assertEqual(h.get(0, 80), 0)
        self.assertEqual(h.get(6, 0), 0)

    def test_independent_owner_and_four_ordered_crypto_fills(self):
        h = self.start(self.fresh(mode=1, owner_error=5))
        self.assertEqual(h.effects[0], {"action": 7, "sequence": 1, "result": 0, "errno": 5})
        self.assertEqual(h.get(0, 64), 0)
        self.assertEqual(h.get(0, 72), 1)
        self.assertEqual(sum(row["caller"] == 6 and row["target"] == 7 for row in h.calls), 4)
        self.query(h, headers=[], expected=OWNER_ENTROPY)
        for failed in range(1, 5):
            h = self.start(self.fresh(mode=1, entropy_fail=failed))
            self.assertEqual(h.get(0, 64), 1)
            self.assertEqual(h.get(0, 72), 0)
            self.query(h, headers=[], body=b"\0")
            self.query(h, op=2, headers=[], payload=b"key unavailable", expected=CRYPTO_UNAVAILABLE)
            self.assertEqual(h.get(0, 80), 1)
            h = self.start(self.fresh(mode=2, entropy_fail=failed))
            self.assertEqual(h.get(0, 72), 0)
            self.assertEqual(h.bytes(0, 384, 128), bytes(128))
            self.assertEqual(h.get(0, 56), 1)
            self.assertEqual(sum(row["caller"] == 0 and row["target"] == 7 for row in h.calls), failed)
            self.assertEqual(len(self.query(h, op=2, payload=b"global key remains available")), 64)

    def test_candidate_hashing_full_length_and_all_digest_positions(self):
        h = self.start(self.fresh())
        for i in range(len(TOKEN)):
            altered = bytearray(TOKEN)
            altered[i] ^= 1
            self.query(h, headers=[(b"x-hepta-runtime-token", bytes(altered))], expected=UNAUTHORIZED)
        for size in [1048576, 1048577, 2097185, (4 << 20) - 48 - len(b"x-hepta-runtime-token")]:
            start = len(h.calls)
            self.query(h, headers=[(b"x-hepta-runtime-token", b"z" * size)], expected=UNAUTHORIZED)
            sha_calls = [row for row in h.calls[start:] if row["target"] == 3]
            self.assertEqual(len(sha_calls), 1 if size <= 1048576 else ((size + 1048575) // 1048576) + 2)
        self.query(h, body=b"\x01")

    def test_capacity_refusal_keeps_bound_owner_and_bad_ack_retires(self):
        h = self.start(self.fresh(export=False))
        COUNTS["native_public_requests"] += 1
        code, raw = h.request(frame(headers=GOOD), capacity=9)
        self.assertEqual((code, raw), (0xfffffffe, b""))
        self.assertEqual(h.get(0, 80), 1)
        self.query(h, body=b"\x01")
        self.query(h, op=2, payload=b"", expected=BINDING_INPUT)
        self.assertEqual(h.get(0, 80), 1)
        h = self.start(self.fresh(export=False))
        def fault(instance, caller, target, b):
            if caller == 0 and target == 3 and instance.get(0, 16) == 8:
                instance.put(0, b + 88, instance.get(0, b + 88) + 1)
                instance.completion_fault = None
        h.completion_fault = fault
        COUNTS["synthetic_ack_controls"] += 1
        COUNTS["native_public_requests"] += 1
        self.assertEqual(h.request(frame(headers=GOOD)), (FATAL, b""))
        self.assertEqual(h.get(0, 0), 4)
        self.assertEqual(h.bytes(0, 256, 256), bytes(256))

    def test_serialized_fields_cannot_create_or_reload_authority(self):
        h = self.start(self.fresh(export=False))
        before = len(h.effects)
        for wire in [b"", b"0", b"zz", b"00", b"7b2261757468656e74696361746564223a747275657d",
                     (b"HRLOAD01" + struct.pack("<2Q", 1, 0) + b"/tmp/forged-token").hex().encode()]:
            COUNTS["native_public_requests"] += 1
            code, raw = h.request(wire)
            self.assertEqual(code, 8)
            self.assertEqual(response(raw), (0xffffffff, b""))
        self.query(h, headers=[(b"authenticated", b"true"), (b"owner", b"a" * 64)], expected=UNAUTHORIZED)
        self.assertEqual(len(h.effects), before)
        self.assertEqual(h.get(0, 80), 0)
        self.query(h, body=b"\x01")

    def test_missing_required_credential_and_invalid_startup_precede_session(self):
        h = self.fresh(mode=4)
        COUNTS["native_lifecycle_calls"] += 1
        self.assertEqual(h.startup(), (0xffffffed, b""))
        CORPUS.append(dict(h.reference_config, operation="start", code=0xffffffed, output_hex=""))
        self.assertEqual(h.calls, [])
        self.assertEqual(h.effects, [])
        h = self.fresh(mode=2)
        COUNTS["native_lifecycle_calls"] += 1
        code, raw = h.startup(self.root / "absent-token")
        self.assertEqual((code, raw), (0xfffffffd, b""))
        CORPUS.append(dict(h.reference_config, operation="start", code=code, output_hex="", missing_file=True))
        self.assertEqual([row["target"] for row in h.calls], [8])
        self.assertEqual([row["action"] for row in h.effects], [1])


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuthorityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "hepta.runtime.caller-authority.native-tests.v1", "tests_run": result.testsRun,
              "expected_tests": 8, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
              "synthetic_entropy_fixture": True, "production_http_transport": False,
              "loaded_artifacts": AuthorityTests.modules.loaded_artifacts,
              "elapsed_seconds": round(time.monotonic() - started, 6)}
    passed = result.wasSuccessful() and result.testsRun == 8 and all(report[key] == 0 for key in
        ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
    expected_counts = {"native_entries": [333, 0, 18, 95, 0, 15, 77, 84, 164], "native_public_requests": 112,
        "native_lifecycle_calls": 23, "native_contexts": 20, "synthetic_entropy_contexts": 20,
        "synthetic_ack_controls": 1, "fixture_os_effects": 133, "trusted_extension_fixture_transfers": 2,
        "original_rust_replays": 0}
    report["expected_counts"] = expected_counts
    report["counts_match"] = COUNTS == expected_counts
    report["rust_corpus_rows"] = len(CORPUS)
    passed = passed and report["counts_match"] and len(CORPUS) == 122
    here = Path(__file__).resolve().parent
    report["sources"] = {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
        for name in ["test_caller_authority.py", "authority_native_harness.py"]}
    report["status"] = "PASS" if passed else "FAIL"
    corpus_dir = os.environ.get("HIA_AUTHORITY_CORPUS_DIR")
    if corpus_dir:
        destination = Path(corpus_dir)
        destination.mkdir(parents=True, exist_ok=False)
        raw = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in CORPUS)
        packed = gzip.compress(raw, mtime=0)
        (destination / "authority_cases.jsonl.gz").write_bytes(packed)
        output = b"".join(struct.pack("<IQ", row["code"], len(bytes.fromhex(row["output_hex"])))
                          + bytes.fromhex(row["output_hex"]) for row in CORPUS)
        metadata = {"schema": "hepta.runtime.caller-authority.native-corpus.v1", "rows": len(CORPUS),
            "source_sha256": hashlib.sha256((Path(__file__).resolve().parents[2] / "native/caller_authority.hepta").read_bytes()).hexdigest(),
            "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(), "gzip_bytes": len(packed),
            "gzip_sha256": hashlib.sha256(packed).hexdigest(), "output_sha256": hashlib.sha256(output).hexdigest(),
            "native_report": report, "predetermined_control_contexts": CONTROL_CONTEXTS,
            "adapter_only_rows": sum(row.get("adapter_only", False) for row in CORPUS),
            "original_rust_replay_status": "PENDING"}
        (destination / "native-corpus.json").write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n")
    target = os.environ.get("HIA_AUTHORITY_TEST_REPORT")
    if target:
        Path(target).write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if passed else 1)
