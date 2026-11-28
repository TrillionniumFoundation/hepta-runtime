"""Execute native HistoryStore transitions and retain every original-domain row."""
from __future__ import annotations
import collections
import copy
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
sys.path.append(str(REFERENCE / "scripts"))
INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffffd
BYTE_CAP = 64 << 20
COUNTS = collections.Counter()
CORPUS = None
NEXT_SESSION = 0
ELF_OBSERVATIONS = []
SOURCE_FILES = ('native/history.hepta', 'native/history_composition.json',
                'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
                'scripts/hia_native_history_build.py', 'tests/hia_native/test_history.py',
                'tests/hia_native/history_oracle_source.py', 'tests/hia_native/oracle_history.rs')
REFERENCE_FILES = ('native/text_budget.hepta', 'native/composition_packer.hepta',
                   'tests/hia_native/view_cache_hex_transport.hepta',
                   'scripts/hia_native_composition_build.py', 'scripts/hia_native_scope_qualification.py',
                   'scripts/hia_native_entropy_qualification.py', 'src/mcp/fs/core.rs',
                   'src/mcp/fs/core_tests.rs', 'src/mcp/fs/text_editing.rs')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_pins():
    return {'owner': {name: sha((ROOT / name).read_bytes()) for name in SOURCE_FILES},
            'reference': {name: sha((REFERENCE / name).read_bytes()) for name in REFERENCE_FILES}}


def packet(op, key=b"", value=b"", cap=0):
    return struct.pack("<8s7Q", b"HHISTQ01", op, cap, len(key), len(value), 0, 0, 0) + key + value


def fields(raw):
    magic, op, cap, kn, vn, a, b, c = struct.unpack_from("<8s7Q", raw)
    assert magic == b"HHISTQ01" and not (a or b or c) and len(raw) == 64 + kn + vn
    return op, raw[64:64 + kn], raw[64 + kn:], cap


class Reference:
    """Ordinary collections provide a second expectation; Rust replay is separate."""
    def __init__(self):
        self.files = {}
        self.order = collections.deque()
        self.total = 0
        self.poisoned = False
        self.active = False

    def apply(self, raw):
        op, key, value, cap = fields(raw)
        body, kind = b"", 0
        if op == 0:
            assert not self.active
            self.active = True
        elif op == 4:
            assert self.active
            self.active = False
            self.files.clear()
            self.order.clear()
            self.total = 0
            self.poisoned = False
        elif op == 3:
            self.poisoned = True
        elif self.poisoned:
            kind = 3
        elif op == 1:
            history = self.files.setdefault(key, [])
            self.total += len(value)
            if len(history) == 10:
                self.total -= len(history.pop(0))
            history.append(value)
            self.order.append(key)
            while self.total > cap and len(self.order) > 1:
                oldest = self.order.popleft()
                if oldest not in self.files:
                    continue
                previous = self.files[oldest]
                if previous:
                    self.total -= len(previous.pop(0))
                if not previous:
                    del self.files[oldest]
        elif op == 2:
            if key in self.files and self.files[key]:
                body = self.files[key].pop()
                self.total -= len(body)
                if not self.files[key]:
                    del self.files[key]
                kind = 1
            else:
                kind = 2
        else:
            raise AssertionError(op)
        return struct.pack("<8s7Q", b"HHISTR01", kind, len(body), self.total,
                           sum(map(len, self.files.values())), len(self.order), self.poisoned, 0) + body


def session_id():
    global NEXT_SESSION
    NEXT_SESSION += 1
    return NEXT_SESSION


def record(sid, raw, result, execution):
    COUNTS["reference_rows"] += 1
    op = fields(raw)[0]
    group = "lifecycle_rows" if op in (0, 4) else "poison_rows" if op == 3 else "original_owner_rows"
    COUNTS[group] += 1
    if CORPUS:
        CORPUS["input"].write(struct.pack("<II", sid, len(raw)) + raw)
        CORPUS["output"].write(struct.pack("<I", len(result)) + result)
        CORPUS["rows"].write(json.dumps({"ordinal": COUNTS["reference_rows"], "session": sid,
            "operation": op, "execution": execution, "classification": group}, sort_keys=True).encode() + b"\n")


class Session:
    def __init__(self, module, workspace=1 << 20, output=1 << 15):
        self.sid = session_id()
        self.session = module.session(output_capacity=output, workspace_capacity=workspace)
        self.reference = Reference()
        self.do(packet(0))

    def do(self, wire):
        expected = self.reference.apply(wire)
        result = self.session.invoke(wire)
        COUNTS["native_image_calls"] += 1
        assert result == expected, (fields(wire)[:2], result[:64], expected[:64])
        record(self.sid, wire, result, "native-image")
        return result

    def refuse(self, wire, code):
        before = self.session._workspace.raw[:self.session.workspace_capacity]
        ctypes.memset(self.session._output, 0xa5, self.session.output_capacity)
        result, output, after = self.session.invoke_raw(wire)
        COUNTS["native_image_calls"] += 1
        assert result == code, (result, code)
        assert before == after and output == b"\xa5" * len(output)
        COUNTS[{INVALID: "frame_refusals", CAPACITY: "capacity_refusals", STATE: "state_refusals"}[code]] += 1

    def inspect(self, tail=True):
        address = ctypes.addressof(self.session._workspace)
        magic, version, used, snapshots, queue_count, total, poison, end = struct.unpack(
            "<8s7Q", ctypes.string_at(address, 64))
        assert magic == b"HHISTA01" and version == 1
        assert snapshots == sum(map(len, self.reference.files.values()))
        assert total == self.reference.total and queue_count == len(self.reference.order)
        assert poison == self.reference.poisoned
        counts = collections.Counter()
        at = 64
        while at < end:
            kn, vn = struct.unpack("<2Q", ctypes.string_at(address + at, 16))
            key = ctypes.string_at(address + at + 16, kn)
            value = ctypes.string_at(address + at + 16 + kn, vn)
            assert value == self.reference.files[key][counts[key]]
            counts[key] += 1
            at += 16 + kn + vn
        assert at == end and counts == {k: len(v) for k, v in self.reference.files.items()}
        order = []
        while at < used:
            size = struct.unpack("<Q", ctypes.string_at(address + at, 8))[0]
            order.append(ctypes.string_at(address + at + 8, size))
            at += 8 + size
        assert at == used and order == list(self.reference.order)
        if tail:
            assert not any(ctypes.string_at(address + used, self.session.workspace_capacity - used))

    def close(self):
        if self.reference.active:
            self.do(packet(4))
            assert not any(self.session._workspace.raw[:self.session.workspace_capacity])
        self.session.close()


class HistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle_path = Path(os.environ["HIA_HISTORY_BUNDLE"])
        cls.bundle = json.loads(cls.bundle_path.read_bytes())
        cls.build = cls.bundle_path.parents[2]
        path = cls.build / cls.bundle["module"]
        assert sha(path.read_bytes()) == cls.bundle["module_sha256"]
        cls.module = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
        cls.manifest = json.loads(path.read_bytes())
        assert cls.manifest["source_sha256"] == sha((ROOT / "native/history.hepta").read_bytes())
        assert cls.manifest["buffer_profile"] == "history.v1"
        assert [cls.manifest[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [128 << 20, 128 << 20, 256 << 20]
        cls.proof = json.loads((ROOT / "native/history_composition.json").read_bytes())
        spec = importlib.util.spec_from_file_location('history_oracle_source', ROOT / 'tests/hia_native/history_oracle_source.py')
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        assert (ROOT / 'tests/hia_native/oracle_history.rs').read_bytes() == original.oracle_source(REFERENCE).encode()
        sys.path.insert(0, str(Path(os.environ["HIA_HEPTA_DIR"])))
        from hepta.hia_agent_assembly import assemble_program
        actual = {f["name"]: f for f in assemble_program((ROOT / "native/history.hepta").read_bytes()).as_dict()["functions"]}
        for row in cls.proof["imports"]:
            source = (REFERENCE / row["path"]).read_bytes()
            assert sha(source) == row["sha256"]
            original = {f["name"]: f for f in assemble_program(source).as_dict()["functions"]}
            reverse = {new: old for old, new in row["function_relocation"].items()}
            for old, new in row["function_relocation"].items():
                f = copy.deepcopy(actual[new])
                f["name"] = old
                for block in f["blocks"]:
                    for op in block["ops"]:
                        if op["op"] == "call":
                            op["attrs"]["function"] = reverse[op["attrs"]["function"]]
                assert f == original[old]
        for name, row in cls.proof["original_sources"].items():
            source = (REFERENCE / name).read_bytes()
            assert sha(source) == row["sha256"]
            assert hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest() == row["blob"]
        fixture = cls.build / cls.bundle["fixture"]
        assert sha(fixture.read_bytes()) == cls.bundle["fixture_sha256"]
        cls.fixture = json.loads(fixture.read_bytes())
        cls.executable = fixture.parent / cls.fixture["executable"]
        assert sha(cls.executable.read_bytes()) == cls.fixture["executable_sha256"]
        assert cls.fixture["members"][1]["image_sha256"] == cls.manifest["image_sha256"]
        from hia_native_scope_qualification import embedded_images
        images = []
        for row in cls.fixture["members"]:
            manifest = fixture.parent / row["manifest"]
            assert sha(manifest.read_bytes()) == row["manifest_sha256"]
            metadata = json.loads(manifest.read_bytes())
            image = (manifest.parent / metadata["image"]).read_bytes()
            assert sha(image) == row["image_sha256"]
            images.append(image)
        cls.elf_binding = embedded_images(cls.executable.read_bytes(), cls.fixture["profile"], images)

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    def test_01_original_examples_and_lifo(self):
        s = Session(self.module)
        s.do(packet(2, b"missing"))
        for key, value in ((b"a", b"x" * 100), (b"b", b"y" * 100), (b"c", b"z" * 100)):
            s.do(packet(1, key, value, 250))
        for key in (b"a", b"b", b"c", b"c"):
            s.do(packet(2, key))
        for i in range(12):
            s.do(packet(1, b"f", ("v" + str(i)).encode(), (1 << 64) - 1))
        for _ in range(11):
            s.do(packet(2, b"f"))
        s.inspect()
        s.close()

    def test_02_stale_events_empty_values_and_exact_bytes(self):
        s = Session(self.module)
        for key in (b"", b"\0", b"host:22/a", "汉字/é".encode(), "e\u0301".encode()):
            for value in (b"", b"\n", b"\r\n", b"\r\r\n", "\0ÿ".encode(), "🙂".encode()):
                s.do(packet(1, key, value, 1 << 20))
                s.do(packet(2, key))
            s.do(packet(1, key, b"oversized", 0))
            s.do(packet(2, key))
        # Stale queue events address the current oldest value of that key.
        s.do(packet(1, b"same", b"old", 1 << 20))
        s.do(packet(2, b"same"))
        s.do(packet(1, b"same", b"new", 0))
        assert not s.reference.files
        s.do(packet(2, b"same"))
        s.inspect()
        s.close()

    def test_03_deterministic_complete_transition_stream(self):
        sessions = [Session(self.module) for _ in range(4)]
        rng = random.Random(0x48495354)
        keys = [str(i).encode() for i in range(24)] + [b"", b"a\0b", "目录/🙂".encode()]
        for i in range(6000):
            s = sessions[rng.randrange(len(sessions))]
            key = rng.choice(keys)
            if rng.randrange(4):
                value = (rng.choice(["a", "\r\n", "汉", "🙂", "\0"]) * rng.randrange(90)).encode()
                s.do(packet(1, key, value, rng.choice([0, 1, 16, 128, 1024, 4096, BYTE_CAP, (1 << 64) - 1])))
            else:
                s.do(packet(2, key))
            if i % 500 == 0:
                s.inspect()
        for s in sessions:
            s.inspect()
            s.close()

    def test_04_production_budget_and_full_byte_profile(self):
        s = Session(self.module, workspace=192 << 20, output=128 << 20)
        for i in range(11):
            s.do(packet(1, b"file", bytes([65 + i]) * (5 << 20), BYTE_CAP))
        assert s.reference.total == 50 << 20
        for _ in range(11):
            s.do(packet(2, b"file"))
        for size in (BYTE_CAP - 1, BYTE_CAP, BYTE_CAP + 1):
            s.do(packet(1, b"budget", b"x" * size, BYTE_CAP))
            s.do(packet(2, b"budget"))
        maximum = (128 << 20) - 64 - len(b"maximum")
        s.do(packet(1, b"maximum", b"z" * maximum, BYTE_CAP))
        assert s.reference.total == maximum
        s.do(packet(2, b"maximum"))
        s.inspect(tail=False)
        s.close()
        COUNTS["full_input_boundary_bytes"] = 128 << 20
        COUNTS["production_total_byte_cap"] = BYTE_CAP
        COUNTS["largest_original_snapshot"] = maximum

    def test_05_refusals_preserve_state_and_output(self):
        s = Session(self.module, workspace=1024, output=64)
        s.do(packet(1, b"key", b"payload", BYTE_CAP))
        bad = [b"", b"x" * 63, b"badMAGIC" + packet(2)[8:], packet(5), packet(2, cap=1),
               packet(0, b"key"), packet(3, value=b"x"), packet(2, b"\xff"),
               packet(1, b"k", b"\xc0\xaf", 5), packet(1, b"\xed\xa0\x80", b"x", 5),
               packet(1, b"k", b"\xf4\x90\x80\x80", 5)]
        for at in (24, 32, 40, 48, 56):
            raw = bytearray(packet(1, b"key", b"x", 1))
            struct.pack_into("<Q", raw, at, (1 << 64) - 1)
            bad.append(bytes(raw))
        for raw in bad:
            s.refuse(raw, INVALID)
        s.refuse(packet(2, b"key"), CAPACITY)
        s.refuse(packet(1, b"big", b"x" * 1000, BYTE_CAP), CAPACITY)
        s.refuse(packet(0), STATE)
        before = s.session._workspace.raw[:s.session.workspace_capacity]
        for at, value in ((0, 0), (8, 2), (16, 63), (16, 1025), (24, 999), (32, 999),
                          (40, 999), (48, 2), (56, 63), (56, 1025), (64, (1 << 64) - 1),
                          (72, (1 << 64) - 1)):
            changed = bytearray(before)
            struct.pack_into("<Q", changed, at, value)
            ctypes.memmove(s.session._workspace, bytes(changed), len(changed))
            s.refuse(packet(2, b"key"), STATE)
            ctypes.memmove(s.session._workspace, before, len(before))
        s.inspect()
        s.close()

    def test_06_poison_and_owned_lifetimes(self):
        left, right = Session(self.module), Session(self.module)
        left.do(packet(1, b"same", b"left", BYTE_CAP))
        right.do(packet(1, b"same", b"right", BYTE_CAP))
        left.do(packet(3))
        left.do(packet(1, b"same", b"unreachable", BYTE_CAP))
        left.do(packet(2, b"same"))
        right.do(packet(2, b"same"))
        left.inspect()
        right.inspect()
        left.close()
        right.do(packet(1, b"same", b"still-live", BYTE_CAP))
        right.do(packet(2, b"same"))
        right.close()

    def test_07_actual_static_native_transport(self):
        for attempt in range(4):
            sid = session_id()
            reference = Reference()
            rows = [packet(0), packet(1, b"k", b"one\r\n", 100), packet(1, b"k", b"two", 100),
                    packet(2, b"k"), packet(2, b"k"), packet(2, b"k")]
            if attempt & 1:
                rows.extend([packet(3), packet(1, b"other", b"refused", 100), packet(2, b"k")])
            rows.append(packet(4))
            wire = b"\n".join(raw.hex().encode() for raw in rows) + b"\n"
            completed = subprocess.run([str(self.executable), '--local-read-profile', '/history-fixture'],
                                       input=wire, capture_output=True, timeout=10,
                                       env={'PATH': '', 'LANG': 'C'})
            assert completed.returncode == 0 and not completed.stderr, (completed.returncode, completed.stderr)
            responses = completed.stdout.splitlines()
            assert len(responses) == len(rows)
            COUNTS["native_elf_processes"] += 1
            ELF_OBSERVATIONS.append({'session': sid, 'executable_sha256': sha(self.executable.read_bytes()),
                                     'returncode': completed.returncode, 'stdin_hex': wire.hex(),
                                     'stdout_hex': completed.stdout.hex(), 'stderr_hex': completed.stderr.hex(),
                                     'requests': len(rows)})
            for raw, line in zip(rows, responses, strict=True):
                header, encoded = line.split(b":", 1)
                value = bytes.fromhex(encoded.decode())
                assert int(header, 16) == len(value)
                assert value == reference.apply(raw)
                record(sid, raw, value, "static-native-elf")
                COUNTS["native_elf_requests"] += 1


def main():
    global CORPUS
    started = time.monotonic()
    before = source_pins()
    folder_value = os.environ.get("HIA_HISTORY_CORPUS_DIR")
    folder = Path(folder_value) if folder_value else None
    if folder:
        folder.mkdir(parents=True, exist_ok=False)
        CORPUS = {name: gzip.GzipFile(filename=str(folder / filename), mode="wb", compresslevel=1, mtime=0)
                  for name, filename in (("input", "input.bin.gz"), ("output", "native-output.bin.gz"),
                                         ("rows", "rows.jsonl.gz"))}
    result = None
    try:
        result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(HistoryTests))
    finally:
        if CORPUS:
            for stream in CORPUS.values():
                stream.close()
    passed = result is not None and result.wasSuccessful() and not result.skipped and result.testsRun == 7
    after = source_pins()
    passed = passed and before == after
    report = {"schema": "hepta.runtime.history-native-test.v1", "status": "PASS" if passed else "FAIL",
              "groups": 0 if result is None else result.testsRun, "counts": dict(COUNTS),
              "seconds": time.monotonic() - started,
              "source_sha256": sha((ROOT / "native/history.hepta").read_bytes()),
              "source_proof_sha256": sha((ROOT / "native/history_composition.json").read_bytes()),
              "bundle_sha256": sha(Path(os.environ["HIA_HISTORY_BUNDLE"]).read_bytes()),
              "source_pins": before, "source_pins_unchanged": before == after,
              "elf_observations": ELF_OBSERVATIONS,
              "original_rust_executions": 0, "production_activated": False, "whole_runtime_replaced": False}
    if folder:
        streams = {}
        for name in ("input.bin.gz", "native-output.bin.gz", "rows.jsonl.gz"):
            path = folder / name
            identity, size = hashlib.sha256(), 0
            with gzip.open(path, "rb") as stream:
                while raw := stream.read(1 << 20):
                    identity.update(raw)
                    size += len(raw)
            streams[name] = {"gzip_sha256": sha(path.read_bytes()), "gzip_bytes": path.stat().st_size,
                             "raw_sha256": identity.hexdigest(), "raw_bytes": size}
        metadata = {"schema": "hepta.runtime.history-native-corpus.v1", "report": report,
                    "streams": streams, "source_root": str(ROOT), "reference_root": str(REFERENCE)}
        (folder / "native-corpus.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
