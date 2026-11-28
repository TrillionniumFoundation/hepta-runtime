#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Execute real HIA scope/lease/context/cache compositions and retain exact bytes.

Expected traces describe original context/Arc behavior and the explicit private
continuation adapter. This suite is not an original Rust invocation, an HTTP
scheduler, or proof that a production filesystem caller has been replaced.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import HEPTA_COMMIT
from hia_native_loader import NativeModule
from hia_native_request_scope_build import members, source_check
from hia_native_scope_qualification import embedded_images

INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffffd
FIRST_ERROR = 0xffff0000
RUNS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frame(magic, operation, epoch=0, ticket=0, a=0, b=0, payload=b""):
    return magic + struct.pack("<7Q", operation, epoch, ticket, a, b, len(payload), 0) + payload


def scope(operation, generation=1, continuation=1, *, a=0, b=0, payload=b""):
    return frame(b"HRSCQ001", operation, generation, continuation, a, b, payload)


def opening(slot=3, *, epoch=1, source=1):
    return scope(1, 0, 0, a=slot, b=5, payload=struct.pack("<2Q", epoch, source))


def lease(operation, epoch=1, ticket=1, *, a=0, payload=b""):
    return frame(b"HRCLQ001", operation, epoch, ticket, a, 0, payload)


def creating():
    return lease(1, 0, 0, a=6)


def sr(generation=1, continuation=1, phase=1, tag=0, epoch=1, ticket=2, payload=b""):
    return b"HRSCR001" + struct.pack("<7Q", generation, continuation, phase, tag, epoch, ticket, len(payload)) + payload


def lr(ticket=1, count=1, epoch=1, phase=1, payload=b""):
    return b"HRCLR001" + struct.pack("<7Q", epoch, ticket, count, phase, len(payload), 0, 0) + payload


def cq(operation, key=b"", value=b"", after=b"", selector=0):
    return b"HVCACH01" + struct.pack("<5Q", operation, selector, len(key), len(value), len(after)) + key + value + after


def cr(value=None):
    return b"HVCAR001" + struct.pack("<3Q", value is not None, len(value or b""), 0) + (value or b"")


def hints(*values):
    payload = b"".join(struct.pack("<Q", len(value)) + value for value in values)
    return b"HRCXR001" + struct.pack("<3Q", 1, len(values), len(payload)) + payload


class Trace:
    def __init__(self):
        self.rows = []

    def add(self, target, wire, expected, domain):
        self.rows.append((target, wire, expected, domain))
        return self

    def create(self):
        return self.add(5, creating(), lr(), "original-cache-init-adapter")

    def open(self, target=1, *, generation=1, epoch=1, source=1, ticket=2):
        return self.add(target, opening(target + 2, epoch=epoch, source=source),
                        sr(generation=generation, epoch=epoch, ticket=ticket), "original-scope-enter-adapter")

    def close(self, target=1, *, generation=1, continuation=1, reason=0):
        return self.add(target, scope(7, generation, continuation, a=reason),
                        sr(generation, continuation, 0, epoch=0, ticket=0), "original-scope-drop-adapter")

    def release(self, ticket=1, *, count=0, epoch=1):
        return self.add(5, lease(3, epoch, ticket), lr(ticket, count, epoch, int(count > 0)), "original-arc-release-adapter")


class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source_check(ROOT)
        cls.manifest_path = Path(os.environ["HIA_REQUEST_SCOPE_MANIFEST"])
        raw = cls.manifest_path.read_bytes()
        meta = json.loads(raw)
        expected = [{"id": i, "name": item.name, "flags": item.flags, "call_mask": item.call_mask,
                     "input_capacity": item.input_capacity, "output_capacity": item.output_capacity,
                     "workspace_capacity": item.workspace_capacity, "source_sha256": sha(item.source.read_bytes())}
                    for i, item in enumerate(members(ROOT))]
        if meta["profile"] != expected or len(meta["members"]) != 7 or meta["compiler_commit"] != HEPTA_COMMIT:
            raise ValueError("request lifetime fixed private table differs")
        images = []
        for index, row in enumerate(meta["members"]):
            if row["manifest"] != f"module_{index:02d}.json":
                raise ValueError("request lifetime image manifest path differs")
            path = cls.manifest_path.parent / row["manifest"]
            child_raw = path.read_bytes()
            child = json.loads(child_raw)
            if (sha(child_raw) != row["manifest_sha256"] or child["compiler_commit"] != HEPTA_COMMIT
                    or child["compiler_sha256"] != meta["compiler_sha256"]
                    or child["source_sha256"] != expected[index]["source_sha256"]):
                raise ValueError("request lifetime child source/compiler differs")
            with NativeModule(path, manifest_sha256=sha(child_raw)):
                pass
            image = (path.parent / child["image"]).read_bytes()
            if sha(image) != child["image_sha256"] or sha(image) != row["image_sha256"]:
                raise ValueError("request lifetime child bytes differ")
            images.append(image)
        cls.executable = cls.manifest_path.parent / meta["executable"]
        elf = cls.executable.read_bytes()
        if sha(elf) != meta["executable_sha256"]:
            raise ValueError("request lifetime executable changed")
        cls.binding = {"manifest_sha256": sha(raw), "executable_sha256": sha(elf), "profile": expected,
                       "embedded_images": embedded_images(elf, expected, images)}
        cls.corpus = Path(os.environ["HIA_REQUEST_SCOPE_CORPUS_DIR"]) if os.environ.get("HIA_REQUEST_SCOPE_CORPUS_DIR") else None
        if cls.corpus:
            cls.corpus.mkdir(parents=True, exist_ok=False)

    @classmethod
    def tearDownClass(cls):
        if source_check(ROOT) != cls.source or sha(cls.executable.read_bytes()) != cls.binding["executable_sha256"]:
            raise ValueError("request lifetime source or executable changed during execution")

    def execute(self, name, trace):
        wire = b"".join(str(target).encode() + b":" + packet.hex().encode() + b"\n"
                        for target, packet, _, _ in trace.rows)
        command = [str(self.executable), "--local-read-profile", "/request-scope-fixture"]
        started = time.monotonic()
        actual = subprocess.run(command, input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=90, env={"PATH": "", "LANG": "C"})
        elapsed = time.monotonic() - started
        expected = [(value, b"") if type(value) is int else (len(value), value)
                    for _, _, value, _ in trace.rows]
        expected_stdout = b"".join(f"{code:08x}:".encode() + body.hex().encode() + b"\n" for code, body in expected)
        domains = [{"ordinal": index, "target": target, "domain": domain,
                    "input_bytes": len(packet), "input_sha256": sha(packet),
                    "expected_code": expected[index][0], "expected_output_sha256": sha(expected[index][1])}
                   for index, (target, packet, _, domain) in enumerate(trace.rows)]
        streams = {"input": wire, "stdout": actual.stdout, "stderr": actual.stderr,
                   "expected": expected_stdout, "domains": (json.dumps(domains, sort_keys=True) + "\n").encode()}
        record = {"command": command, "timeout_seconds": 90, "elapsed_seconds": elapsed,
                  "exit_code": actual.returncode, "requests": len(trace.rows),
                  "expected_refusals": sum(code >= FIRST_ERROR for code, _ in expected),
                  "streams": {key: {"bytes": len(value), "sha256": sha(value)} for key, value in streams.items()}}
        if self.corpus:
            for key, value in streams.items():
                filename = name + "." + key + ".gz"
                compressed = gzip.compress(value, mtime=0)
                with (self.corpus / filename).open("xb") as handle:
                    handle.write(compressed)
                record["streams"][key].update({"path": filename, "gzip_bytes": len(compressed), "gzip_sha256": sha(compressed)})
        RUNS[name] = record
        self.assertEqual(actual.returncode, 0, actual.stderr.decode(errors="replace"))
        self.assertEqual(actual.stderr, b"")
        if actual.stdout != expected_stdout:
            lines = actual.stdout.splitlines()
            wanted = expected_stdout.splitlines()
            for index, (left, right) in enumerate(zip(lines, wanted)):
                if left != right:
                    self.fail(f"{name} row {index} {trace.rows[index][3]}: actual {left[:300]!r} expected {right[:300]!r}")
            self.fail(f"{name}: actual lines {len(lines)} expected {len(wanted)}")
        return record

    def test_01_interleaved_scopes_share_cache_and_isolate_hints(self):
        t = Trace().create().open().open(2, ticket=3)
        t.add(1, scope(3, payload=b"request A"), sr(), "original-push")
        t.add(1, scope(3, payload=b"request A"), sr(), "original-push-duplicate")
        t.add(2, scope(3, payload="请求 B🙂".encode()), sr(ticket=3), "original-push")
        t.add(1, scope(9, payload=cq(2, b"file", b"shared")), sr(tag=5, payload=cr()), "original-cache-set")
        t.add(1, scope(5), sr(continuation=2, phase=2), "continuation-yield-adapter")
        t.add(2, scope(9, payload=cq(1, b"file")), sr(tag=5, ticket=3, payload=cr(b"shared")), "original-shared-cache-get")
        t.add(2, scope(4), sr(tag=4, ticket=3, payload=hints("请求 B🙂".encode())), "original-drain")
        t.add(1, scope(6, continuation=2), sr(continuation=2), "continuation-resume-adapter")
        t.add(1, scope(4, continuation=2), sr(continuation=2, tag=4, payload=hints(b"request A")), "original-drain-deduplicated")
        t.close(continuation=2).close(2).release()
        self.execute("interleaved", t)

    def test_02_await_and_stale_completion_are_consumed_once(self):
        t = Trace().create().open()
        t.add(1, scope(2), sr(tag=1), "original-access-cache")
        t.add(1, scope(5), sr(continuation=2, phase=2), "continuation-yield-adapter")
        for op in (2, 3, 4, 5, 7):
            t.add(1, scope(op), STATE, "suspended-access-refusal")
        t.add(1, scope(6, continuation=1), STATE, "stale-resume-refusal")
        t.add(1, scope(6, continuation=2), sr(continuation=2), "continuation-resume-adapter")
        t.add(1, scope(6, continuation=2), STATE, "duplicate-resume-refusal")
        t.add(1, scope(3, continuation=2, payload=b"after await"), sr(continuation=2), "original-push-after-await")
        t.add(1, scope(5, continuation=2), sr(continuation=3, phase=2), "continuation-yield-adapter")
        t.add(1, scope(6, continuation=2), STATE, "old-resume-refusal")
        t.add(1, scope(6, continuation=3), sr(continuation=3), "continuation-resume-adapter")
        t.add(1, scope(4, continuation=3), sr(continuation=3, tag=4, payload=hints(b"after await")), "original-drain-after-await")
        t.close(continuation=3).release()
        self.execute("await", t)

    def test_03_spawn_and_heartbeat_do_not_inherit_binding(self):
        t = Trace().create().open()
        t.add(1, scope(3, payload=b"keep private"), sr(), "original-push")
        t.add(1, scope(9, payload=cq(2, b"file", b"truth")), sr(tag=5, payload=cr()), "original-cache-set")
        t.add(1, scope(5), sr(continuation=2, phase=2), "continuation-yield-adapter")
        for _ in range(3):
            t.add(1, scope(2, 0, 0), sr(0, 0, 0, 2, 0, 0), "original-unbound-access")
            t.add(1, scope(3, 0, 0, payload=b"background dropped"), sr(0, 0, 0, 2, 0, 0), "original-unbound-push")
            t.add(1, scope(4, 0, 0), sr(0, 0, 0, 2, 0, 0, hints()), "original-unbound-drain")
            t.add(1, scope(9, 0, 0, payload=cq(2, b"file", b"must not replace")), sr(0, 0, 0, 2, 0, 0, cr()), "original-unbound-cache-noop")
        t.add(1, scope(6, continuation=2), sr(continuation=2), "continuation-resume-adapter")
        t.add(1, scope(9, continuation=2, payload=cq(1, b"file")), sr(continuation=2, tag=5, payload=cr(b"truth")), "original-cache-preserved")
        t.add(1, scope(4, continuation=2), sr(continuation=2, tag=4, payload=hints(b"keep private")), "original-drain-isolated")
        t.close(continuation=2).release()
        self.execute("unbound", t)

    def test_04_cancel_drop_unwind_tombstones_and_generation_reuse(self):
        t = Trace().create()
        for generation, reason in enumerate((2, 3, 4), 1):
            ticket = generation + 1
            t.open(generation=generation, ticket=ticket)
            t.add(1, scope(3, generation, payload=b"discard abandoned"), sr(generation=generation, ticket=ticket), "original-push-before-abandon")
            t.add(1, scope(5, generation), sr(generation, 2, 2, ticket=ticket), "continuation-yield-adapter")
            t.add(1, scope(8, generation, 0, a=reason), sr(generation, 2, 3, epoch=0, ticket=0), "original-cancel-drop-unwind-adapter")
            t.add(5, lease(5), lr(count=1), "original-arc-request-released")
            t.add(1, opening(), STATE, "tombstone-reopen-refusal")
            t.add(1, scope(3, generation, 2, payload=b"late hint"), STATE, "late-hint-refusal")
            t.add(1, scope(9, generation, 2, payload=cq(2, b"file", b"late")), STATE, "late-cache-refusal")
            t.add(1, scope(6, generation, 2), sr(generation, 2, 0, 3, 0, 0), "late-completion-retirement-only")
            t.add(1, scope(6, generation, 2), STATE, "duplicate-late-completion-refusal")
        t.open(generation=4, ticket=5)
        t.add(1, scope(4, 4), sr(generation=4, ticket=5, tag=4, payload=hints()), "original-no-abandoned-hints")
        t.add(1, scope(2, 1), STATE, "previous-generation-refusal")
        t.add(1, scope(3, 3, 2, payload=b"old"), STATE, "previous-generation-late-hint-refusal")
        t.close(generation=4).release()
        self.execute("cancel", t)

    def test_05_publication_clone_survives_session_and_last_release_destroys(self):
        t = Trace().create()
        t.add(5, lease(2), lr(2, 2), "original-publication-arc-clone")
        t.open(ticket=3)
        t.add(1, scope(9, payload=cq(2, b"key", b"before drop")), sr(ticket=3, tag=5, payload=cr()), "original-cache-set")
        t.release(1, count=2)
        t.add(5, lease(4, ticket=2, payload=cq(1, b"key")), lr(2, 2, payload=cr(b"before drop")), "original-publication-get-after-session-drop")
        t.close()
        t.add(5, lease(2, ticket=2), lr(4, 2), "original-clone-existing-non-session-arc")
        t.add(5, lease(4, ticket=2, payload=cq(5)), lr(2, 2, payload=cr()), "original-publication-owned-forget-all")
        t.add(5, lease(4, ticket=4, payload=cq(1, b"key")), lr(4, 2, payload=cr()), "original-shared-forget-all-visible")
        t.add(5, lease(4, ticket=4, payload=cq(2, b"key", b"retained")), lr(4, 2, payload=cr()), "original-cache-set")
        t.release(2, count=1)
        t.add(5, lease(3, ticket=2), STATE, "double-release-refusal")
        t.add(5, lease(4, ticket=4, payload=cq(1, b"key")), lr(4, 1, payload=cr(b"retained")), "original-last-clone-still-live")
        t.release(4)
        t.add(5, lease(4, ticket=4, payload=cq(1, b"key")), STATE, "destroyed-cache-access-refusal")
        t.add(5, creating(), lr(epoch=2), "original-new-cache-lifetime-adapter")
        t.add(5, lease(4, epoch=2, payload=cq(1, b"key")), lr(epoch=2, payload=cr()), "original-new-cache-empty")
        t.add(5, lease(3, ticket=1), STATE, "previous-cache-epoch-release-refusal")
        t.release(epoch=2)
        self.execute("leases", t)

    def test_06_refusals_preserve_hints_and_committed_cache(self):
        t = Trace().create().open()
        t.add(1, scope(3, payload=b"keep"), sr(), "original-push")
        t.add(1, scope(9, payload=cq(2, b"key", b"committed before error")), sr(tag=5, payload=cr()), "original-cache-set-before-error")
        bad = bytearray(scope(3, payload=b"ignored")); struct.pack_into("<Q", bad, 56, 1)
        for raw in (bytes(bad), scope(3, payload=b"\xff"), scope(7, a=9), scope(8, 1, 0, a=1),
                    scope(9, payload=cq(5)), scope(9, payload=cq(1, b"k", b"illegal-extra")), scope(10)):
            t.add(1, raw, INVALID, "typed-frame-refusal")
        t.add(1, scope(3, 2, payload=b"wrong generation"), STATE, "binding-refusal")
        t.add(1, scope(4), sr(tag=4, payload=hints(b"keep")), "original-hints-preserved-on-refusal")
        t.close(reason=1).open(generation=2, ticket=3)
        t.add(1, scope(9, 2, payload=cq(1, b"key")), sr(generation=2, ticket=3, tag=5, payload=cr(b"committed before error")), "original-cache-not-rolled-back")
        t.add(1, scope(4, 2), sr(generation=2, ticket=3, tag=4, payload=hints()), "original-error-scope-hints-discarded")
        t.close(generation=2).release()
        self.execute("refusals", t)

    def test_07_live_clone_records_have_no_fixed_count_quota(self):
        t = Trace().create()
        for ticket in range(2, 4099):
            t.add(5, lease(2), lr(ticket, ticket), "original-arc-clone-many")
        for ticket in range(2, 4099):
            t.release(ticket, count=4099 - ticket)
        t.release()
        self.execute("many-leases", t)

    def test_08_private_child_admission_rollback_and_exact_text(self):
        t = Trace().create()
        t.add(1, opening(4), INVALID, "wrong-private-context-slot-refusal")
        t.add(5, lease(5), lr(), "failed-open-clone-rolled-back")
        t.open(generation=2, ticket=3)
        values = [b"", b"\0", b"\r\n", b"\n", b"\r", "⚠️ ".encode(), "é".encode(), "e\u0301".encode(), "🙂\U0010ffff".encode()]
        for value in values + values[::-1]:
            t.add(1, scope(3, 2, payload=value), sr(generation=2, ticket=3), "original-exact-hint")
        t.add(1, scope(4, 2), sr(generation=2, ticket=3, tag=4, payload=hints(*values)), "original-exact-first-order-dedup")
        t.close(generation=2).release()
        self.execute("private-admission", t)

    def test_09_separate_native_processes_own_separate_sessions(self):
        def one(index):
            value = ("independent cache " + str(index)).encode()
            t = Trace().create().open()
            t.add(1, scope(9, payload=cq(2, b"same-key", value)), sr(tag=5, payload=cr()), "original-independent-session-set")
            t.add(1, scope(9, payload=cq(1, b"same-key")), sr(tag=5, payload=cr(value)), "original-independent-session-get")
            t.close().release()
            return self.execute("process-" + str(index), t)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [executor.submit(one, index) for index in range(2)]
            for future in results:
                future.result()

    def test_10_short_output_refuses_before_owner_mutation(self):
        t = Trace()
        t.add("5@0000003f", creating(), CAPACITY, "short-output-cache-create-refusal")
        t.create()
        t.add("1@0000003f", opening(), CAPACITY, "short-output-open-refusal")
        t.add(5, lease(5), lr(), "open-refusal-did-not-retain")
        t.open()
        t.add("5@0000003f", lease(2), CAPACITY, "short-output-clone-refusal")
        t.add(5, lease(5), lr(count=2), "clone-refusal-count-preserved")
        t.add("1@0000003f", scope(3, payload=b"not appended"), CAPACITY, "short-output-push-refusal")
        t.add(1, scope(3, payload=b"keep"), sr(), "original-push")
        t.add("1@00000060", scope(4), CAPACITY, "short-output-drain-refusal")
        t.add(1, scope(4), sr(tag=4, payload=hints(b"keep")), "original-drain-after-capacity-refusal")
        t.add("1@0000005f", scope(9, payload=cq(2, b"key", b"not stored")), CAPACITY, "short-output-scope-cache-refusal")
        t.add("5@0000005f", lease(4, payload=cq(2, b"key", b"not stored")), CAPACITY, "short-output-owned-cache-refusal")
        t.add(1, scope(9, payload=cq(1, b"key")), sr(tag=5, payload=cr()), "cache-capacity-refusals-did-not-set")
        t.add("1@0000003f", scope(7), CAPACITY, "short-output-close-refusal")
        t.add("1@0000003f", scope(8, 1, 0, a=2), CAPACITY, "short-output-cancel-refusal")
        t.add(1, scope(2), sr(tag=1), "scope-remains-active-after-short-output")
        t.add("5@0000003f", lease(3), CAPACITY, "short-output-release-refusal")
        t.add(5, lease(5), lr(count=2), "release-refusal-count-preserved")
        t.close().release()
        self.execute("short-output", t)

    def test_11_handed_off_publisher_lease_survives_request_cancel(self):
        t = Trace().create().open()
        t.add(1, scope(9, payload=cq(2, b"key", b"committed")), sr(tag=5, payload=cr()), "original-cache-commit-before-handoff")
        t.add(5, lease(2, ticket=2), lr(3, 3), "original-worker-owned-arc-clone-from-request")
        t.add(1, scope(3, payload=b"discard request-only hint"), sr(), "original-request-owned-hint")
        t.add(1, scope(5), sr(continuation=2, phase=2), "continuation-yield-adapter")
        t.add(1, scope(8, 1, 0, a=2), sr(1, 2, 3, epoch=0, ticket=0), "cancel-releases-only-request-lease")
        t.release(1, count=1)
        t.add(5, lease(4, ticket=3, payload=cq(1, b"key")), lr(3, 1, payload=cr(b"committed")), "original-worker-retains-cache-after-cancel-and-session-drop")
        t.add(1, scope(6, continuation=2), sr(1, 2, 0, 3, 0, 0), "late-request-completion-only-retires")
        t.add(5, lease(5, ticket=3), lr(3, 1), "late-request-completion-did-not-release-worker")
        t.add(5, lease(4, ticket=3, payload=cq(5)), lr(3, 1, payload=cr()), "original-worker-owned-forget-all")
        t.release(3)
        t.add(5, lease(5, ticket=3), STATE, "worker-completion-consumes-only-own-lease")
        self.execute("publisher-handoff", t)

    def test_12_failed_init_does_not_destroy_preexisting_context(self):
        def context(op, payload=b""):
            return b"HRCXQ001" + struct.pack("<3Q", op, len(payload), 0) + payload
        unit = b"HRCXR001" + struct.pack("<3Q", 0, 0, 0)
        associated = b"HRCXR001" + struct.pack("<4Q", 3, 1, 8, 123)
        t = Trace().create()
        t.add(3, context(1), unit, "existing-context-control-setup")
        t.add(3, context(2, struct.pack("<Q", 123)), unit, "existing-context-control-setup")
        t.add(3, context(4, b"preserve preexisting owner"), unit, "existing-context-control-setup")
        t.add(1, opening(), STATE, "failed-init-must-not-destroy-existing-context")
        t.add(5, lease(5), lr(), "failed-init-releases-only-new-clone")
        t.add(3, context(6), hints(b"preserve preexisting owner"), "existing-context-control-observation")
        t.add(3, context(7), associated, "existing-context-control-observation")
        t.add(3, context(3), unit, "existing-context-control-own-cleanup")
        t.add(3, context(8), unit, "existing-context-control-own-cleanup")
        t.open(generation=2, ticket=3)
        t.add(1, scope(4, 2), sr(generation=2, ticket=3, tag=4, payload=hints()), "original-new-scope-empty-after-explicit-own-cleanup")
        t.close(generation=2).release()
        self.execute("preexisting-context", t)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LifecycleTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {"schema": "hepta.runtime.request-scope-lifecycle-native-corpus.v1",
               "status": "PASS" if result.wasSuccessful() else "FAIL", "groups": result.testsRun,
               "native_elf_processes": len(RUNS), "native_elf_requests": sum(v["requests"] for v in RUNS.values()),
               "native_refusals": sum(v["expected_refusals"] for v in RUNS.values()),
               "binding": getattr(LifecycleTests, "binding", None), "runs": RUNS,
               "original_rust_processes": 0, "production_dispatcher_installed": False,
               "legacy_callers_replaced": False, "unbounded_cache_storage_closed": False}
    raw = (json.dumps(summary, sort_keys=True) + "\n").encode()
    if getattr(LifecycleTests, "corpus", None):
        with (LifecycleTests.corpus / "native-corpus.json").open("xb") as handle:
            handle.write(raw)
    sys.stdout.buffer.write(raw)
    raise SystemExit(0 if result.wasSuccessful() else 1)
