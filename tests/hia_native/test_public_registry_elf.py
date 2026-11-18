#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual fixed public registry, immutable administrator authority and framing.

These controls execute the kernel-loaded ELF. They do not provide synthetic
config/regex/SDK completions; the full original byte replay is a separate suite.
"""
from pathlib import Path
import argparse
import collections
import fcntl
import gzip
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_registry_cases import compact, configuration, fixture, initialize, metadata, request, tool

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = OUTPUT = None
COUNTS = collections.Counter()
TRANSCRIPT = None
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def observe(raw, reply, kind="request"):
    TRANSCRIPT.write(compact({"kind": kind, "request_hex": raw.hex(), "response_hex": reply.hex()}) + b"\n")
    TRANSCRIPT.flush()


def lock_is_free(path):
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    finally:
        os.close(fd)


class Session:
    def __init__(self, binary, config, *, stderr=subprocess.PIPE):
        self.process = subprocess.Popen([str(binary), "--runtime-config", str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
            env={"PATH": "", "LC_ALL": "C"}, start_new_session=True)
        self.pending = bytearray()
        COUNTS["actual_processes"] += 1

    def send(self, raw, ending=b"\n"):
        self.process.stdin.write(raw + ending)
        self.process.stdin.flush()

    def read(self):
        deadline = time.monotonic() + 30
        while b"\n" not in self.pending:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.process.stdout], [], [], left)[0]:
                raise AssertionError("actual public registry response deadline")
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise AssertionError(("actual public registry EOF", self.process.poll()))
            self.pending.extend(data)
        line, _, tail = self.pending.partition(b"\n")
        self.pending = bytearray(tail)
        COUNTS["actual_responses"] += 1
        return bytes(line)

    def call(self, raw, ending=b"\n"):
        self.send(raw, ending)
        reply = self.read()
        observe(raw + ending, reply)
        return json.loads(reply), reply

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=30)
        tail = self.process.stdout.read()
        error = b"" if self.process.stderr is None else self.process.stderr.read()
        assert (self.process.returncode, bytes(self.pending), tail, error) == (0, b"", b"", b"")

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is None:
                self.close()
        finally:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)


class PublicRegistryELF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_bytes())
        cls.binary = MANIFEST.parent / cls.manifest["executable"]
        elf = cls.binary.read_bytes()
        assert (len(elf), sha(elf)) == (cls.manifest["elf_bytes"], cls.manifest["elf_sha256"])
        assert sha((ROOT / "scripts/public_runtime_adapter.S").read_bytes()) == cls.manifest["adapter_source_sha256"]
        assert [m["id"] for m in cls.manifest["members"]] == list(range(17))
        for member in cls.manifest["members"]:
            path = Path(member["manifest"])
            manifest = json.loads(path.read_bytes())
            image = (path.parent / manifest["image"]).read_bytes()
            assert sha(path.read_bytes()) == member["manifest_sha256"]
            assert sha(image) == member["image_sha256"]
            assert sha((ROOT / member["source"]).read_bytes()) == member["source_sha256"]
            assert elf[member["offset"]:member["offset"] + len(image)] == image
        COUNTS["embedded_images_verified"] = 17

    def query(self, session, name="host_list", arguments=b"{}", *, error=False, meta=None):
        parsed, raw = session.call(tool(name, arguments, meta=meta))
        self.assertEqual(parsed["id"], 1)
        result = parsed["result"]
        self.assertEqual(result["isError"], error)
        self.assertEqual(len(result["content"]), 1)
        self.assertEqual(result["content"][0]["type"], "text")
        return result["content"][0]["text"], raw

    def test_01_immutable_config_and_real_lock_custody(self):
        with tempfile.TemporaryDirectory(prefix="hia-public-authority-", dir=OUTPUT) as td:
            root = Path(td)
            config = root / "config"
            config.write_bytes(compact(configuration(root / "state")))
            locks = [root / "state/controller.owner.lock", root / "state/controller.lock"]
            with Session(self.binary, config) as session:
                session.call(initialize("2025-06-18"))
                before, _ = self.query(session)
                count = len(list(Path(f"/proc/{session.process.pid}/fd").iterdir()))
                self.assertTrue(all(not lock_is_free(path) for path in locks))
                COUNTS["held_lock_controls"] += 2
                config.write_bytes(compact({"state_dir": str(root / "attacker"), "hosts": {}}))
                config.unlink()
                for args in [{"config": {"hosts": {}}}, {"runtime_config": str(config)},
                             {"state_dir": str(root / "attacker")}, {"host": "private-target"},
                             {"modern": True}, {"legacy": False}]:
                    self.query(session, arguments=compact(args), error=True)
                    self.assertEqual(self.query(session)[0], before)
                    self.assertEqual(len(list(Path(f"/proc/{session.process.pid}/fd").iterdir())), count)
                    COUNTS["immutable_authority_controls"] += 1
                self.assertFalse((root / "attacker").exists())
                self.query(session, "execution_shadow_admit", compact(fixture()))
            self.assertTrue(all(lock_is_free(path) for path in locks))
            COUNTS["eof_released_lock_controls"] += 2

    def test_02_persistent_mode_and_peer_replacement(self):
        with tempfile.TemporaryDirectory(prefix="hia-public-mode-", dir=OUTPUT) as td:
            root = Path(td)
            config = root / "config"
            config.write_bytes(compact(configuration(root / "state")))
            with Session(self.binary, config) as session:
                session.call(request("ping"))
                first, _ = session.call(request("tools/list", {"_meta": metadata()}))
                self.assertEqual(first["result"]["resultType"], "complete")
                session.call(initialize("2025-06-18", name="replacement"))
                missing, _ = session.call(tool("host_list"))
                self.assertIn("error", missing)
                modern, _ = session.call(tool("host_list", meta=metadata()))
                self.assertEqual(modern["result"]["resultType"], "complete")
                older, _ = session.call(tool("host_list", meta=metadata("2025-06-18")))
                self.assertNotIn("resultType", older["result"])
                COUNTS["actual_mode_transition_controls"] += 5

    def test_03_full_frame_crlf_and_final_eof(self):
        limit = 8388608
        with tempfile.TemporaryDirectory(prefix="hia-public-frame-", dir=OUTPUT) as td:
            root = Path(td)
            config = root / "config"
            config.write_bytes(compact(configuration(root / "state")))
            ping = request("ping", ident="at-limit")
            full = ping + b" " * (limit - len(ping))
            with Session(self.binary, config) as session:
                session.call(initialize())
                result, _ = session.call(full, b"\r\n")
                self.assertEqual((result["id"], result["result"]), ("at-limit", {}))
                session.send(b"", b"\r\n")
                session.send(b"{", b"\n")
                self.query(session)
                COUNTS["exact_8mib_frame_controls"] += 1
                COUNTS["ignored_transport_then_real_route_controls"] += 2
            payload = initialize() + b"\n" + full
            done = subprocess.run([str(self.binary), "--runtime-config", str(config)],
                input=payload, capture_output=True, timeout=30, env={"PATH": "", "LC_ALL": "C"})
            COUNTS["actual_processes"] += 1
            self.assertEqual((done.returncode, done.stderr), (0, b""))
            replies = done.stdout.splitlines()
            self.assertEqual(len(replies), 2)
            self.assertEqual(json.loads(replies[1])["id"], "at-limit")
            COUNTS["actual_responses"] += 2
            COUNTS["exact_8mib_final_eof_controls"] += 1
            observe(payload, done.stdout, "eof-frame")
            payload = initialize() + b"\n" + full + b" \n"
            done = subprocess.run([str(self.binary), "--runtime-config", str(config)],
                input=payload, capture_output=True, timeout=30, env={"PATH": "", "LC_ALL": "C"})
            COUNTS["actual_processes"] += 1
            self.assertEqual((done.returncode, done.stderr), (111, b""))
            self.assertEqual(len(done.stdout.splitlines()), 1)
            self.assertTrue(lock_is_free(root / "state/controller.owner.lock"))
            self.assertTrue(lock_is_free(root / "state/controller.lock"))
            COUNTS["actual_responses"] += 1
            COUNTS["overlong_fatal_no_partial_reply_controls"] += 1
            COUNTS["fatal_released_lock_controls"] += 2
            observe(payload, done.stdout, "overlong-frame")

    def test_04_large_id_and_value_population(self):
        with tempfile.TemporaryDirectory(prefix="hia-public-value-", dir=OUTPUT) as td:
            root = Path(td)
            config = root / "config"
            config.write_bytes(compact(configuration(root / "state")))
            with Session(self.binary, config) as session:
                session.call(initialize())
                ident = "\n\t\"😀" * 50000
                result, raw = session.call(tool("host_list", ident=ident))
                self.assertEqual(result["id"], ident)
                self.assertFalse(result["result"]["isError"])
                self.assertGreater(len(raw), 500000)
                COUNTS["large_escaped_id_controls"] += 1
                text, _ = self.query(session, arguments=b'{"x":[' + b",".join([b"0"] * 300000) + b"]}", error=True)
                self.assertEqual(text, "failed to deserialize parameters: unknown field `x`, there are no fields")
                COUNTS["above_old_parser_node_limit_controls"] += 1
                self.query(session, "execution_shadow_admit", compact(fixture()))

    def test_05_regex_startup_error_order_and_cli_authority(self):
        with tempfile.TemporaryDirectory(prefix="hia-public-startup-", dir=OUTPUT) as td:
            root = Path(td)
            config = root / "config"
            for i, pattern in enumerate([r"\p{Greek}+", "("]):
                state = root / str(i)
                value = configuration(state)
                value["hosts"]["h"]["privileged_actions"] = {"inspect": {"executable": "/echo",
                    "allow_extra_args": True, "extra_arg_patterns": [pattern]}}
                config.write_bytes(compact(value))
                if i == 0:
                    with Session(self.binary, config) as session:
                        session.call(initialize())
                        self.assertIn("inspect", self.query(session)[0])
                        summary = json.loads(self.query(session, "effective_config")[0])
                        self.assertEqual(summary["hosts"][0]["named_privileged_action_count"], 1)
                    COUNTS["actual_regex_configurations"] += 1
                else:
                    done = subprocess.run([str(self.binary), "--runtime-config", str(config)],
                        input=b"", capture_output=True, timeout=30, env={"PATH": "", "LC_ALL": "C"})
                    COUNTS["actual_processes"] += 1
                    self.assertEqual((done.returncode, done.stdout, done.stderr),
                        (78, b"", b"host `h` privileged action `inspect` has invalid argument regex\n"))
                    self.assertFalse(state.exists())
                    observe(b"", done.stderr, "startup-refusal")
                    COUNTS["regex_before_state_effect_refusals"] += 1
            for args in [["--modern"], ["--legacy"], ["--runtime-config", str(config), "--modern"],
                         ["--runtime-config", str(config), "--runtime-config", str(config)]]:
                done = subprocess.run([str(self.binary), *args], input=b"", capture_output=True,
                    timeout=30, env={"PATH": "", "LC_ALL": "C"})
                COUNTS["actual_processes"] += 1
                self.assertEqual((done.returncode, done.stdout, done.stderr), (64, b"", b""))
                COUNTS["caller_mode_cli_refusals"] += 1


def main():
    global MANIFEST, OUTPUT, TRANSCRIPT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    MANIFEST = args.manifest.resolve(strict=True)
    OUTPUT = args.output.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    manifest_before = sha(MANIFEST.read_bytes())
    source_before = sha(Path(__file__).read_bytes())
    started = time.monotonic()
    with gzip.open(OUTPUT / "transcript.jsonl.gz", "wb", compresslevel=6) as TRANSCRIPT:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicRegistryELF))
    unchanged = manifest_before == sha(MANIFEST.read_bytes()) and source_before == sha(Path(__file__).read_bytes())
    transcript = (OUTPUT / "transcript.jsonl.gz").read_bytes()
    report = {"schema": "hepta.public-registry.actual-elf-controls.v1",
        "status": "PASS" if result.wasSuccessful() and unchanged else "FAIL", "groups": result.testsRun,
        "elapsed_seconds": time.monotonic() - started, "counts": dict(COUNTS), "source_unchanged": unchanged,
        "manifest_sha256": manifest_before, "test_source_sha256": source_before,
        "transcript_sha256": sha(transcript), "transcript_bytes": len(transcript),
        "kernel_loaded_static_elf": True, "synthetic_child_completions": False,
        "original_rust_executed_here": False, "public_audit_result_lifecycle_closed": False}
    (OUTPUT / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
