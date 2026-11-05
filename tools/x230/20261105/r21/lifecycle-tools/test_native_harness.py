#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local fake-MCP and synthetic /proc tests; no SSH or HeptaRuntime execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import allocator_environment as allocator
import allocator_environment_audit as allocator_audit
import audit_native_evidence as audit
import observation_resources as resources
import run_native_observation as wrapper
import x230_observation_benchmark as bench

FAKE = '''#!/usr/bin/python3
import json,sys
for line in sys.stdin.buffer:
    request=json.loads(line)
    if "id" not in request: continue
    if request["method"]=="initialize":
        result={"protocolVersion":"2025-03-26","serverInfo":{"name":"fake-selftest","version":"1"}}
    else:
        args=request["params"]["arguments"]
        data=("SELFTEST-"+args["host"]+"\\n").encode()
        dto={"job_id":args["job_id"],"audit_recorded":True}
        if request["params"]["name"]=="process_status":
            dto.update(state="succeeded",exit_code=0,output_complete=True,cancelled=False,timed_out=False,
                log_bytes={"stdout":{"seen":len(data),"stored":len(data)},"stderr":{"seen":0,"stored":0}},
                log_truncated={"stdout":False,"stderr":False},log_errors={"stdout":None,"stderr":None})
        else:
            for name,raw in (("stdout",data),("stderr",b"")):
                dto[name]={"bytes_hex":raw.hex(),"offset":0,"next_offset":len(raw),"size":len(raw),"eof":True}
        result={"content":[{"type":"text","text":json.dumps(dto)}],"isError":False}
    reply={"jsonrpc":"2.0","id":request["id"],"result":result}
    # Spaces deliberately differ from producer canonical hashing.
    sys.stdout.write(json.dumps(reply,separators=(", ",": "))+"\\n")
    sys.stdout.flush()
'''


class HarnessTests(unittest.TestCase):
    def test_allocator_match_is_enforced_independently(self):
        binaries = {"A": "a" * 64, "B": "b" * 64}
        value = allocator.run_metadata({arm: allocator.configured(1) for arm in "AB"}, binaries)
        value.update(comparison_contract="same-allocator-two-binaries/v1", same_allocator_environment=True)
        allocator_audit.validate_metadata(value, binaries, {"A", "B"})
        changed = copy.deepcopy(value)
        changed["variants"]["A"]["environment"] = {}
        with self.assertRaises(ValueError):
            allocator_audit.validate_metadata(changed, binaries, {"A", "B"})
        parent = {"MALLOC_ARENA_MAX": "4", "GLIBC_TUNABLES": "glibc.malloc.arena_max=2", "SSH_AUTH_SOCK": "/fake/agent"}
        original = dict(parent)
        for arm in "AB":
            child = allocator.child_environment(parent, value["variants"][arm]["environment"])
            self.assertEqual(child, {"MALLOC_ARENA_MAX": "1", "SSH_AUTH_SOCK": "/fake/agent"})
        self.assertEqual(parent, original)

    def test_profile_bound_topology_and_original_registry_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            jobs = []
            for host in sorted(bench.HOSTS):
                raw = b"not reserialized\n"
                jobs.append({"host": host, "id": "job-" + host, "record_bytes": raw,
                    "record": {"ssh_target": "unused-" + host, "remote_job_dir": "/unused/jobs/job-" + host}})
            profile = Path(temporary) / "profile.json"
            profile.write_text("{}\n")
            manifest = {"schema": "hepta-x230-benchmark-topology/v1", "profile_template_sha256": audit.sha(profile.read_bytes()),
                        "hosts": {host: {"platform": "macos" if host in {"main", "mac"} else "linux",
                                         "machine_group": "mac" if host == "main" else host} for host in bench.HOSTS}}
            manifest_path = Path(temporary) / "topology.json"
            manifest_path.write_text(json.dumps(manifest))
            raw, topology = bench.load_topology(manifest_path, profile)
            self.assertEqual(topology["physical_machine_groups"], 5)
            prepared = {host: {"prepare": {"platform": "darwin" if item["platform"] == "macos" else "linux",
                                           "hostname": item["machine_group"]}} for host, item in manifest["hosts"].items()}
            self.assertEqual(bench.check_prepared_topology(prepared, topology)["distinct_reported_hostnames"], 5)
            altered = copy.deepcopy(prepared)
            altered["main"]["prepare"]["hostname"] = "unexpected-independent-host"
            with self.assertRaisesRegex(RuntimeError, "grouping"):
                bench.check_prepared_topology(altered, topology)
            root = Path(temporary) / "fixture"
            config = json.loads(bench.fixture(root, jobs, topology).read_bytes())
            self.assertEqual(config["hosts"]["main"]["platform"], "macos")
            self.assertEqual(config["hosts"]["mac"]["platform"], "macos")
            for job in jobs:
                self.assertEqual((root / "state/jobs" / (job["id"] + ".json")).read_bytes(), job["record_bytes"])
                for key in ("allow_execute", "allow_pty", "allow_write", "allow_job_network"):
                    self.assertIs(config["hosts"][job["host"]][key], False)
            manifest["hosts"]["main"] = {"platform": "linux", "machine_group": "main-linux"}
            manifest_path.write_text(json.dumps(manifest))
            raw, topology = bench.load_topology(manifest_path, profile)
            self.assertEqual(topology["physical_machine_groups"], 6)
            changed_config = json.loads(bench.fixture(Path(temporary) / "other-profile-fixture", jobs, topology).read_bytes())
            self.assertEqual(changed_config["hosts"]["main"]["platform"], "linux")
            projected = {"topology": topology, "profile": {"template_sha256": manifest["profile_template_sha256"]},
                         "topology_manifest_unchanged": True}
            self.assertTrue(audit.topology(Path(temporary), projected)["verified"])
            profile.write_text('{"changed":true}\n')
            with self.assertRaisesRegex(RuntimeError, "profile/alias"):
                bench.load_topology(manifest_path, profile)

    def test_complete_transport_clocks_and_raw_resource_audit(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": "/selftest-unused-agent"}):
            root = Path(temporary)
            executable = root / "fake-mcp"
            executable.write_text(FAKE)
            executable.chmod(0o700)
            jobs, originals = [], {}
            for host in sorted(bench.HOSTS):
                data = ("SELFTEST-" + host + "\n").encode()
                jobs.append({"host": host, "id": "job-" + host, "expected": data})
                originals[host] = {"job_id": "job-" + host, "stdout_bytes": len(data), "stdout_sha256": audit.sha(data)}
            result = {"cells": []}
            for phase in ("first", "restart"):
                directory = root / phase
                directory.mkdir()
                try:
                    controller = bench.Controller(executable, root / "unused-config", root / "unused-profile", directory, 2,
                                                  allocator_values=allocator.configured(1))
                except PermissionError as error:
                    if error.errno == 13 and str(error.filename).endswith("/environ"):
                        self.skipTest("this executor denies child /proc/environ; run the unmodified test on X230")
                    raise
                try:
                    if phase == "first":
                        result["startup"] = controller.startup
                        result["initial_complete_outputs"] = [controller.call("process_read", j, "preflight_complete_output") for j in jobs]
                        result["cells"].append(wrapper.cell(controller, jobs, 2, 12))
                    else:
                        result["restart_startup"] = controller.startup
                        result["restart_checks"] = [controller.call(t, j, "restart_same_original")
                                                    for j in jobs for t in ("process_status", "process_read")]
                finally:
                    result["shutdown" if phase == "first" else "restart_shutdown"] = controller.close()
            verified = audit.audit_round(root, result, originals)
            self.assertEqual(verified["transport"]["rpc_envelopes_independently_verified"], 56)
            self.assertEqual(verified["transport"]["frames_rehashed"], 56)
            row = result["cells"][0]["rows"][0]
            self.assertNotEqual(row["response_sha256"], row["rpc"]["transport_response"]["sha256"])
            changed = copy.deepcopy(result)
            changed["cells"][0]["rows"][0]["elapsed_ms"] += 1
            with self.assertRaisesRegex(ValueError, "latency"):
                audit.audit_round(root, changed, originals)
            changed = copy.deepcopy(result)
            changed["cells"][0]["raw_timing"]["controller_after"]["utime_ticks"] += 1
            with self.assertRaisesRegex(ValueError, "stat fields"):
                audit.audit_round(root, changed, originals)
            changed = copy.deepcopy(result)
            changed["cells"][0]["rows"][0]["dto_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "DTO"):
                audit.audit_round(root, changed, originals)
            raw_path = root / "first/transport-responses.jsonl"
            raw_path.write_bytes(raw_path.read_bytes().replace(b"fake-selftest", b"FAKE-selftest", 1))
            with self.assertRaisesRegex(ValueError, "hash changed"):
                audit.audit_round(root, result, originals)

    def test_ssh_descendant_cpu_survives_missing_fd_and_wrong_parent_is_excluded(self):
        # Synthetic /proc tree: 100 controller -> 101 ssh. PID 102 is stale/reused
        # and now belongs to a different parent; it must not be charged here.
        def counters(pid):
            now = time.monotonic_ns()
            parent, birth, user, system, comm = {
                100: (9, 10, 50, 10, "controller"),
                101: (100, 11, 20, 10, "ssh"),
                102: (999, 12, 999, 999, "other")}[pid]
            fields = ["0"] * 20
            fields[0], fields[1], fields[11], fields[12], fields[19] = "S", str(parent), str(user), str(system), str(birth)
            return {"pid": pid, "comm": comm, "ppid": parent, "birth_ticks": birth,
                "utime_ticks": user, "stime_ticks": system, "clock_ticks_per_second": 100,
                "read_start_monotonic_ns": now, "read_end_monotonic_ns": now,
                "raw_stat": f"{pid} ({comm}) " + " ".join(fields) + "\n"}
        original_read, original_iter = Path.read_text, Path.iterdir
        def read_text(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                if path.name == "status":
                    return "VmRSS:\t100 kB\nVmHWM:\t110 kB\n"
                if path.name == "children":
                    return "101 102" if str(path).startswith("/proc/100/") else ""
                raise AssertionError(str(path))
            return original_read(path, *args, **kwargs)
        def iterdir(path):
            if str(path).startswith("/proc/"):
                if str(path) == "/proc/101/fd":
                    raise PermissionError("synthetic denied FD directory")
                if path.name == "fd":
                    return iter([path / "0", path / "1", path / "2"])
                if path.name == "task":
                    return iter([path / path.parent.name])
                raise AssertionError(str(path))
            return original_iter(path)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(resources, "counters", side_effect=counters), \
                 mock.patch.object(Path, "read_text", read_text), mock.patch.object(Path, "iterdir", iterdir), \
                 mock.patch.object(resources.os, "readlink", side_effect=lambda p: "/usr/bin/ssh" if str(p) == "/proc/101/exe" else "/test/controller"):
                observer = resources.Resources(100, root, autostart=False)
                observer.sample()
                summary = observer.stop()
            self.assertEqual(summary["sampled_cpu_seconds_by_scope"]["controller"], .6)
            self.assertEqual(summary["sampled_cpu_seconds_by_scope"]["ssh_descendants"], .3)
            self.assertEqual(summary["sampled_process_generations"], 2)
            self.assertEqual(summary["error_counts"]["fd:PermissionError"], 1)
            self.assertEqual(summary["error_counts"]["ownership:ParentChanged"], 1)
            proof = audit.resources(root, summary, {"pid": 100, "birth_ticks": 10})
            self.assertEqual(proof["process_generations"], 2)
            changed = copy.deepcopy(summary)
            changed["sampled_cpu_seconds_by_scope"]["ssh_descendants"] = .9
            with self.assertRaisesRegex(ValueError, "CPU class"):
                audit.resources(root, changed, {"pid": 100, "birth_ticks": 10})


if __name__ == "__main__":
    unittest.main(verbosity=2)
