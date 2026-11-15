#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Reject incomplete, late, rebound and replaying saturation evidence offline."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import audit_native_evidence as evidence
import verify_saturation_extension as audit


def proc(pid, parent, born):
    fields = ["0"] * 20
    fields[0], fields[1], fields[19] = "S", str(parent), str(born)
    return {"pid":pid,"parent_pid":parent,"birth_ticks":born,"state":"S",
            "raw_stat":f"{pid} (owned fixture) " + " ".join(fields)}


class EvidenceFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-r25-proof-test-")
        self.root = Path(self.temporary.name)
        gate, binary = self.root / "saturation-gate", self.root / "bin"
        gate.mkdir()
        binary.mkdir()
        controller = {"pid":1000,"birth_ticks":10}
        hosts = tuple(audit.HOST_COUNTS)
        report = {"nonce":"fixture", "after_crash_startup":controller,
                  "after_cancel_startup":{"start_monotonic_ns":5000},
                  "hosts":{}, "native_calls":[]}
        bindings = {}
        for host in hosts:
            record = {"id":host+"-original","remote_job_dir":"/owned/jobs/"+host+"-original",
                      "unit":host+"-unit","request_digest":"a"*64,"ssh_target":host+".invalid",
                      "launch_state":"launched","system_jobctl":False}
            report["hosts"][host] = {"launch":{"job":record}}
            bindings[host] = {"ssh_target":record["ssh_target"],"request":{
                "job_id":record["id"],"job_dir":record["remote_job_dir"],"unit":record["unit"],
                "request_digest":record["request_digest"],"wait_seconds":0}}
        config = {"nonce":"fixture","controller":controller,"bindings":bindings,
                  "created_monotonic_ns":100,"expires_monotonic_ns":8_000_000_100,
                  "status_command_sha256":"c"*64}
        config_raw = evidence.canonical(config)
        (gate / "config.closed.json").write_bytes(config_raw)
        for name in ("ssh","ssh-original"):
            (binary / name).write_bytes(name.encode())
        wrapper = {"script_bytes":3,"script_sha256":evidence.sha(b"ssh"),
                   "original_wrapper_bytes":12,"original_wrapper_sha256":evidence.sha(b"ssh-original"),
                   "gates_effect_commands":False,"only_exact_original_status_predicate":True,
                   "maximum_gate_seconds":8,"predicate":{"remote_command_sha256":"c"*64}}
        report["saturation_wrapper"] = wrapper
        held = []
        for index in range(8):
            host = hosts[index % 6]
            ready = {"pid":2000+index,"birth_ticks":20+index,"parent_pid":1000,
                     "controller":controller,"host":host,"nonce":"fixture",
                     "config_sha256":evidence.sha(config_raw),"status_command_sha256":"c"*64,
                     "request":bindings[host]["request"],"ready_monotonic_ns":500+index}
            raw = evidence.canonical(ready)
            name = f"ready-{ready['pid']}-{ready['birth_ticks']}.json"
            (gate / name).write_bytes(raw)
            held.append({"ready":ready,"ready_file":name,"ready_bytes":len(raw),
                         "ready_sha256":evidence.sha(raw),"observed":proc(2000+index,1000,20+index)})
        snapshots = [{"label":name,"start_monotonic_ns":start,"end_monotonic_ns":start+100,
                      "controller":proc(1000,99,10),"held_children":copy.deepcopy(held)}
                     for name,start in (("before_cancel",1000),("after_all_six_cancel_acks",2000))]
        calls = []
        for index in range(32):
            host, sequence = hosts[index%6], index+1
            dto = {"reused":True,"retried_launch":False,"launch":None,
                   "job":report["hosts"][host]["launch"]["job"],
                   "status":{"state":"status_unavailable" if index<16 else "cancelled"}}
            calls.append({"index":index,"sequence":sequence,"host":host,"result":dto})
            report["native_calls"].append({"sequence":sequence,"phase":"saturation_pressure",
                "host":host,"tool":"process_start","controller_directory":"after-crash-controller",
                "end_monotonic_ns":950 if index<16 else 3100,
                "rpc":{"send_end_monotonic_ns":600,"rpc_end_monotonic_ns":900 if index<16 else 3000}})
        for host in hosts:
            report["native_calls"].append({"phase":"concurrent_cancel","host":host,"tool":"process_cancel",
                                           "start_monotonic_ns":1200,"end_monotonic_ns":1800})
        release = {"nonce":"fixture","controller":controller,"released_monotonic_ns":2200}
        (gate / "release.json").write_bytes(evidence.canonical(release))
        report["saturation"] = {"schema":"hepta-r25-cancel-saturation/v1","passed":True,
            "pressure_count":32,"normal_admitted":16,"normal_children":8,"drain_errors":[],
            "automatic_retries":0,"only_confirmed_original_keys":True,
            "config":{"value":config,"bytes":len(config_raw),"sha256":evidence.sha(config_raw)},
            "calls":calls,"snapshots":snapshots,"status_unavailable_count":16,
            "pending_before_cancel":16,"refused_before_cancel":copy.deepcopy(calls[:16]),
            "release":release,"cancel_acks_before_release":True,"drained_monotonic_ns":4000}
        report["saturation"]["retirement"] = {"config_file":"config.closed.json",
            "config_sha256":evidence.sha(config_raw),"release_sha256":evidence.sha(evidence.canonical(release)),
            "start_monotonic_ns":4200,"end_monotonic_ns":4300,"directory_synced":True}
        self.report = report

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_fixture_accepts_exact_counts(self):
        value = audit.verify(self.report, self.root)
        self.assertTrue(value["verified"])
        self.assertEqual(value["normal_pressure_calls"],32)
        self.assertEqual(value["cancel_acks_before_release"],6)

    def test_replay_wrong_original_duplicate_or_missing_pressure_refuses(self):
        changes = [
            lambda r:r["saturation"]["calls"][0]["result"].update(retried_launch=True),
            lambda r:r["saturation"]["calls"][0]["result"].update(job={"id":"replacement"}),
            lambda r:r["saturation"]["calls"][0].update(sequence=2),
            lambda r:r["saturation"]["calls"].pop(),
            lambda r:r["saturation"].update(pending_before_cancel=15),
        ]
        for change in changes:
            altered = copy.deepcopy(self.report)
            change(altered)
            with self.assertRaises(ValueError):
                audit.verify(altered,self.root)

    def test_late_pressure_or_cancel_outside_held_interval_refuses(self):
        for index,key in ((0,"rpc"),(32,"start_monotonic_ns"),(32,"end_monotonic_ns")):
            altered = copy.deepcopy(self.report)
            if key == "rpc":
                altered["native_calls"][index][key]["send_end_monotonic_ns"] = 1500
            else:
                altered["native_calls"][index][key] = 800 if key.startswith("start") else 2500
            with self.assertRaises(ValueError):
                audit.verify(altered,self.root)

    def test_rebound_or_terminal_held_original_refuses(self):
        for changed in ({"parent_pid":999},{"birth_ticks":999},{"state":"Z"}):
            altered = copy.deepcopy(self.report)
            altered["saturation"]["snapshots"][1]["held_children"][0]["observed"].update(changed)
            with self.assertRaises(ValueError):
                audit.verify(altered,self.root)

    def test_early_release_refuses_even_if_file_matches_claim(self):
        altered = copy.deepcopy(self.report)
        altered["saturation"]["release"]["released_monotonic_ns"] = 1500
        (self.root / "saturation-gate/release.json").write_bytes(evidence.canonical(altered["saturation"]["release"]))
        with self.assertRaises(ValueError):
            audit.verify(altered,self.root)


if __name__ == "__main__":
    unittest.main()
