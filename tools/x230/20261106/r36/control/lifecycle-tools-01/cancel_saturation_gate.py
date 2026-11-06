#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Finite local gate for exact existing-job status requests in one private canary.

The gate holds only the original local transport child, before exec of the
unchanged private SSH wrapper. Start/cancel commands never match its frozen
status-command hash. The remote job fixture and all effect calls are unchanged.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import stat
import time

HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
COUNT = 32
NORMAL_ADMITTED = 16
NORMAL_CHILDREN = 8
GATE_SECONDS = 8
READY_SECONDS = 3


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.geteuid() and not before.st_mode & 0o077
             and before.st_size <= maximum, "unsafe owned gate file")
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "gate file changed")
        return raw
    finally:
        os.close(fd)


def identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(") ") + 2:].split()
    need(int(raw.split("(", 1)[0]) == pid and len(fields) >= 20, "invalid process identity")
    return {"pid": pid, "birth_ticks": int(fields[19]), "parent_pid": int(fields[1]), "state": fields[0], "raw_stat": raw}


def retire_config(root, expected_sha, controller, nonce):
    """Retain the immutable proof after the caller has drained every pressure RPC."""
    root = Path(root)
    started = time.monotonic_ns()
    raw = read(root / "config.json")
    config = json.loads(raw)
    release_raw = read(root / "release.json", 4096)
    release = json.loads(release_raw)
    need(sha(raw) == expected_sha and config["controller"] == release["controller"] == controller
         and config["nonce"] == release["nonce"] == nonce, "gate retirement binding changed")
    target = root / "config.closed.json"
    need(not os.path.lexists(target), "gate configuration was already retired")
    os.rename(root / "config.json", target)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(read(target) == raw and not os.path.lexists(root / "config.json"), "gate retirement did not preserve the original proof")
    return {"config_file":"config.closed.json", "config_sha256":expected_sha,
            "release_sha256":sha(release_raw), "start_monotonic_ns":started,
            "end_monotonic_ns":time.monotonic_ns(), "directory_synced":True}


# This program has no general gate selector. The only admitted predicate is the
# fixed command hash plus the exact original request/target and controller birth.
WRAPPER = r'''#!/usr/bin/python3
import hashlib, json, os, pathlib, stat, sys, time
ROOT = pathlib.Path(__ROOT__)
REAL = __REAL__
STATUS_SHA = __STATUS_SHA__
def need(value, reason):
    if not value: raise RuntimeError(reason)
def read(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and not info.st_mode & 0o077 and info.st_size <= maximum, 'unsafe gate input')
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size and os.fstat(fd).st_mtime_ns == info.st_mtime_ns, 'gate input changed')
        return raw
    finally: os.close(fd)
def birth(pid):
    raw = pathlib.Path('/proc/%d/stat' % pid).read_text()
    fields = raw[raw.rfind(') ') + 2:].split()
    return int(fields[19]), int(fields[1]), fields[0]
def exec_real(raw=None):
    if raw is not None:
        fd = os.memfd_create('hepta-saturation-status-stdin', os.MFD_CLOEXEC)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view); need(written > 0, 'short status payload write'); view = view[written:]
            os.lseek(fd, 0, os.SEEK_SET)
            os.dup2(fd, 0, inheritable=True)
        finally: os.close(fd)
    os.execv(REAL, [REAL, *sys.argv[1:]])
command = sys.argv[-1] if len(sys.argv) > 1 else ''
if hashlib.sha256(command.encode()).hexdigest() != STATUS_SHA or not (ROOT / 'config.json').exists():
    exec_real()
config_raw = read(ROOT / 'config.json')
config = json.loads(config_raw)
raw = sys.stdin.buffer.read(65537)
need(len(raw) <= 65536, 'status payload exceeds fixed gate bound')
q = json.loads(raw)
matches = [host for host, item in config['bindings'].items()
           if q == item['request'] and len(sys.argv) > 2 and sys.argv[-2] == item['ssh_target']]
if not matches: exec_real(raw)
need(len(matches) == 1 and config['status_command_sha256'] == STATUS_SHA, 'ambiguous status predicate')
host = matches[0]
controller = config['controller']
need(os.getppid() == controller['pid'] and birth(controller['pid'])[0] == controller['birth_ticks'], 'controller binding changed')
pid = os.getpid(); born, parent, state = birth(pid)
row = {'host':host,'pid':pid,'birth_ticks':born,'parent_pid':parent,'controller':controller,
       'nonce':config['nonce'],'config_sha256':hashlib.sha256(config_raw).hexdigest(),
       'request':q,'raw_request_sha256':hashlib.sha256(raw).hexdigest(),
       'status_command_sha256':STATUS_SHA,'ready_monotonic_ns':time.monotonic_ns()}
path = ROOT / ('ready-%d-%d.json' % (pid, born))
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n'); stream.flush(); os.fsync(stream.fileno())
while True:
    if (ROOT / 'release.json').exists():
        release = json.loads(read(ROOT / 'release.json', 4096))
        need(release['nonce'] == config['nonce'] and release['controller'] == controller, 'gate release binding changed')
        break
    need(time.monotonic_ns() < config['expires_monotonic_ns'], 'owned status gate expired without release')
    need(os.getppid() == controller['pid'] and birth(controller['pid'])[0] == controller['birth_ticks'], 'controller ended while gate held')
    time.sleep(.002)
exec_real(raw)
'''


def install_wrapper(wrapper, out, predicate_path):
    wrapper, out = Path(wrapper), Path(out)
    predicate_raw = Path(predicate_path).read_bytes()
    predicate = json.loads(predicate_raw)
    need(predicate["schema"] == "hepta-r25-fixed-status-predicate/v1", "wrong frozen status predicate")
    root = out / "saturation-gate"
    root.mkdir(mode=0o700)
    real = wrapper.with_name("ssh-original")
    need(not os.path.lexists(real), "original wrapper destination exists")
    original = wrapper.read_bytes()
    os.rename(wrapper, real)
    script = WRAPPER.replace("__ROOT__", repr(str(root))).replace("__REAL__", repr(str(real))).replace(
        "__STATUS_SHA__", repr(predicate["remote_command_sha256"])).encode()
    create(wrapper, script, 0o700)
    return wrapper, {"script_sha256":sha(script), "script_bytes":len(script),
                     "original_wrapper_sha256":sha(original), "original_wrapper_bytes":len(original),
                     "predicate_sha256":sha(predicate_raw), "predicate":predicate,
                     "gate_directory":"saturation-gate", "maximum_gate_seconds":GATE_SECONDS,
                     "only_exact_original_status_predicate":True, "gates_effect_commands":False}


class Pressure:
    def __init__(self, out, active, report, requests, native):
        self.out, self.active, self.report = Path(out), active, report
        self.root = self.out / "saturation-gate"
        self.native, self.requests = native, requests
        self.pool = None
        self.futures = []
        self.closed = False
        self.controller = {"pid":active.child.pid, "birth_ticks":active.birth}
        self.result = {"schema":"hepta-r25-cancel-saturation/v1", "passed":False,
                       "pressure_count":COUNT, "normal_admitted":NORMAL_ADMITTED,
                       "normal_children":NORMAL_CHILDREN, "calls":[], "snapshots":[],
                       "only_confirmed_original_keys":True, "automatic_retries":0}
        report["saturation"] = self.result

    def response(self, index, host, metadata):
        value = self.native(host, "process_start", self.requests[host],
                            phase_override="saturation_pressure", call_metadata=metadata)
        need(value.get("reused") is True and value.get("retried_launch") is False
             and value.get("launch") is None and value["job"]["id"] == self.report["hosts"][host]["job_id"],
             "pressure was not exact observation-only reuse")
        state = value["status"].get("state")
        need(state in {"status_unavailable", "running", "cancelled"}, "unexpected pressure status")
        return {"index":index, "host":host, "sequence":metadata["sequence"], "result":value}

    def snapshot(self, label):
        started = time.monotonic_ns()
        current = identity(self.controller["pid"])
        need(current["birth_ticks"] == self.controller["birth_ticks"] and current["state"] != "Z",
             "owned controller ended during saturation")
        rows = []
        for path in sorted(self.root.glob("ready-*.json")):
            raw = read(path)
            row = json.loads(raw)
            now = identity(row["pid"])
            need(now["birth_ticks"] == row["birth_ticks"] and now["parent_pid"] == self.controller["pid"]
                 and now["state"] != "Z" and row["controller"] == self.controller
                 and row["nonce"] == self.report["nonce"], "ordinary original transport changed")
            rows.append({"ready_file":path.name, "ready_bytes":len(raw), "ready_sha256":sha(raw),
                         "ready":row, "observed":now})
        snapshot = {"label":label, "start_monotonic_ns":started,
                    "end_monotonic_ns":time.monotonic_ns(), "controller":current, "held_children":rows}
        self.result["snapshots"].append(snapshot)
        return snapshot

    def begin(self):
        now = time.monotonic_ns()
        bindings = {}
        for host in HOSTS:
            record = self.report["hosts"][host]["launch"]["job"]
            need(record["launch_state"] == "launched" and record.get("system_jobctl") is False,
                 "gate requires the qualified operator fixture backend")
            bindings[host] = {"ssh_target":record["ssh_target"], "request":{
                "job_id":record["id"], "job_dir":record["remote_job_dir"],
                "request_digest":record["request_digest"], "unit":record["unit"], "wait_seconds":0}}
        config = {"nonce":self.report["nonce"], "controller":self.controller, "bindings":bindings,
                  "created_monotonic_ns":now, "expires_monotonic_ns":now + GATE_SECONDS * 10**9,
                  "status_command_sha256":self.report["saturation_wrapper"]["predicate"]["remote_command_sha256"]}
        raw = canonical(config)
        create(self.root / "config.json", raw)
        self.result["config"] = {"bytes":len(raw), "sha256":sha(raw), "value":config}
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=COUNT)
        for index in range(COUNT):
            host, metadata = HOSTS[index % len(HOSTS)], {}
            self.futures.append(self.pool.submit(self.response, index, host, metadata))
        until = time.monotonic() + READY_SECONDS
        while True:
            done = [future for future in self.futures if future.done()]
            completed = [future.result() for future in done]
            need(all(row["result"]["status"]["state"] == "status_unavailable" for row in completed),
                 "a pressure status escaped its owned gate")
            ready = list(self.root.glob("ready-*.json"))
            need(len(ready) <= NORMAL_CHILDREN and len(done) <= COUNT - NORMAL_ADMITTED,
                 "ordinary direct bound or expected refusal count differs")
            if len(done) == COUNT - NORMAL_ADMITTED and len(ready) == NORMAL_CHILDREN:
                break
            need(time.monotonic() < until, "normal 8/16 saturation was not observed in the fixed readiness budget")
            time.sleep(.002)
        snap = self.snapshot("before_cancel")
        self.result["refused_before_cancel"] = completed
        self.result["pending_before_cancel"] = len(self.futures) - len(done)
        self.result["saturated_monotonic_ns"] = snap["end_monotonic_ns"]
        self.result["cancel_start_budget_remaining_ms"] = (config["expires_monotonic_ns"] - time.monotonic_ns()) / 1e6

    def after_cancel(self):
        snap = self.snapshot("after_all_six_cancel_acks")
        need(len(snap["held_children"]) == NORMAL_CHILDREN
             and [r["ready"] for r in snap["held_children"]]
             == [r["ready"] for r in self.result["snapshots"][0]["held_children"]],
             "ordinary ownership changed before cancel proof completed")
        need(sum(future.done() for future in self.futures) == COUNT - NORMAL_ADMITTED,
             "ordinary capacity drained before all cancellation acknowledgements")
        need(time.monotonic_ns() < self.result["config"]["value"]["expires_monotonic_ns"],
             "cancel proof exceeded the fixed gate deadline")
        self.result["cancel_acks_before_release"] = True

    def release_and_drain(self):
        if self.closed:
            return
        release = {"nonce":self.report["nonce"], "controller":self.controller,
                   "released_monotonic_ns":time.monotonic_ns()}
        create(self.root / "release.json", canonical(release))
        self.result["release"] = release
        errors, rows = [], []
        try:
            for future in self.futures:
                try:
                    rows.append(future.result(timeout=50))
                except BaseException as error:
                    errors.append({"type":type(error).__name__, "reason":str(error)[:2000]})
        finally:
            if self.pool is not None:
                self.pool.shutdown(wait=True)
            self.closed = True
        self.result["calls"] = sorted(rows, key=lambda row:row["index"])
        self.result["drain_errors"] = errors
        self.result["drained_monotonic_ns"] = time.monotonic_ns()
        need(not errors and len(rows) == COUNT, "pressure calls did not drain exactly once")
        unavailable = sum(row["result"]["status"]["state"] == "status_unavailable" for row in rows)
        self.result["status_unavailable_count"] = unavailable
        need(unavailable == COUNT - NORMAL_ADMITTED and self.result.get("cancel_acks_before_release") is True,
             "saturation or cancellation proof did not complete before drain")
        self.result["retirement"] = retire_config(
            self.root, self.result["config"]["sha256"], self.controller, self.report["nonce"])
        self.result["passed"] = True
