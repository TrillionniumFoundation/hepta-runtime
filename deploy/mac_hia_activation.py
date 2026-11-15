#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Candidate protocol for a config-only macOS GUI HIA transition.

The executable, LaunchAgent, state roots, host policy, resource limits and
credentials are invariant.  This helper never executes a candidate binary or
calls HIA.  A qualified external admission must establish writer cooperation,
loaded baseline configuration, state compatibility and independent recovery.
Taking our flock does not establish any of those facts.

This is separate Python deployment code, not part of the 4cd runtime binary's
build qualification.  No production or macOS qualification is implied by the
offline tests.  Intent is durable before each effect; uncertain effects are
observed, not automatically retried or rolled back.
"""
import argparse
import contextlib
import ctypes
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import plistlib
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time


BASE_RUNTIME = "4cd85c99c5f5a480832c48fbde8561bb365f67a9"
# Original public Hepta online-readback checker; a different checker needs a
# separately reviewed helper revision. Never accept an arbitrary execution pin.
ONLINE_READBACK_CHECKER_SHA256 = "ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542"
PINNED_HELPERS = {
    "mcp_tool_contract": "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216",
    "stage_dc_successor": "80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582",
}
HERE = pathlib.Path(__file__).resolve().parent
HASH = re.compile(r"[0-9a-f]{64}")
OPERATION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}")
LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}")
PROFILE_KEYS = {"host", "working_directory", "python_executable", "state_root",
                "artifact_roots", "timeout_seconds", "memory_max_bytes",
                "worker_sha256", "backend_sha256", "catalog_sha256"}
CHANGED_PROFILE_KEYS = {"working_directory", "python_executable", "worker_sha256",
                        "backend_sha256"}
PINS = {"worker_sha256", "backend_sha256", "catalog_sha256"}
MAX_TEXT = 16 * 1024 * 1024
JOURNAL_CAPACITY = 128
# Remaining durable-event slots after each control event. The longest ordinary
# path is 16 events: claim/admit, activate, observe, rollback, observe, finish.
# These are logical slots under the cooperative lock, not reserved disk space.
CONTROL_RESERVATIONS = {
    "OWNERSHIP_INTENT": 15, "OWNERSHIP_CLAIMED": 14,
    "OWNERSHIP_CLAIM_RECOVERED": 14, "ADMITTED": 13,
    "ACTIVATE_CONFIG_INTENT": 12, "ACTIVATE_CONFIG_INSTALLED": 11,
    "ACTIVATE_RESTART_INTENT": 10, "ACTIVATE_RESTART_RETURNED": 9,
    "ACTIVATE_RESTART_UNKNOWN": 9, "ACTIVATE_RESTART_NOT_DISPATCHED": 9,
    "ROLLBACK_ADMITTED": 7, "ROLLBACK_CONFIG_INTENT": 6,
    "ROLLBACK_CONFIG_INSTALLED": 5, "ROLLBACK_RESTART_INTENT": 4,
    "ROLLBACK_RESTART_RETURNED": 3, "ROLLBACK_RESTART_UNKNOWN": 3,
    "ROLLBACK_RESTART_NOT_DISPATCHED": 3,
    "RESTORE_ADMITTED": 6, "RESTORE_CONFIG_INTENT": 5,
    "RESTORE_CONFIG_INSTALLED": 4, "RESTORE_CONFIG_RETURNED": 3,
    "OWNER_RELEASE_INTENT": 1, "ABORT_RELEASE_INTENT": 1,
    "OWNER_RELEASED": 0, "ABORTED_BASELINE_UNCHANGED": 0,
    "ABORTED_CONFIG_RESTORED_WITHOUT_RESTART": 0,
}
SCHEMA = "hepta.mac.hia.config-transition.v1"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       indent=2, allow_nan=False) + "\n").encode()


def decode(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            if key in out:
                raise ValueError("duplicate JSON member")
            out[key] = value
        return out
    def constant(_):
        raise ValueError("non-finite JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def load_helper(name):
    """Execute the pinned source bytes, never a cached .pyc replacement."""
    path = HERE / (name + ".py")
    raw = path.read_bytes()
    if digest(raw) != PINNED_HELPERS[name]:
        raise ValueError("4cd helper source pin changed: " + name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


CONTRACT = load_helper("mcp_tool_contract")
S = load_helper("stage_dc_successor")


def helper_identity():
    return {"mac_hia_activation.py": digest(pathlib.Path(__file__).read_bytes()),
            **{name + ".py": pin for name, pin in PINNED_HELPERS.items()}}


def info_key(info):
    return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
            "mtime_ns": str(info.st_mtime_ns), "ctime_ns": str(info.st_ctime_ns),
            "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}


def snapshot(path, cap=MAX_TEXT):
    """Reuse 4cd descriptor walking and inode admission; also bind the path."""
    parent, name = S.open_parent(path)
    try:
        S.require_trusted_publication_parent(parent)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            S.validate_inode(before, "transition input")
            if before.st_size > cap:
                raise ValueError("input exceeds snapshot bound")
            chunks, size = [], 0
            while True:
                part = os.read(fd, min(1024 * 1024, cap + 1 - size))
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                if size > cap:
                    raise ValueError("input grew past snapshot bound")
            after = os.fstat(fd)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if info_key(before) != info_key(after) or info_key(after) != info_key(linked):
                raise ValueError("input or its path changed during read")
            raw = b"".join(chunks)
            if len(raw) != before.st_size:
                raise ValueError("incomplete descriptor snapshot")
            return raw, {"path": str(S.absolute_path(path)), **info_key(after),
                         "sha256": digest(raw)}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def reference(value, cap=MAX_TEXT):
    if type(value) is not dict or set(value) != {"path", "sha256"}:
        raise ValueError("explicit path and SHA256 reference required")
    if type(value["sha256"]) is not str or not HASH.fullmatch(value["sha256"]):
        raise ValueError("invalid SHA256 reference")
    raw, meta = snapshot(value["path"], cap)
    if meta["sha256"] != value["sha256"]:
        raise ValueError("referenced bytes differ from pin")
    return raw, meta


def owned_inode(a, b):
    # rename can update ctime. This only recognizes our pre-recorded staged
    # object after an interrupted rename; the ordinary post-state guard is full.
    return all(a[k] == b[k] for k in
               ("device", "inode", "bytes", "mtime_ns", "uid", "mode", "sha256"))


def require_equal(actual, expected, label):
    if actual != expected:
        raise ValueError(label + " changed; no effect admitted")


def validate_profile_delta(before, after):
    if type(before) is not dict or type(after) is not dict:
        raise ValueError("whole runtime configurations required")
    if {k: v for k, v in before.items() if k != "hia_worker"} != {
            k: v for k, v in after.items() if k != "hia_worker"}:
        raise ValueError("host policy, controller state or non-HIA config changed")
    a, b = before.get("hia_worker"), after.get("hia_worker")
    if type(a) is not dict or type(b) is not dict or set(a) != PROFILE_KEYS or set(b) != PROFILE_KEYS:
        raise ValueError("exact ten-field HIA profiles required")
    changed = {k for k in PROFILE_KEYS if a[k] != b[k]}
    if not changed or not changed <= CHANGED_PROFILE_KEYS:
        raise ValueError("transition is not the admitted config-only HIA scope")
    for key in ("working_directory", "python_executable"):
        S.absolute_path(b[key])
    for key in PINS:
        if type(b[key]) is not str or not HASH.fullmatch(b[key]):
            raise ValueError("invalid candidate source pin")
    return sorted(changed)


def qualification(inputs, production_raw):
    """Bind original entrypoint evidence, both entire configs and full catalog.

    The trusted operator supplies the pins. Binding a receipt does not create
    source/build qualification or prove production-state compatibility.
    """
    roles = {"release_lock", "candidate", "probe_config", "preflight", "full_contract",
             "native_tools", "worker_manifest", "stdio_transcript"}
    if set(inputs) != roles:
        raise ValueError("complete original preflight evidence set required")
    held = {key: reference(value) for key, value in inputs.items()}
    values = {key: decode(raw) for key, (raw, _) in held.items()}
    lock, candidate, preflight = (values[k] for k in ("release_lock", "candidate", "preflight"))
    if lock.get("schema") != "hepta.hia.release-lock.v1":
        raise ValueError("original release lock required")
    if lock["sources"]["runtime"]["commit"] != BASE_RUNTIME:
        raise ValueError("runtime upgrade is outside this helper's scope")
    pair = {"hepta_commit": lock["sources"]["hepta"]["commit"],
            "runtime_commit": BASE_RUNTIME, "installation": lock["installation"]}
    if (candidate.get("schema") != "hepta.hia.unified-candidate.v1"
            or candidate.get("source_qualified") is not True or candidate.get("source_pair") != pair
            or candidate.get("source_pair_sha256") != digest(canonical(pair))):
        raise ValueError("candidate is not bound to the qualified source pair")
    if (candidate.get("configuration_sha256") != held["probe_config"][1]["sha256"]
            or candidate.get("worker_profile_sha256") != digest(canonical(values["probe_config"]["hia_worker"]))):
        raise ValueError("candidate does not bind the whole probe configuration")
    target, probe = decode(production_raw), values["probe_config"]
    for obj in (target, probe):
        if {key: obj["hia_worker"][key] for key in PINS} != pair["installation"]:
            raise ValueError("configuration pins differ from the original lock")
    # A probe is isolated. Only these explicit state locations may differ from
    # the prospective production config; no policy or worker input substitution.
    def without_test_state(obj):
        obj = decode(canonical(obj))
        obj.pop("state_dir", None)
        obj["hia_worker"].pop("state_root", None)
        return obj
    require_equal(without_test_state(target), without_test_state(probe), "probe configuration scope")
    if (target.get("state_dir") == probe.get("state_dir")
            or target["hia_worker"]["state_root"] == probe["hia_worker"]["state_root"]):
        raise ValueError("probe must use independent controller and worker state")
    if (preflight.get("status") != "entrypoint_observed"
            or preflight.get("entrypoint_observed") is not True
            or preflight.get("release_lock_sha256") != held["release_lock"][1]["sha256"]
            or preflight.get("candidate_sha256") != held["candidate"][1]["sha256"]
            or preflight.get("configuration_sha256") != held["probe_config"][1]["sha256"]
            or preflight.get("full_contract_file_sha256") != held["full_contract"][1]["sha256"]
            or preflight.get("evidence", {}).get("origin") != "actual_configured_stdio_mcp"):
        raise ValueError("successful original whole-config stdio probe required")
    captures = preflight["evidence"].get("captures", {})
    for role, name in (("native_tools", "native-tools.json"),
                       ("worker_manifest", "worker-manifest.json"),
                       ("stdio_transcript", "stdio-transcript.json")):
        require_equal(captures.get(name), held[role][1]["sha256"], "original capture")
    contract = CONTRACT.ToolContract(values["full_contract"])
    tools = values["native_tools"]
    if type(tools) is not dict or tools.get("nextCursor") is not None:
        raise ValueError("complete tools/list capture required")
    contract.verify(tools.get("tools"))
    required = {"host_list", "effective_config", "process_start", "process_status",
                "process_read", "process_wait", "process_cancel"}
    required.update("hia_" + name for name in ("describe", "read", "artifact", "context",
                    "inspect", "candidate", "verify", "emit", "evaluate", "adopt", "rollback"))
    if not required <= set(contract.by_name):
        raise ValueError("a HIA-only catalog is not a whole-server contract")
    require_equal(values["worker_manifest"], pair["installation"], "observed worker installation")
    require_equal(preflight["checks"]["whole_server_catalog_sha256"], contract.catalog_sha256,
                  "observed complete catalog")
    if (preflight["checks"].get("hia_catalog_sha256") != pair["installation"]["catalog_sha256"]
            or preflight["checks"].get("hia_tool_count") != 11
            or preflight["checks"].get("tool_count") != len(contract.tools)):
        raise ValueError("preflight catalog counts or HIA identity differ")
    return {"source_pair": pair, "release_lock_sha256": held["release_lock"][1]["sha256"],
            "whole_contract_sha256": held["full_contract"][1]["sha256"],
            "probe_configuration_sha256": held["probe_config"][1]["sha256"],
            "production_configuration_sha256": digest(production_raw),
            "runtime_binary_sha256": preflight["evidence"]["runtime_binary"]["sha256"],
            "inputs": {k: meta for k, (_, meta) in held.items()},
            "production_state_compatibility_proven_by_probe": False,
            "binary_build_provenance_attested": False}


def process_key(value):
    return {key: value[key] for key in ("pid", "uid", "start_identity", "loaded_binary_sha256",
                                       "loaded_binary_device", "loaded_binary_inode")}


def loaded_configuration_attestation(ref, configuration_sha256, service):
    """Bind actual receipt bytes and subjects, without inventing authenticity.

    The independent reviewer must authenticate this producer and its custody.
    A correct JSON shape or a source hash alone does not establish that trust.
    """
    raw, meta = reference(ref)
    value = decode(raw)
    if (value.get("schema") != "hepta.mac.hia.loaded-configuration-attestation.v1"
            or value.get("status") != "verified"
            or value.get("basis") not in ("guarded_startup_receipt", "runtime_loaded_configuration_attestation")
            or value.get("configuration_scope") != "entire_runtime_configuration"
            or value.get("configuration_sha256") != configuration_sha256
            or value.get("process") != process_key(service)
            or value.get("service_target") != service["target"]
            or type(value.get("producer_source_sha256")) is not str
            or not HASH.fullmatch(value["producer_source_sha256"])):
        raise ValueError("loaded-config receipt does not bind the whole configuration and actual process")
    return meta


def admission_window(value, now=None):
    start, end = value.get("issued_unix"), value.get("expires_unix")
    current = int(time.time()) if now is None else now
    if type(start) is not int or type(end) is not int or not start <= current < end <= start + 900:
        raise ValueError("maintenance admission is absent, future or expired")


def admission(value, plan, now):
    """Validate a separately reviewed admission; never manufacture one."""
    if value.get("schema") != "hepta.mac.hia.maintenance-admission.v1" or value.get("status") != "admitted":
        raise ValueError("separate, positive maintenance admission required")
    binding = {"operation_id": plan["operation_id"],
               "helper_identity": plan["helper_identity"],
               "baseline_sha256": digest(canonical(plan["baseline"])),
               "candidate_configuration_sha256": plan["candidate"]["sha256"],
               "release_lock_sha256": plan["qualification"]["release_lock_sha256"],
               "whole_contract_sha256": plan["qualification"]["whole_contract_sha256"]}
    require_equal(value.get("binding"), binding, "maintenance admission binding")
    admission_window(value, now)
    writers = value.get("writers", {})
    if (writers.get("model") != "cooperating_same_uid_deployment_lock"
            or writers.get("all_actual_writers_joined") is not True
            or writers.get("unknown_writer_present") is not False
            or writers.get("lease_path") != plan["lease_path"]):
        raise ValueError("writer cooperation is not established by holding flock")
    state = value.get("state", {})
    if (state.get("schema_compatibility") != "confirmed"
            or state.get("inflight_operations") not in ("compatible", "drained")
            or state.get("rollback_compatibility") != "confirmed"):
        raise ValueError("live state/in-flight/rollback compatibility is unknown")
    if value.get("recovery", {}).get("independent_of_target_service") is not True:
        raise ValueError("independent recovery owner is not established")
    evidence = value.get("reviewed_evidence_sha256")
    if type(evidence) is not list or not evidence or any(type(x) is not str or not HASH.fullmatch(x) for x in evidence):
        raise ValueError("reviewed admission evidence pins required")
    loaded = loaded_configuration_attestation(value.get("baseline_loaded_configuration"),
        plan["baseline"]["config"]["sha256"], plan["baseline"]["service"])
    if loaded["sha256"] not in evidence:
        raise ValueError("actual loaded-config receipt is not bound to reviewed admission evidence")
    admission_window(value)
    return value


class MacGUI:
    """Fixed OS observations and one restart primitive; no arbitrary command."""
    def __init__(self, label, plist, config, binary):
        if sys.platform != "darwin" or os.geteuid() == 0 or os.geteuid() != os.getuid():
            raise RuntimeError("native adapter requires the existing non-root macOS login")
        if not LABEL.fullmatch(label):
            raise ValueError("invalid exact GUI service label")
        self.label, self.plist, self.config, self.binary = label, plist, config, binary
        self.target = "gui/" + str(os.getuid()) + "/" + label

    @staticmethod
    def run(argv, timeout=10):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False,
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise ValueError("OS observation exceeds output bound")
        if result.returncode:
            raise RuntimeError("OS observation unavailable: " + argv[0])
        return result.stdout.decode("utf-8", "strict")

    def observe(self):
        raw, _ = snapshot(self.plist)
        plist = plistlib.loads(raw)
        argv = plist.get("ProgramArguments", [])
        if (plist.get("Label") != self.label or type(argv) is not list
                or argv.count("--runtime-config") != 1 or "mcp" not in argv):
            raise ValueError("LaunchAgent does not select the admitted controller")
        index = argv.index("--runtime-config")
        if index + 1 >= len(argv) or argv[index + 1] != self.config:
            raise ValueError("LaunchAgent configuration path differs")
        result = self.run(["/bin/launchctl", "print", self.target])
        fields = {}
        for line in result.splitlines():
            if line.startswith("\t") and not line.startswith("\t\t") and " = " in line:
                key, val = line.strip().split(" = ", 1)
                if key in ("path", "program", "pid", "state"):
                    if key in fields:
                        raise ValueError("ambiguous launchd observation")
                    fields[key] = val
        if (fields.get("path") != self.plist or fields.get("program") != argv[0]
                or fields.get("state") != "running" or not fields.get("pid", "").isdigit()):
            raise ValueError("GUI service identity is unavailable or different")
        pid = int(fields["pid"])
        before = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="]).strip()
        uid = self.run(["/bin/ps", "-p", str(pid), "-o", "uid="]).strip()
        if uid != str(os.getuid()):
            raise ValueError("actual process belongs to a different login")
        actual = shlex.split(self.run(["/bin/ps", "-p", str(pid), "-o", "args="]))
        if actual != argv:
            raise ValueError("actual process arguments differ from LaunchAgent")
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        path = ctypes.create_string_buffer(4096)
        if lib.proc_pidpath(pid, path, len(path)) <= 0:
            raise ValueError("actual executable path unavailable")
        loaded = path.value.decode("utf-8", "strict")
        if loaded != self.binary:
            raise ValueError("actual loaded executable differs from pinned release")
        _, binary = snapshot(loaded, 512 * 1024 * 1024)
        entries, current = [], {}
        text = self.run(["/usr/sbin/lsof", "-n", "-P", "-a", "-p", str(pid), "-d", "txt", "-F", "pDin"])
        for line in text.splitlines():
            if line[:1] == "D":
                if current:
                    entries.append(current)
                current = {"device": int(line[1:], 16)}
            elif line[:1] == "i":
                current["inode"] = int(line[1:])
            elif line[:1] == "n":
                current["path"] = line[1:]
        entries.append(current)
        if sum(e.get("path") == loaded and e.get("device") == binary["device"]
               and e.get("inode") == binary["inode"] for e in entries) != 1:
            raise ValueError("loaded executable inode is not the measured file")
        after = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="]).strip()
        if not before or before != after:
            raise ValueError("process start identity changed during observation")
        # ps_lstart is also the exact 4cd non-Linux job start-identity kind.
        # It is not a new kernel-level anti-PID-reuse attestation.
        return {"target": self.target, "pid": pid, "uid": int(uid),
                "start_identity": {"kind": "ps_lstart", "value": before},
                "loaded_binary_sha256": binary["sha256"],
                "loaded_binary_device": binary["device"], "loaded_binary_inode": binary["inode"],
                "loaded_configuration_sha256": None,
                "scope": "OS process/image observation; loaded config is not exposed by this adapter"}

    def restart(self):
        # This call is never made by inspection, planning, observation or tests.
        # Any exception after dispatch is uncertain, including loss of the h
        # connection that launched the independently-owned deployment process.
        self.run(["/bin/launchctl", "kickstart", "-k", self.target], timeout=30)


class Lease:
    """Serialize cooperating deployment writers, not hostile same-UID code."""
    def __init__(self, path):
        self.path = path
        self.fd = self.parent = None

    def __enter__(self):
        self.parent, self.name = S.open_parent(self.path)
        S.require_trusted_publication_parent(self.parent)
        try:
            self.fd = os.open(self.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=self.parent)
            item = os.fstat(self.fd)
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid()
                    or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1):
                raise ValueError("private deployment lock identity required")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = (item.st_dev, item.st_ino)
            self.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def check(self):
        item = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        if (item.st_dev, item.st_ino) != self.identity or item.st_nlink != 1:
            raise ValueError("deployment lock path was replaced")

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None


def private_directory(path, create=False):
    parent, name = S.open_parent(path)
    try:
        S.require_trusted_publication_parent(parent)
        if create:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
    finally:
        os.close(parent)
    item = os.fstat(fd)
    if item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
        os.close(fd)
        raise ValueError("operation directory must already be private and owned")
    return fd


def write_new(directory, name, raw):
    if "/" in name or name in ("", ".", ".."):
        raise ValueError("named private journal member required")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("incomplete private receipt write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


class Journal:
    def __init__(self, bundle):
        self.bundle = pathlib.Path(bundle)
        self.fd = private_directory(self.bundle)

    def close(self):
        os.close(self.fd)

    @staticmethod
    def reservation_after(kind, data, events):
        if kind in CONTROL_RESERVATIONS:
            return CONTROL_RESERVATIONS[kind]
        if kind != "OBSERVATION":
            raise ValueError("unclassified journal event cannot consume reserved capacity")
        status = data.get("status")
        if status == "ACTIVATE_CONFIG_AND_NEW_PROCESS_OBSERVED":
            return 8  # admitted rollback through its observation and final release
        if (status == "ACTIVATE_CONFIG_OBSERVED_BASELINE_PROCESS"
                and not any("RESTART_INTENT" in e["kind"] for e in events)):
            return 7  # explicit config-only restore, observe, abort
        if status in ("ROLLBACK_CONFIG_AND_NEW_PROCESS_OBSERVED",
                      "RESTORE_CONFIG_OBSERVED_PREDECESSOR_PROCESS"):
            return 2  # guarded release intent and receipt
        if status == "OWNER_RELEASE_EFFECT_OBSERVED_CURRENT_STATE_SEPARATE":
            return 0
        # A non-actionable observation must retain enough room for a later
        # actionable one. It must not consume the control path's reserved slots.
        previous = events[-1]["reserved_slots"] if events else 0
        intents = [e for e in events if e["kind"].endswith("_CONFIG_INTENT")]
        waiting = (9 if intents[-1]["kind"].startswith("ACTIVATE_") else 3) if intents else 0
        return max(previous, waiting)

    def events(self):
        names = os.listdir(self.fd)
        if len(names) > 160:
            raise ValueError("bounded journal exceeded")
        names = sorted(n for n in names if re.fullmatch(r"event-[0-9]{3}\.json", n))
        if len(names) > JOURNAL_CAPACITY:
            raise ValueError("bounded event count exceeded")
        events, previous = [], None
        for index, name in enumerate(names):
            if name != "event-%03d.json" % index:
                raise ValueError("journal has a missing event")
            raw, _ = snapshot(self.bundle / name)
            event = decode(raw)
            if event.get("sequence") != index or event.get("previous_sha256") != previous:
                raise ValueError("journal chain changed")
            reserved = self.reservation_after(event["kind"], event["data"], events)
            if (type(event.get("reserved_slots")) is not int or event["reserved_slots"] != reserved
                    or index + 1 + reserved > JOURNAL_CAPACITY):
                raise ValueError("journal reservation ledger changed or exceeds capacity")
            events.append(event)
            previous = digest(raw)
        return events

    def require_append(self, kind, data):
        events = self.events()
        reserved = self.reservation_after(kind, data, events)
        if len(events) + 1 + reserved > JOURNAL_CAPACITY:
            raise ValueError("operation event budget cannot reserve the required continuation; no new effect admitted")
        return events, reserved

    def append(self, kind, data):
        events, reserved = self.require_append(kind, data)
        previous = digest(snapshot(self.bundle / ("event-%03d.json" % (len(events) - 1)))[0]) if events else None
        event = {"sequence": len(events), "previous_sha256": previous, "kind": kind,
                 "at_unix": int(time.time()), "reserved_slots": reserved, "data": data}
        write_new(self.fd, "event-%03d.json" % len(events), encode(event))
        return event

    def record_observation(self, data):
        events = self.events()
        previous = next((e for e in reversed(events) if e["kind"] == "OBSERVATION"), None)
        if previous and previous["data"] == data:
            return {"journal_recorded": False, "journal_reason": "unchanged observation",
                    "previous_observation_sequence": previous["sequence"]}
        reserve = self.reservation_after("OBSERVATION", data, events)
        if len(events) + 1 + reserve > JOURNAL_CAPACITY:
            return {"journal_recorded": False, "journal_reason": "continuation slots preserved",
                    "reserved_slots": events[-1]["reserved_slots"] if events else 0,
                    "recovery": "retain the journal; this unrecorded read cannot authorize a new effect"}
        event = self.append("OBSERVATION", data)
        return {"journal_recorded": True, "observation_sequence": event["sequence"],
                "reserved_slots": event["reserved_slots"]}


def freeze(request, destination, backend):
    """Read/validate all input bindings before create-only private publication."""
    operation = request.get("operation_id")
    if type(operation) is not str or not OPERATION.fullmatch(operation):
        raise ValueError("invalid operation id")
    if request.get("schema") != SCHEMA or request.get("helper_identity") != helper_identity():
        raise ValueError("separately pinned deployment helper identity required")
    live, plist, binary, candidate = (reference(request[k], 512 * 1024 * 1024 if k == "binary" else MAX_TEXT)
                                     for k in ("live_config", "plist", "binary", "candidate_config"))
    if (live[1]["uid"] != os.getuid() or live[1]["mode"] != 0o600
            or plist[1]["uid"] != os.getuid() or plist[1]["mode"] != 0o600
            or not binary[1]["mode"] & 0o111):
        raise ValueError("private same-login config/LaunchAgent and executable binary required")
    changed = validate_profile_delta(decode(live[0]), decode(candidate[0]))
    baseline_lock_raw, baseline_lock = reference(request["live_release_lock"])
    baseline_release = decode(baseline_lock_raw)
    if (baseline_release.get("schema") != "hepta.hia.release-lock.v1"
            or baseline_release.get("sources", {}).get("runtime", {}).get("commit") != BASE_RUNTIME
            or baseline_release.get("installation") != {k: decode(live[0])["hia_worker"][k] for k in PINS}):
        raise ValueError("current config is not bound to the pinned baseline release lock")
    _, checker = reference(request["online_readback_checker"])
    require_equal(checker["sha256"], ONLINE_READBACK_CHECKER_SHA256, "independently fixed original checker")
    qualified = qualification(request["qualification"], candidate[0])
    require_equal(qualified["runtime_binary_sha256"], binary[1]["sha256"], "qualified runtime binary")
    service = backend.observe()
    if (not LABEL.fullmatch(request["service"])
            or service.get("target") != "gui/" + str(os.getuid()) + "/" + request["service"]):
        raise ValueError("observed exact GUI service differs from the requested service")
    require_equal(service["loaded_binary_sha256"], binary[1]["sha256"], "actual loaded binary")
    if (service["loaded_binary_device"], service["loaded_binary_inode"]) != (binary[1]["device"], binary[1]["inode"]):
        raise ValueError("actual process is not using the measured binary inode")
    plan = {"schema": SCHEMA, "operation_id": operation, "helper_identity": helper_identity(),
            "baseline": {"config": live[1], "plist": plist[1], "binary": binary[1], "service": service},
            "candidate": candidate[1], "qualification": qualified,
            "baseline_release_lock": baseline_lock,
            "baseline_installation": baseline_release["installation"],
            "online_readback_checker": checker,
            "qualification_references": request["qualification"], "changed_profile_fields": changed,
            "candidate_profile_sha256": digest(canonical(decode(candidate[0])["hia_worker"])),
            "lease_path": str(pathlib.Path(live[1]["path"]).with_name(".hepta-mac-hia-deployment.lock")),
            "owner_path": str(pathlib.Path(live[1]["path"]).with_name(".hepta-mac-hia-active.json")),
            "service": request["service"], "status": "PREPARED_NOT_ADMITTED_OR_DEPLOYED",
            "source_runtime_qualification_transferred_to_helper": False}
    # A process or input can change while qualification files are read.
    for role, pair in (("config", live), ("plist", plist), ("binary", binary)):
        require_equal(snapshot(pair[1]["path"], 512 * 1024 * 1024 if role == "binary" else MAX_TEXT)[1], pair[1], role)
    require_equal(backend.observe(), service, "baseline service")
    fd = private_directory(destination, create=True)
    try:
        write_new(fd, "plan.json", encode(plan))
        write_new(fd, "original-config.json", live[0])
        write_new(fd, "candidate-config.json", candidate[0])
    finally:
        os.close(fd)
    return plan


def load_plan(bundle, expected):
    raw, _ = reference({"path": str(pathlib.Path(bundle) / "plan.json"), "sha256": expected})
    plan = decode(raw)
    if plan.get("schema") != SCHEMA or plan.get("helper_identity") != helper_identity():
        raise ValueError("operation plan or separate helper identity changed")
    original, _ = snapshot(pathlib.Path(bundle) / "original-config.json")
    candidate, _ = snapshot(pathlib.Path(bundle) / "candidate-config.json")
    if digest(original) != plan["baseline"]["config"]["sha256"] or digest(candidate) != plan["candidate"]["sha256"]:
        raise ValueError("private original/candidate bytes changed")
    validate_profile_delta(decode(original), decode(candidate))
    require_equal(qualification(plan["qualification_references"], candidate), plan["qualification"], "candidate qualification")
    baseline = plan["baseline_release_lock"]
    require_equal(snapshot(baseline["path"])[1], baseline, "baseline release lock")
    checker = plan["online_readback_checker"]
    require_equal(checker["sha256"], ONLINE_READBACK_CHECKER_SHA256, "fixed original checker pin")
    require_equal(snapshot(checker["path"])[1], checker, "original checker source")
    return plan, original, candidate


def owner_bytes(plan, bundle, expected):
    return encode({"schema": "hepta.mac.hia.active-owner.v1", "operation_id": plan["operation_id"],
                   "plan_sha256": expected, "bundle": str(S.absolute_path(bundle)),
                   "helper_identity": plan["helper_identity"]})


def claim_owner(plan, bundle, expected, journal):
    raw = owner_bytes(plan, bundle, expected)
    journal.append("OWNERSHIP_INTENT", {"owner_sha256": digest(raw)})
    parent, name = S.open_parent(plan["owner_path"])
    try:
        S.require_trusted_publication_parent(parent)
        # A persistent active-operation fence, in addition to transient flock.
        # Unfinished operations are never displaced by a later invocation.
        write_new(parent, name, raw)
    finally:
        os.close(parent)
    meta = require_owner(plan, bundle, expected)
    journal.append("OWNERSHIP_CLAIMED", {"owner": meta})
    return meta


def require_owner(plan, bundle, expected, journal=None):
    raw, meta = snapshot(plan["owner_path"])
    if raw != owner_bytes(plan, bundle, expected):
        raise ValueError("another active operation owns this deployment lane")
    if journal is not None:
        claims = [e["data"]["owner"] for e in journal.events()
                  if e["kind"] in ("OWNERSHIP_CLAIMED", "OWNERSHIP_CLAIM_RECOVERED")]
        if len(claims) != 1 or claims[0] != meta:
            raise ValueError("active operation fence identity changed or is unresolved")
    return meta


def invariant_files(plan):
    for role in ("plist", "binary"):
        item = plan["baseline"][role]
        require_equal(snapshot(item["path"], 512 * 1024 * 1024 if role == "binary" else MAX_TEXT)[1], item, role)


def live_effect_guard(plan, config, service, backend, lease, owner):
    lease.check()
    require_equal(snapshot(plan["owner_path"])[1], owner, "active operation fence before effect")
    require_equal(snapshot(plan["baseline"]["config"]["path"])[1], config, "live config before effect")
    invariant_files(plan)
    require_equal(backend.observe(), service, "actual process before effect")
    lease.check()


def stage_config(plan, raw, suffix):
    path = pathlib.Path(plan["baseline"]["config"]["path"])
    parent, name = S.open_parent(path)
    try:
        S.require_trusted_publication_parent(parent)
        staged = "." + name + ".hia-" + plan["operation_id"] + "-" + suffix + "-" + secrets.token_hex(8)
        write_new(parent, staged, raw)
        meta = snapshot(path.with_name(staged))[1]
        return parent, name, staged, meta
    except BaseException:
        os.close(parent)
        raise


def replace_config(plan, raw, expected, lease, journal, prefix, owner, admitted, backend, service):
    # Check before staging, and append rechecks after staging. Both are under
    # the same operation lock. The durable intent carries its remaining reserve.
    journal.require_append(prefix + "_CONFIG_INTENT", {})
    parent, name, staged, staged_meta = stage_config(plan, raw, prefix.lower())
    try:
        journal.append(prefix + "_CONFIG_INTENT", {"before": expected, "staged": staged_meta})
        live_effect_guard(plan, expected, service, backend, lease, owner)
        # This is serialized compare/check/replace for participating writers,
        # not an OS atomic compare-and-swap against arbitrary same-UID writers.
        admission_window(admitted)
        os.replace(staged, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        actual = snapshot(plan["baseline"]["config"]["path"])[1]
        if not owned_inode(actual, staged_meta):
            raise ValueError("config effect does not match the recorded staged inode")
        journal.append(prefix + "_CONFIG_INSTALLED", {"config": actual})
        return actual
    finally:
        os.close(parent)


def restart_once(backend, journal, prefix, before, admitted, pre_dispatch):
    journal.require_append(prefix + "_RESTART_INTENT", {})
    admission_window(admitted)
    journal.append(prefix + "_RESTART_INTENT", {"before_process": process_key(before)})
    try:
        # The journal fsync may have blocked. An intent is not a dispatch.
        pre_dispatch()
        admission_window(admitted)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        journal.append(prefix + "_RESTART_NOT_DISPATCHED", {"reason": "final guard or admission window refused",
                       "error_type": type(error).__name__})
        raise
    try:
        backend.restart()
    except BaseException as error:
        journal.append(prefix + "_RESTART_UNKNOWN", {"error_type": type(error).__name__,
                       "recovery": "observe this operation; do not retry the service effect"})
        return {"status": prefix + "_RESTART_UNKNOWN", "formal_hia_verified": False}
    journal.append(prefix + "_RESTART_RETURNED", {"returned_success": True,
                   "loaded_configuration_verified": False})
    return {"status": prefix + "_RESTART_RETURNED_AWAITING_OBSERVATION", "formal_hia_verified": False}


def apply(bundle, expected, admission_ref, backend):
    plan, _, candidate = load_plan(bundle, expected)
    admit_raw, admit_meta = reference(admission_ref)
    admitted = admission(decode(admit_raw), plan, int(time.time()))
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        if journal.events():
            raise ValueError("operation already has a journal; observe, never reapply")
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], plan["baseline"]["config"], "baseline config")
        require_equal(backend.observe(), plan["baseline"]["service"], "actual baseline service")
        admission(admitted, plan, int(time.time()))
        owner = claim_owner(plan, bundle, expected, journal)
        journal.append("ADMITTED", {"admission": admit_meta, "cooperative_scope_only": True})
        installed = replace_config(plan, candidate, plan["baseline"]["config"], lease, journal,
                                   "ACTIVATE", owner, admitted, backend, plan["baseline"]["service"])
        lease.check()
        require_owner(plan, bundle, expected, journal)
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], installed, "installed config")
        require_equal(backend.observe(), plan["baseline"]["service"], "pre-restart service")
        return restart_once(backend, journal, "ACTIVATE", plan["baseline"]["service"], admitted,
            lambda: live_effect_guard(plan, installed, plan["baseline"]["service"], backend, lease, owner))


def observe(bundle, expected, backend):
    plan, _, _ = load_plan(bundle, expected)
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        events = journal.events()
        claims = [e for e in events if e["kind"] in ("OWNERSHIP_CLAIMED", "OWNERSHIP_CLAIM_RECOVERED")]
        ownership_intents = [e for e in events if e["kind"] == "OWNERSHIP_INTENT"]
        if not claims and len(ownership_intents) == 1 and not any("CONFIG_INTENT" in e["kind"] or "RESTART_INTENT" in e["kind"] for e in events):
            # The create-only owner write can outlive its acknowledgement.
            # Recover only these exact original bytes, before any live effect.
            meta = require_owner(plan, bundle, expected)
            require_equal(meta["sha256"], ownership_intents[0]["data"]["owner_sha256"], "original owner intent")
            journal.append("OWNERSHIP_CLAIM_RECOVERED", {"owner": meta, "live_effect_admitted": False})
            events = journal.events()
        owner_absent_after_release = False
        try:
            require_owner(plan, bundle, expected, journal)
        except FileNotFoundError:
            if not any(e["kind"] in ("OWNER_RELEASE_INTENT", "ABORT_RELEASE_INTENT") for e in events):
                raise
            owner_absent_after_release = True
        invariant_files(plan)
        current = snapshot(plan["baseline"]["config"]["path"])[1]
        actual = backend.observe()
        lease.check()
        intents = [e for e in events if e["kind"].endswith("_CONFIG_INTENT")]
        if not intents:
            status = "NO_CONFIG_EFFECT_INTENT"
        else:
            last = intents[-1]
            prefix = last["kind"].split("_", 1)[0]
            predecessor = process_key(plan["baseline"]["service"])
            for event in events:
                if event["sequence"] < last["sequence"] and event["kind"] == "OBSERVATION":
                    predecessor = process_key(event["data"]["service"])
                if event["kind"] == prefix + "_RESTART_INTENT":
                    predecessor = event["data"]["before_process"]
            if not owned_inode(current, last["data"]["staged"]):
                status = "CONFIG_EFFECT_UNKNOWN_OR_FOREIGN"
            elif process_key(actual) == predecessor:
                status = prefix + ("_CONFIG_OBSERVED_BASELINE_PROCESS" if prefix == "ACTIVATE"
                                   else "_CONFIG_OBSERVED_PREDECESSOR_PROCESS")
            else:
                status = prefix + "_CONFIG_AND_NEW_PROCESS_OBSERVED"
        if owner_absent_after_release:
            status = "OWNER_RELEASE_EFFECT_OBSERVED_CURRENT_STATE_SEPARATE"
        result = {"status": status, "config": current, "service": actual,
                  "loaded_configuration_verified": False, "formal_hia_verified": False,
                  "scope": "file effect and OS process observation only; preserve original UNKNOWN events"}
        recorded = journal.record_observation(result)
        return {**result, **recorded}


def abort_before_restart(bundle, expected, backend):
    """Release only an unchanged baseline or this operation's observed restore."""
    plan, _, _ = load_plan(bundle, expected)
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        owner = require_owner(plan, bundle, expected, journal)
        events = journal.events()
        if any("RESTART_INTENT" in e["kind"] for e in events):
            raise ValueError("service effect was admitted; abort cannot erase it")
        invariant_files(plan)
        current = snapshot(plan["baseline"]["config"]["path"])[1]
        restored = current != plan["baseline"]["config"]
        if restored:
            observations = [e["data"] for e in events if e["kind"] == "OBSERVATION"]
            intents = [e for e in events if e["kind"].endswith("_CONFIG_INTENT")]
            if (not observations or not intents
                    or observations[-1]["status"] != "RESTORE_CONFIG_OBSERVED_PREDECESSOR_PROCESS"
                    or observations[-1]["config"] != current
                    or intents[-1]["kind"] != "RESTORE_CONFIG_INTENT"
                    or not owned_inode(current, intents[-1]["data"]["staged"])
                    or current["sha256"] != plan["baseline"]["config"]["sha256"]):
                raise ValueError("exact original config or separately observed owned restore required")
        require_equal(backend.observe(), plan["baseline"]["service"], "exact original process")
        lease.check()
        require_equal(require_owner(plan, bundle, expected, journal), owner, "active owner before abort")
        journal.append("ABORT_RELEASE_INTENT", {"baseline_process_unchanged": True,
                       "original_config_inode_unchanged": not restored, "own_config_restore_observed": restored})
        parent, name = S.open_parent(plan["owner_path"])
        try:
            require_equal(snapshot(plan["owner_path"])[1], owner, "owner immediately before abort")
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        status = "ABORTED_CONFIG_RESTORED_WITHOUT_RESTART" if restored else "ABORTED_BASELINE_UNCHANGED"
        journal.append(status, {"service_effect_dispatched": False})
        return {"status": status, "formal_hia_verified": False}


def restore_before_restart(bundle, expected, admission_ref, backend):
    """Explicit config-only compensation; never dispatch a service effect.

    A separate observation must establish our post-inode and the exact original
    process. Any restart intent, even one without acknowledgement, refuses this
    path. Restoration itself has an intent and cannot be blindly repeated.
    """
    plan, original, _ = load_plan(bundle, expected)
    admit_raw, admit_meta = reference(admission_ref)
    admitted = admission(decode(admit_raw), plan, int(time.time()))
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        events = journal.events()
        owner = require_owner(plan, bundle, expected, journal)
        if any("RESTART_INTENT" in e["kind"] or e["kind"].startswith("RESTORE_") for e in events):
            raise ValueError("restart or prior restoration intent prevents config-only compensation")
        observations = [e["data"] for e in events if e["kind"] == "OBSERVATION"]
        if not observations or observations[-1]["status"] != "ACTIVATE_CONFIG_OBSERVED_BASELINE_PROCESS":
            raise ValueError("separate owned-config/baseline-process observation required for restoration")
        last = observations[-1]
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], last["config"], "own activation post-state")
        require_equal(last["service"], plan["baseline"]["service"], "observed exact original process")
        require_equal(backend.observe(), plan["baseline"]["service"], "actual exact original process")
        admission(admitted, plan, int(time.time()))
        journal.append("RESTORE_ADMITTED", {"admission": admit_meta, "restart_intent_absent": True})
        restored = replace_config(plan, original, last["config"], lease, journal,
                                  "RESTORE", owner, admitted, backend, plan["baseline"]["service"])
        lease.check()
        require_owner(plan, bundle, expected, journal)
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], restored, "own restored config")
        require_equal(backend.observe(), plan["baseline"]["service"], "original process after restoration")
        journal.append("RESTORE_CONFIG_RETURNED", {"service_effect_dispatched": False,
                       "recovery": "observe this operation, then abort-before-restart only under original-process guard"})
        return {"status": "RESTORE_CONFIG_RETURNED_AWAITING_OBSERVATION", "service_effect_dispatched": False}


def rollback(bundle, expected, admission_ref, backend):
    plan, original, _ = load_plan(bundle, expected)
    admit_raw, admit_meta = reference(admission_ref)
    admitted = admission(decode(admit_raw), plan, int(time.time()))
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        events = journal.events()
        owner = require_owner(plan, bundle, expected, journal)
        if any(e["kind"].startswith("ROLLBACK_") for e in events):
            raise ValueError("rollback already has an intent; observe, never replay")
        observations = [e["data"] for e in events if e["kind"] == "OBSERVATION"]
        if not observations or observations[-1]["status"] != "ACTIVATE_CONFIG_AND_NEW_PROCESS_OBSERVED":
            raise ValueError("explicit original-operation observation required before rollback")
        last = observations[-1]
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], last["config"], "own activation post-state")
        require_equal(backend.observe(), last["service"], "observed activation process")
        admission(admitted, plan, int(time.time()))
        journal.append("ROLLBACK_ADMITTED", {"admission": admit_meta})
        restored = replace_config(plan, original, last["config"], lease, journal,
                                  "ROLLBACK", owner, admitted, backend, last["service"])
        lease.check()
        require_owner(plan, bundle, expected, journal)
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], restored, "restored config")
        require_equal(backend.observe(), last["service"], "pre-rollback-restart process")
        return restart_once(backend, journal, "ROLLBACK", last["service"], admitted,
            lambda: live_effect_guard(plan, restored, last["service"], backend, lease, owner))


def finish(bundle, expected, completion_ref, backend):
    """Release only this operation's fence after separately verified readback.

    The original online checker is run by the operator workflow, not replaced
    by this helper. Its exact report and execution receipt are pinned inputs;
    their authenticity is part of that external reviewed workflow.
    """
    plan, original, candidate = load_plan(bundle, expected)
    completion_raw, completion_meta = reference(completion_ref)
    completion = decode(completion_raw)
    with Lease(plan["lease_path"]) as lease, contextlib.closing(Journal(bundle)) as journal:
        owner = require_owner(plan, bundle, expected, journal)
        events = journal.events()
        observations = [e["data"] for e in events if e["kind"] == "OBSERVATION"]
        if not observations:
            raise ValueError("observed original operation required before release")
        last = observations[-1]
        if last["status"] not in ("ACTIVATE_CONFIG_AND_NEW_PROCESS_OBSERVED", "ROLLBACK_CONFIG_AND_NEW_PROCESS_OBSERVED"):
            raise ValueError("operation has no settled config/process observation")
        rolled_back = last["status"].startswith("ROLLBACK")
        desired = original if rolled_back else candidate
        desired_pins = {k: decode(desired)["hia_worker"][k] for k in PINS}
        lock_hash = plan["baseline_release_lock"]["sha256"] if rolled_back else plan["qualification"]["release_lock_sha256"]
        if (completion.get("schema") != "hepta.mac.hia.completion.v1"
                or completion.get("plan_sha256") != expected
                or completion.get("process") != process_key(last["service"])
                or completion.get("configuration_sha256") != digest(desired)):
            raise ValueError("completion does not bind this operation and observed process")
        loaded = loaded_configuration_attestation(completion.get("loaded_configuration"),
            digest(desired), last["service"])
        report_raw, report_meta = reference(completion["readback_report"])
        report = decode(report_raw)
        execution_raw, execution_meta = reference(completion["checker_execution"])
        execution = decode(execution_raw)
        if (type(execution.get("exit_code")) is not int or execution.get("exit_code") != 0
                or execution.get("stdout_sha256") != report_meta["sha256"]
                or execution.get("checker_source_unchanged") is not True
                or execution.get("checker_sha256") != plan["online_readback_checker"]["sha256"]):
            raise ValueError("original checker execution binding is incomplete")
        if (report.get("schema") != "hepta.hia.online-release-readback.v1"
                or report.get("status") != "PASS_CURRENT_INSTALLATION_READBACK"
                or report.get("passed") is not True or report.get("release_lock_sha256") != lock_hash
                or report.get("expected_installation") != desired_pins
                or report.get("observed_installation") != desired_pins
                or type(report.get("matches")) is not dict or set(report["matches"]) != PINS
                or any(report["matches"][k] is not True for k in PINS)):
            raise ValueError("formal readback does not match the requested final installation")
        invariant_files(plan)
        require_equal(snapshot(plan["baseline"]["config"]["path"])[1], last["config"], "completion config")
        require_equal(backend.observe(), last["service"], "completion process")
        lease.check()
        require_equal(require_owner(plan, bundle, expected, journal), owner, "active operation fence")
        journal.append("OWNER_RELEASE_INTENT", {"completion": completion_meta,
                       "loaded_configuration": loaded, "readback_report": report_meta,
                       "checker_execution": execution_meta, "checker_source": plan["online_readback_checker"],
                       "rolled_back": rolled_back})
        parent, name = S.open_parent(plan["owner_path"])
        try:
            require_equal(snapshot(plan["owner_path"])[1], owner, "owner immediately before release")
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        journal.append("OWNER_RELEASED", {"external_readback_bound": True, "rolled_back": rolled_back})
        return {"status": "OWNER_RELEASED_AFTER_EXTERNAL_VERIFICATION", "rolled_back": rolled_back,
                "scope": "cooperative transaction; no new global qualification"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("helper-identity")
    p = sub.add_parser("prepare")
    p.add_argument("--request", required=True)
    p.add_argument("--request-sha256", required=True)
    p.add_argument("--destination", required=True)
    for command in ("apply", "observe", "rollback", "restore-before-restart", "finish", "abort-before-restart"):
        p = sub.add_parser(command)
        p.add_argument("--bundle", required=True)
        p.add_argument("--plan-sha256", required=True)
        if command in ("apply", "rollback", "restore-before-restart"):
            p.add_argument("--admission", required=True)
            p.add_argument("--admission-sha256", required=True)
        elif command == "finish":
            p.add_argument("--completion", required=True)
            p.add_argument("--completion-sha256", required=True)
    a = ap.parse_args(argv)
    if a.command == "helper-identity":
        result = helper_identity()
    elif a.command == "prepare":
        raw, _ = reference({"path": a.request, "sha256": a.request_sha256})
        request = decode(raw)
        backend = MacGUI(request["service"], request["plist"]["path"],
                         request["live_config"]["path"], request["binary"]["path"])
        result = freeze(request, a.destination, backend)
    else:
        plan, _, _ = load_plan(a.bundle, a.plan_sha256)
        backend = MacGUI(plan["service"], plan["baseline"]["plist"]["path"],
                         plan["baseline"]["config"]["path"], plan["baseline"]["binary"]["path"])
        if a.command == "observe":
            result = observe(a.bundle, a.plan_sha256, backend)
        elif a.command == "abort-before-restart":
            result = abort_before_restart(a.bundle, a.plan_sha256, backend)
        elif a.command == "finish":
            result = finish(a.bundle, a.plan_sha256,
                            {"path": a.completion, "sha256": a.completion_sha256}, backend)
        else:
            effect = {"apply": apply, "rollback": rollback, "restore-before-restart": restore_before_restart}[a.command]
            result = effect(a.bundle, a.plan_sha256,
                {"path": a.admission, "sha256": a.admission_sha256}, backend)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "REFUSED_OR_EFFECT_UNRESOLVED", "error_type": type(error).__name__,
                          "message": str(error)[:1000], "automatic_retry": False,
                          "recovery": "read the original operation journal; no automatic effect replay"}), file=sys.stderr)
        raise SystemExit(1)
