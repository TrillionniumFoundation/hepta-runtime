#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Finite native-MCP concurrency qualification using an isolated controller.

Example (run on the controller machine with its existing SSH configuration):
  python3 tests/runtime_unbounded_concurrency_acceptance.py \
    --binary /absolute/path/hepta-runtime --runtime-config /absolute/live.json \
    --host rog --output /absolute/new-proof-directory

The input config and binary are read-only. A new private local state/config and
private stdio endpoint are created. Only the selected, already executable
operator host is copied; its SSH/authentication settings are unchanged. Remote
setup creates a new tempfile namespace. Exactly 32 original payloads write
start/end markers and sleep briefly. A finite shared gate (30 s by default)
keeps them observable during 32 concurrent process_wait calls. The gate is
released after that observation, or expires by itself if the harness dies.

32 exact retries of one completed key must reuse its original job. No new-key
retry, process_cancel, service restart, sshd change, or live-state controller is
used. All isolated state and original receipts are retained on both outcomes.
The script is stdlib-only and supports Linux/macOS controller process sampling.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

COUNT = 32
PREFIX = "hepta-unbounded-proof-"
FENCE_ENV = (
    "HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "HEPTA_EFFECT_OWNER_SELF",
    "HEPTA_EFFECT_OWNER_FENCE_DIR",
)

REMOTE = r'''
import hashlib,json,os,pathlib,re,socket,stat,sys,tempfile
q=json.load(sys.stdin)
os.umask(0o077)
def write_new(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(value,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
def read_file(path,maximum=1048576):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
        assert stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=maximum
        raw=source.read(maximum+1)
        assert len(raw)==info.st_size and len(raw)<=maximum
    return raw
if q['op']=='create':
    root=pathlib.Path(os.path.realpath(tempfile.mkdtemp(prefix='hepta-unbounded-proof-')))
    os.chmod(root,0o700)
    for name in ('jobs','markers'):(root/name).mkdir(mode=0o700)
    info=root.stat()
    binding={'root':str(root),'uid':os.geteuid(),'device':info.st_dev,'inode':info.st_ino,'nonce':q['nonce']}
    write_new(root/'proof-owner.json',binding)
    print(json.dumps({**binding,'python':os.path.realpath(sys.executable),'hostname':socket.gethostname()}))
else:
    binding=q['binding'];root=pathlib.Path(binding['root'])
    info=root.lstat()
    assert str(root.resolve())==str(root) and root.name.startswith('hepta-unbounded-proof-')
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700
    assert (info.st_uid,info.st_dev,info.st_ino)==(binding['uid'],binding['device'],binding['inode'])
    expected={key:binding[key] for key in ('root','uid','device','inode','nonce')}
    assert json.loads(read_file(root/'proof-owner.json'))==expected
    if q['op']=='release':
        if not (root/'release.json').exists():write_new(root/'release.json',{'nonce':binding['nonce']})
        assert json.loads(read_file(root/'release.json'))['nonce']==binding['nonce']
        print(json.dumps({'released':True,'nonce':binding['nonce']}))
    elif q['op']=='snapshot':
        result={'jobs':{},'markers':{},'attempts':[],'job_directories':[]}
        for job_id in q['job_ids']:
            assert re.fullmatch(r'[A-Za-z0-9_.-]+',job_id)
            directory=root/'jobs'/job_id
            row={}
            for name in ('request.json','owner-intent.json','started.json','child.json','launch.json','exit.json','exit.witness.json'):
                try:
                    raw=read_file(directory/name)
                    row[name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes_hex':raw.hex(),'value':json.loads(raw)}
                except (OSError,ValueError,AssertionError) as exc:row[name]={'error':type(exc).__name__+': '+str(exc)}
            result['jobs'][job_id]=row
        for entry in sorted((root/'markers').iterdir()):
            if re.fullmatch(r'[0-9]+-(start|end)\.json',entry.name):
                result['markers'][entry.name]=json.loads(read_file(entry))
        attempts=root/'attempts.jsonl'
        if attempts.exists():result['attempts']=[json.loads(line) for line in read_file(attempts).splitlines()]
        result['job_directories']=sorted(entry.name for entry in (root/'jobs').iterdir() if entry.is_dir())
        print(json.dumps(result,sort_keys=True))
    else:raise ValueError('unknown fixture operation')
'''

PAYLOAD = r'''
import fcntl,json,os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);nonce=sys.argv[2];slot=int(sys.argv[3]);key=sys.argv[4]
hold=float(sys.argv[5]);short_sleep=float(sys.argv[6]);os.umask(0o077)
binding=json.loads((root/'proof-owner.json').read_text())
assert binding['nonce']==nonce and binding['uid']==os.geteuid()
value={'nonce':nonce,'slot':slot,'key':key,'job_id':os.environ['HEPTA_RUNTIME_JOB_ID'],
       'pid':os.getpid(),'uid':os.geteuid(),'supervisor_pid':os.getppid()}
fd=os.open(root/'attempts.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'a') as out:
    fcntl.flock(out.fileno(),fcntl.LOCK_EX)
    out.write(json.dumps(value,sort_keys=True)+'\n');out.flush();os.fsync(out.fileno())
def marker(event,extra):
    item={**value,'event':event,**extra}
    fd=os.open(root/'markers'/('%d-%s.json'%(slot,event)),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(item,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
    print(json.dumps(item,sort_keys=True),flush=True)
marker('start',{})
deadline=time.monotonic()+hold
while not (root/'release.json').exists() and time.monotonic()<deadline:time.sleep(.05)
released=(root/'release.json').exists()
if released:assert json.loads((root/'release.json').read_text())['nonce']==nonce
time.sleep(short_sleep)
marker('end',{'gate_released':released})
'''


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def remote(target, interpreter, query):
    result = subprocess.run(
        ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", target,
         shlex.quote(interpreter) + " -I -S -c " + shlex.quote(REMOTE)],
        input=json.dumps(query), capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"fixture SSH failed ({result.returncode}): {result.stderr[-4000:]}")
    return json.loads(result.stdout)


class Mcp:
    """One native connection; every response is matched to its original RPC ID."""

    def __init__(self, binary, config, workspace, output):
        self.pending = {}
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.journal_lock = threading.Lock()
        self.counter = 0
        self.peak_pending = 0
        self.journal = (output / "mcp-original-envelopes.jsonl").open("x", encoding="utf-8")
        self.errors = (output / "controller.stderr.log").open("xb")
        self.process = subprocess.Popen(
            [str(binary), "mcp", "--path", str(workspace), "--runtime-config", str(config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors,
            text=True, bufsize=1, cwd=workspace, env=dict(os.environ),
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def log(self, direction, message):
        with self.journal_lock:
            self.journal.write(json.dumps({"monotonic": time.monotonic(), "direction": direction,
                                          "message": message}, separators=(",", ":")) + "\n")
            self.journal.flush()

    def _read(self):
        failure = "native MCP transport closed"
        try:
            while True:
                raw = self.process.stdout.readline(16 * 1024 * 1024 + 1)
                if not raw:
                    break
                if not raw.endswith("\n"):
                    raise RuntimeError("incomplete or oversized native response")
                message = json.loads(raw)
                self.log("receive", message)
                if "method" in message:
                    if "id" in message:
                        self.send({"jsonrpc": "2.0", "id": message["id"],
                                   "result": {}} if message["method"] == "ping" else
                                  {"jsonrpc": "2.0", "id": message["id"],
                                   "error": {"code": -32601, "message": "unsupported client method"}})
                    continue
                with self.lock:
                    ticket = self.pending.pop(message.get("id"), None)
                if ticket is None:
                    raise RuntimeError("response has no outstanding original RPC identity")
                ticket["received"] = time.monotonic()
                ticket["future"].set_result(message)
        except Exception as exc:
            failure = type(exc).__name__ + ": " + str(exc)
        finally:
            with self.lock:
                pending, self.pending = self.pending, {}
            for ticket in pending.values():
                ticket["future"].set_exception(RuntimeError(failure))

    def send(self, message):
        with self.write_lock:
            self.log("send", message)
            self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self.process.stdin.flush()

    def submit(self, calls):
        tickets = []
        messages = []
        with self.lock:
            if self.pending:
                raise RuntimeError("prior original RPCs remain unresolved; no further load submitted")
            for method, params in calls:
                self.counter += 1
                ticket = {"rpc_id": self.counter, "sent": time.monotonic(),
                          "future": concurrent.futures.Future()}
                message = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}
                self.pending[self.counter] = ticket
                tickets.append(ticket)
                messages.append(message)
            self.peak_pending = max(self.peak_pending, len(self.pending))
        # Never hold the receipt registry while writing a pipe: stdout may
        # become readable before a whole burst has entered the stdin pipe.
        with self.write_lock:
            for message in messages:
                self.log("send", message)
                self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
        return tickets

    @staticmethod
    def collect(tickets, seconds=40):
        results = []
        for ticket in tickets:
            item = {"rpc_id": ticket["rpc_id"]}
            try:
                envelope = ticket["future"].result(timeout=max(0, ticket["sent"] + seconds - time.monotonic()))
                item["envelope"] = envelope
                if "error" in envelope:
                    raise RuntimeError("native MCP error: " + json.dumps(envelope["error"]))
                result = envelope["result"]
                if result.get("isError"):
                    raise RuntimeError("native tool error: " + json.dumps(result))
                texts = [block["text"] for block in result.get("content", []) if block.get("type") == "text"]
                item["value"] = json.loads(texts[0]) if len(texts) == 1 else result
            except Exception as exc:
                item["error"] = type(exc).__name__ + ": " + str(exc)
            item["elapsed_ms"] = round((ticket.get("received", time.monotonic()) - ticket["sent"]) * 1000, 3)
            results.append(item)
        return results

    def request(self, method, params):
        result = self.collect(self.submit([(method, params)]))[0]
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["value"]

    def batch(self, tool, arguments):
        return self.collect(self.submit([("tools/call", {"name": tool, "arguments": value}) for value in arguments]))

    def close(self):
        outcome = {"pid": self.process.pid, "method": "stdin_eof"}
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError as exc:
                outcome["stdin_close_error"] = str(exc)
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            outcome["method"] = "owned_controller_sigterm"
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                outcome["method"] = "owned_controller_sigkill"
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        outcome["exit_code"] = self.process.returncode
        self.errors.close()
        if not self.reader.is_alive():
            self.journal.close()
        return outcome


class SshSampler:
    """Observe only ssh children of this exact isolated controller PID."""

    def __init__(self, pid):
        self.pid = pid
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.phase = "startup"
        self.peaks = {}
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def begin(self, phase):
        with self.lock:
            self.phase = phase

    def run(self):
        while not self.stop.is_set():
            try:
                rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,comm="], text=True, timeout=3)
                children = []
                for row in rows.splitlines():
                    parts = row.split(None, 2)
                    if len(parts) == 3 and int(parts[1]) == self.pid and Path(parts[2]).name == "ssh":
                        children.append({"pid": int(parts[0]), "ppid": int(parts[1]), "comm": parts[2]})
                with self.lock:
                    previous = self.peaks.get(self.phase, {"count": -1})
                    if len(children) > previous["count"]:
                        self.peaks[self.phase] = {"count": len(children), "children": children,
                                                  "monotonic": time.monotonic()}
            except Exception as exc:
                with self.lock:
                    if len(self.errors) < 5:
                        self.errors.append(type(exc).__name__ + ": " + str(exc))
            self.stop.wait(.02)

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=5)
        with self.lock:
            return {"phases": dict(self.peaks), "errors": list(self.errors)}


def original_records(state, keys):
    found = collections.defaultdict(list)
    for path in (state / "jobs").glob("*.json"):
        value = json.loads(path.read_text())
        if value.get("idempotency_key") in keys:
            found[value["idempotency_key"]].append(value)
    return dict(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--runtime-config", required=True, type=Path)
    parser.add_argument("--host", default="rog")
    parser.add_argument("--output", required=True, type=Path, help="new private evidence directory")
    parser.add_argument("--remote-python", default="python3", help="existing remote interpreter for fixture setup")
    parser.add_argument("--hold-seconds", type=float, default=30, help="finite marker gate, 10..60 seconds")
    parser.add_argument("--sleep-seconds", type=float, default=.25, help="payload sleep after gate, 0.05..2 seconds")
    args = parser.parse_args()
    if not 10 <= args.hold_seconds <= 60 or not .05 <= args.sleep_seconds <= 2:
        parser.error("finite hold/sleep ranges are required")
    if any(os.environ.get(name) for name in FENCE_ENV):
        parser.error("an effect-owner fence is inherited; this harness does not clear or bypass it. Use a separately authorized isolated controller environment.")
    binary, source = args.binary.resolve(strict=True), args.runtime_config.resolve(strict=True)
    config = json.loads(source.read_text())
    names = [name for name in config["hosts"] if name.lower() == args.host.lower()]
    if len(names) != 1:
        parser.error("select one existing configured host by --host")
    host_name = names[0]
    original_host = dict(config["hosts"][host_name])
    if original_host.get("execution_mode") != "operator" or not original_host.get("allow_execute"):
        parser.error("the selected host must already authorize operator execution")
    target = original_host["ssh_target"]
    if not isinstance(target, str) or not target or target.startswith("-") or any(c in target for c in "\0\r\n"):
        parser.error("invalid configured SSH target")
    output = args.output.resolve()
    default_state = (os.environ.get("HEPTA_RUNTIME_STATE_DIR") or
                     str(Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "hepta-runtime"))
    live_state = Path(config.get("state_dir", default_state)).expanduser().resolve()
    if output == live_state or live_state in output.parents:
        parser.error("evidence and isolated state must be outside live controller state")
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    local_root = Path(tempfile.mkdtemp(prefix=PREFIX, dir=output)).resolve()
    state, workspace = local_root / "state", local_root / "workspace"
    state.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    nonce = uuid.uuid4().hex
    report = {"schema": "hepta-native-unbounded-concurrency-proof/v1", "complete": False,
              "passed": False, "count": COUNT, "host": host_name, "ssh_target": target,
              "binary": str(binary), "binary_sha256": digest(binary),
              "source_config": str(source), "source_config_sha256": digest(source),
              "isolated_state": str(state), "transport": "private_native_stdio",
              "live_state_opened_by_candidate": False, "new_key_retries": 0,
              "remote_cancellation_calls": 0, "checks": [], "failures": [], "phases": {}}
    binding = None
    client = None
    sampler = None
    released = False
    rows = []

    def check(name, condition, detail=None):
        report["checks"].append({"name": name, "passed": bool(condition), "detail": detail})
        if not condition:
            report["failures"].append(name)
        save_json(output / "report.json", report)

    try:
        binding = remote(target, args.remote_python, {"op": "create", "nonce": nonce})
        if not Path(binding["root"]).is_absolute() or not Path(binding["root"]).name.startswith(PREFIX):
            raise RuntimeError("remote fixture did not return a private absolute namespace")
        report["remote_fixture"] = binding
        # RuntimeConfig owns the state root; start_job appends jobs/<original-id>.
        host = {**original_host, "remote_state_dir": binding["root"]}
        isolated = {"state_dir": str(state), "controller_workspace_roots": [str(workspace)],
                    "hosts": {host_name: host}}
        isolated_path = local_root / "runtime.json"
        save_json(isolated_path, isolated)
        report["isolated_config"] = str(isolated_path)
        client = Mcp(binary, isolated_path, workspace, output)
        report["controller_pid"] = client.process.pid
        sampler = SshSampler(client.process.pid)
        report["initialize"] = client.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
            "clientInfo": {"name": "hepta-unbounded-concurrency-proof", "version": "1"}})
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        tools = {tool["name"] for tool in client.request("tools/list", {})["tools"]}
        if not {"process_start", "process_status", "process_wait", "process_read"} <= tools:
            raise RuntimeError("candidate does not expose the required native process tools")
        keys = ["unbounded-proof-" + nonce + "-" + str(slot) for slot in range(COUNT)]
        params = [{"host": host_name, "executable": binding["python"],
                   "args": ["-I", "-S", "-c", PAYLOAD, binding["root"], nonce, str(slot), keys[slot],
                            str(args.hold_seconds), str(args.sleep_seconds)],
                   "timeout_seconds": int(args.hold_seconds) + 10, "idempotency_key": keys[slot]}
                  for slot in range(COUNT)]
        sampler.begin("distinct_starts")
        starts = client.batch("process_start", params)
        report["phases"]["distinct_starts"] = starts
        found = original_records(state, set(keys))
        check("32 distinct keys retain exactly one original controller record each",
              all(len(found.get(key, [])) == 1 for key in keys),
              {key: len(found.get(key, [])) for key in keys})
        rows = [found[key][0] for key in keys if len(found.get(key, [])) == 1]
        check("all 32 original starts acknowledge their own launched job",
              len(rows) == COUNT and all(
                  "error" not in result and result["value"].get("reused") is False
                  and result["value"].get("job", {}).get("host") == host_name
                  and result["value"].get("job", {}).get("idempotency_key") == keys[index]
                  and result["value"].get("launch", {}).get("ok") is True
                  for index, result in enumerate(starts)))
        if len(rows) != COUNT:
            raise RuntimeError("missing original identities; no replacement keys or launches created")
        references = [{"host": host_name, "job_id": row["id"]} for row in rows]
        sampler.begin("held_observations")
        observed = client.batch("process_wait", [{**ref, "timeout_seconds": 3} for ref in references])
        report["phases"]["held_observations"] = observed
        check("32 same-host observations return the matching original identities",
              all("error" not in result and result["value"].get("job_id") == row["id"]
                  for result, row in zip(observed, rows)))
        report["release"] = remote(target, binding["python"], {"op": "release", "binding": binding})
        released = True
        sampler.begin("terminal_observations")
        remaining = dict(zip((row["id"] for row in rows), references))
        final = {}
        rounds = []
        for _ in range(3):
            if not remaining:
                break
            identities = list(remaining)
            values = client.batch("process_wait", [{**remaining[key], "timeout_seconds": 5} for key in identities])
            rounds.append(values)
            for identity, result in zip(identities, values):
                if "error" not in result:
                    value = result["value"]
                    final[identity] = value
                    if value.get("state") in ("succeeded", "failed", "cancelled", "timed_out"):
                        del remaining[identity]
        report["phases"]["terminal_observations"] = rounds
        original_success = (len(final) == COUNT and all(
            value.get("state") == "succeeded" and value.get("exit_code") == 0
            and value.get("output_complete") is True and value.get("output_durable") is True
            and value.get("terminal_publication_confirmed") is True for value in final.values()))
        check("all original jobs expose durable complete terminal success", original_success)
        if original_success:
            sampler.begin("same_key_reuse")
            reused = client.batch("process_start", [params[0]] * COUNT)
            report["phases"]["same_key_reuse"] = reused
            check("32 identical-key calls reuse the same original job without relaunch",
                  all("error" not in result and result["value"].get("reused") is True
                      and result["value"].get("retried_launch") is False
                      and result["value"].get("job", {}).get("id") == rows[0]["id"] for result in reused))
        else:
            # An original launch may be unconfirmed. Never let this validation
            # step turn a failed cohort into a new attempt under an old key.
            report["phases"]["same_key_reuse"] = {"skipped": "original terminal success is incomplete"}
            check("32 identical-key calls reuse the same original job without relaunch", False,
                  "not submitted because an original outcome remains incomplete")
        sampler.begin("original_outputs")
        outputs = client.batch("process_read", [{**ref, "stdout_offset": 0, "stderr_offset": 0, "limit": 16384}
                                                for ref in references])
        report["phases"]["original_outputs"] = outputs
        snapshot = remote(target, binding["python"], {"op": "snapshot", "binding": binding,
                                                      "job_ids": [row["id"] for row in rows]})
        save_json(output / "remote-original-receipts.json", snapshot)
        attempts = snapshot["attempts"]
        check("exactly 32 physical payload attempts and one per original key",
              len(attempts) == COUNT and collections.Counter(value["key"] for value in attempts) == collections.Counter(keys))
        check("exactly the original 32 remote job directories remain",
              snapshot["job_directories"] == sorted(row["id"] for row in rows))
        for slot, (row, output_value) in enumerate(zip(rows, outputs)):
            evidence = snapshot["jobs"][row["id"]]
            request = evidence.get("request.json", {}).get("value", {})
            owner = evidence.get("started.json", {}).get("value", {})
            intent = evidence.get("owner-intent.json", {}).get("value", {})
            child = evidence.get("child.json", {}).get("value", {})
            end = evidence.get("exit.json", {}).get("value", {})
            witness = evidence.get("exit.witness.json", {}).get("value", {})
            begin_marker = snapshot["markers"].get(f"{slot}-start.json", {})
            end_marker = snapshot["markers"].get(f"{slot}-end.json", {})
            original_nonce = request.get("launch_nonce")
            original_nonce_valid = (isinstance(original_nonce, str) and len(original_nonce) == 32
                                    and all(char in "0123456789abcdef" for char in original_nonce))
            original_bytes_valid = all(
                "error" not in receipt
                and hashlib.sha256(bytes.fromhex(receipt["bytes_hex"])).hexdigest() == receipt["sha256"]
                and json.loads(bytes.fromhex(receipt["bytes_hex"])) == receipt["value"]
                for receipt in evidence.values())
            owners_match = (original_nonce_valid and original_bytes_valid
                and owner == intent and owner.get("job_id") == request.get("job_id") == row["id"]
                and owner.get("supervisor_uid") == binding["uid"]
                and isinstance(owner.get("supervisor_pid"), int) and owner["supervisor_pid"] > 1
                and owner.get("supervisor_identity", {}).get("value")
                and owner.get("supervisor_identity", {}).get("kind") ==
                    ("ps_lstart" if original_host.get("platform") == "macos" else "proc_start_ticks")
                and request.get("request_fingerprint") == row.get("request_digest")
                and owner.get("launch_nonce") == request.get("launch_nonce") == end.get("launch_nonce") == witness.get("launch_nonce")
                and witness.get("exit_sha256") == evidence.get("exit.json", {}).get("sha256")
                and end.get("job_id") == witness.get("job_id") == row["id"]
                and begin_marker.get("job_id") == end_marker.get("job_id") == row["id"]
                and begin_marker.get("supervisor_pid") == owner.get("supervisor_pid")
                and begin_marker.get("uid") == end_marker.get("uid") == binding["uid"]
                and begin_marker.get("key") == end_marker.get("key") == keys[slot]
                and begin_marker.get("slot") == end_marker.get("slot") == slot
                and begin_marker.get("pid") == end_marker.get("pid") == child.get("pid")
                and child.get("identity", {}).get("value")
                and child.get("identity", {}).get("kind") == owner.get("supervisor_identity", {}).get("kind")
                and begin_marker.get("supervisor_pid") == end_marker.get("supervisor_pid")
                and begin_marker.get("nonce") == end_marker.get("nonce") == nonce
                and end_marker.get("gate_released") is True)
            if evidence.get("launch.json", {}).get("value", {}).get("backend") == "systemd":
                owners_match = owners_match and isinstance(owner.get("invocation_id"), str) and len(owner["invocation_id"]) == 32
            check(f"job {slot}: original owner, request, payload and terminal witness agree", owners_match)
            captured = output_value.get("value", {})
            try:
                stdout = captured["stdout"]
                raw = bytes.fromhex(stdout["bytes_hex"])
                parsed = [json.loads(line) for line in raw.splitlines()]
                intact = ("error" not in output_value and parsed == [begin_marker, end_marker]
                          and stdout.get("eof") is True and len(raw) == stdout.get("size")
                          and captured["stderr"].get("size") == 0)
            except (KeyError, ValueError, TypeError):
                intact = False
            check(f"job {slot}: native output contains exactly its original two markers", intact)
        after = original_records(state, set(keys))
        check("idempotent reuse leaves all original controller identities unchanged",
              all(len(after.get(key, [])) == 1 and after[key][0]["id"] == found[key][0]["id"] for key in keys))
        report["complete"] = True
    except Exception as exc:
        report["failures"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        if binding is not None and not released:
            try:
                report["release"] = remote(target, binding["python"], {"op": "release", "binding": binding})
            except Exception as exc:
                report["release_error"] = type(exc).__name__ + ": " + str(exc)
        if sampler is not None:
            report["ssh_child_observations"] = sampler.finish()
            peak = report["ssh_child_observations"]["phases"].get("held_observations", {}).get("count", 0)
            check("observed more than 16 simultaneous same-target SSH children of this controller",
                  peak > 16, {"peak": peak, "old_host_cap": 2, "old_global_cap": 8, "old_admission_cap": 16})
        if client is not None:
            report["client_peak_outstanding_rpc"] = client.peak_pending
            report["controller_shutdown"] = client.close()
            check("isolated controller exits cleanly after its private transport closes",
                  report["controller_shutdown"]["method"] == "stdin_eof"
                  and report["controller_shutdown"]["exit_code"] == 0)
        try:
            unchanged = digest(binary) == report["binary_sha256"] and digest(source) == report["source_config_sha256"]
        except OSError:
            unchanged = False
        check("input binary and live runtime config remained unchanged", unchanged)
        report["retained_local_root"] = str(local_root)
        report["retained_remote_root"] = binding["root"] if binding else None
        report["passed"] = report["complete"] and not report["failures"]
        save_json(output / "report.json", report)
    print(json.dumps({"passed": report["passed"], "report": str(output / "report.json"),
                      "failures": report["failures"], "retained_remote_root": report["retained_remote_root"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
