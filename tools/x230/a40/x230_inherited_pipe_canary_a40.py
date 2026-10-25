#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native MCP inherited-pipe recovery and staggered EOF compatibility on x230/mac.

Each start and cancellation is submitted once. Fixed descendants self-exit
within eight seconds; the harness never signals a discovered remote PID. The
optional x230 cancellation case first observes the bound unreaped leader, then
uses process_cancel on its original job ID. A missed window is a retained
failure, never an automatic rerun. The default six cases include natural EOF,
staggered stdout/stderr EOF and inherited-pipe timeout on each host. No service
or existing job is modified.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import x230_observation_benchmark as bench
import x230_six_running_recovery_canary as recovery

HOSTS = ("x230", "mac")
DEV_ROOT = recovery.DEV_ROOT
MARKER = b"EXECUTED\n"
REMOTE_LIMIT = 512 * 1024

# The helper can create only this invocation's private fixture, or inspect
# original files under that pinned fixture. Process observations never signal.
REMOTE = r'''import base64,hashlib,json,os,pathlib,re,socket,stat,subprocess,sys,time
p=json.loads(base64.b64decode(sys.argv[1],validate=True))
assert p['mode'] in ('prepare','inspect','probe_unreaped')
assert p['host'] in ('x230','mac') and re.fullmatch('[0-9a-f]{24}',p['nonce'])
assert sys.platform==('darwin' if p['host']=='mac' else 'linux')
assert p['name']=='inherited-pipe-'+p['nonce']+'-'+p['host']
def canonical(v):
    return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_mode]
def stamp(s):
    return identity(s)+[s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def directory(parent,name):
    assert name not in ('','.','..') and '/' not in name
    return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
def absolute(path):
    assert path.startswith('/') and path!='/'
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    for component in path.split('/')[1:]:
        child=directory(fd,component);os.close(fd);fd=child
    s=os.fstat(fd)
    assert s.st_uid==os.geteuid() and not stat.S_IMODE(s.st_mode)&0o022
    return fd
def read(fd,name,limit=65536,optional=True):
    assert name not in ('','.','..') and '/' not in name
    try:
        source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
    except FileNotFoundError:
        if optional:return None
        raise
    try:
        before=os.fstat(source)
        assert stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid()
        assert before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
        assert before.st_size<=limit
        with os.fdopen(os.dup(source),'rb') as stream:raw=stream.read(limit+1)
        assert len(raw)==before.st_size and stamp(before)==stamp(os.fstat(source))==stamp(os.stat(name,dir_fd=fd,follow_symlinks=False))
        return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    finally:os.close(source)
def unpack(item):
    return None if item is None else json.loads(base64.b64decode(item['base64'],validate=True))
def linux_process(pid):
    assert type(pid) is int and pid>1
    path=pathlib.Path('/proc')/str(pid)
    raw=(path/'stat').read_text()
    f=raw.rsplit(') ',1)[1].split()
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return {'pid':pid,'uid':path.stat().st_uid,'state':f[0],'ppid':int(f[1]),
            'identity':{'kind':'proc_start_ticks','value':boot+':'+f[19]}}
def observe_process(record):
    if not record:return None
    pid=record['pid']
    if sys.platform=='linux':
        try:value=linux_process(pid)
        except (FileNotFoundError,ProcessLookupError):return {'present':False}
    else:
        answer=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=,ppid=,stat=,lstart='],capture_output=True,text=True,timeout=3)
        if answer.returncode==1 and not answer.stdout.strip():return {'present':False}
        assert answer.returncode==0
        f=answer.stdout.split(None,3)
        assert len(f)==4
        value={'pid':pid,'uid':int(f[0]),'ppid':int(f[1]),'state':f[2],
               'identity':{'kind':'ps_lstart','value':f[3].strip()}}
    value.update(present=True,original_identity_matches=value['identity']==record['identity'])
    return value
base=absolute(p['base'])
if p['mode']=='prepare':os.mkdir(p['name'],0o700,dir_fd=base)
fixture=directory(base,p['name'])
fi=os.fstat(fixture)
assert fi.st_uid==os.geteuid() and stat.S_IMODE(fi.st_mode)==0o700
origin={'schema':'hepta-inherited-pipe-fixture/v1','nonce':p['nonce'],'host':p['host'],
        'base':p['base'],'name':p['name'],'source_record_sha256':p['source_record_sha256'],
        'fixture_identity':identity(fi)}
if p['mode']=='prepare':
    fd=os.open('.canary-origin.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fixture)
    with os.fdopen(fd,'wb') as stream:stream.write(canonical(origin));stream.flush();os.fsync(stream.fileno())
    os.fsync(fixture);os.fsync(base)
else:
    assert p['fixture_identity']==identity(fi)
    assert base64.b64decode(read(fixture,'.canary-origin.json',8192,False)['base64'],validate=True)==canonical(origin)
result={'mode':p['mode'],'host':p['host'],'nonce':p['nonce'],'hostname':socket.gethostname(),
        'platform':sys.platform,'fixture_identity':identity(fi),'files':{}}
if p['mode']!='prepare':
    assert re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',p['job_id'])
    jobs=directory(fixture,'jobs');job=directory(jobs,p['job_id'])
    ji=os.fstat(job)
    assert ji.st_uid==os.geteuid() and stat.S_IMODE(ji.st_mode)==0o700
    if p['mode']=='probe_unreaped':
        assert sys.platform=='linux'
        until=time.monotonic()+1.5
        result['ready']=False
        while True:
            files={n:read(job,n) for n in ('request.json','started.json','child.json','exit.json')}
            request,started,child=(unpack(files[n]) for n in ('request.json','started.json','child.json'))
            if request is not None:
                assert request['job_id']==p['job_id'] and request['request_fingerprint']==p['request_digest']
            if files['exit.json'] is not None:
                result['reason']='terminal receipt already exists';break
            if request is not None and started is not None and child is not None:
                assert started['job_id']==request['job_id'] and started['launch_nonce']==request['launch_nonce']
                try:
                    owner=linux_process(started['supervisor_pid']);leader=linux_process(child['pid'])
                    owner_after=linux_process(started['supervisor_pid']);leader_after=linux_process(child['pid'])
                    verified=(owner==owner_after and leader==leader_after and leader['state']=='Z'
                        and leader['ppid']==owner['pid'] and owner['state']!='Z'
                        and owner['uid']==leader['uid']==os.geteuid()
                        and owner['identity']==started['supervisor_identity'] and leader['identity']==child['identity'])
                except (FileNotFoundError,ProcessLookupError):verified=False
                if verified:
                    result.update(ready=True,owner=owner,leader=leader,observed_unix=time.time(),
                                  scope='read-only original owner/leader identity and unreaped exit observation')
                    break
            if time.monotonic()>=until:
                result['reason']='original unreaped-leader observation window missed';break
            time.sleep(.02)
        result['files']=files
    else:
        for name in ('request.json','started.json','child.json','launch.json','owner-intent.json',
                     'exit.json','exit.witness.json','stdout.log','stderr.log',
                     'canary-input.json','execution-marker','leader-before-exit.json','descendant.json',
                     'stdout-finished','descendant-finished'):
            result['files'][name]=read(job,name,131072)
        request=unpack(result['files']['request.json'])
        assert request is not None and request['job_id']==p['job_id'] and request['request_fingerprint']==p['request_digest']
        result['descendant_observation']=observe_process(unpack(result['files']['descendant.json']))
    assert identity(os.stat(p['job_id'],dir_fd=jobs,follow_symlinks=False))==identity(ji)
    os.close(job);os.close(jobs)
assert identity(os.stat(p['name'],dir_fd=base,follow_symlinks=False))==identity(fi)
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''

CHILD = r'''import json,os,pathlib,re,select,signal,stat,subprocess,sys,time
p=json.loads(sys.argv[1])
assert p['host'] in ('x230','mac') and p['case'] in ('natural','staggered','timeout','cancel')
fixture=os.open(p['fixture'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
info=os.fstat(fixture)
assert [info.st_dev,info.st_ino,info.st_uid,info.st_mode]==p['fixture_identity']
job_id=os.environ['HEPTA_RUNTIME_JOB_ID']
assert re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',job_id)
jobs=os.open('jobs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fixture)
job=os.open(job_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=jobs)
assert os.fstat(job).st_uid==os.geteuid() and stat.S_IMODE(os.fstat(job).st_mode)==0o700
def write(name,data,append=False):
    flags=os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_APPEND if append else os.O_EXCL)
    fd=os.open(name,flags,0o600,dir_fd=job)
    with os.fdopen(fd,'ab' if append else 'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.fsync(job)
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity():
    if sys.platform=='linux':
        ticks=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]
        boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return {'kind':'proc_start_ticks','value':boot+':'+ticks}
    value=subprocess.check_output(['/bin/ps','-p',str(os.getpid()),'-o','lstart='],text=True,timeout=3).strip()
    return {'kind':'ps_lstart','value':value}
write('canary-input.json',canonical({**p,'job_id':job_id}))
ready_r,ready_w=os.pipe();release_r,release_w=os.pipe()
descendant=os.fork()
if descendant==0:
    os.close(ready_r);os.close(release_w)
    hard_deadline=time.monotonic()+8
    signal.signal(signal.SIGTERM,signal.SIG_DFL if p['case']=='cancel' else signal.SIG_IGN)
    write('descendant.json',canonical({'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp(),
          'identity':identity(),'started_unix':time.time(),
          'job_id':job_id,'case':p['case'],'self_exit_budget_seconds':8}))
    os.write(1,('DESCENDANT BEGIN '+p['case']+'\n').encode())
    os.write(ready_w,b'R');os.close(ready_w)
    readable,_,_=select.select([release_r],[],[],max(0,hard_deadline-time.monotonic()))
    released=bool(readable) and os.read(release_r,1)==b'G'
    os.close(release_r)
    if released:
        if p['case']=='staggered':
            until=min(hard_deadline,time.monotonic()+1.0)
            while time.monotonic()<until:time.sleep(min(.05,max(0,until-time.monotonic())))
            write('stdout-finished',b'STAGGERED STDOUT EOF\n')
            os.write(1,b'DESCENDANT STDOUT EOF staggered\n')
            os.close(1)
            until=min(hard_deadline,time.monotonic()+1.5)
            while time.monotonic()<until:time.sleep(min(.05,max(0,until-time.monotonic())))
            write('descendant-finished',b'STAGGERED STDERR EOF\n')
            os.write(2,b'DESCENDANT STDERR EOF staggered\n')
            os.close(2)
        else:
            until=min(hard_deadline,time.monotonic()+.3) if p['case']=='natural' else hard_deadline
            while time.monotonic()<until:time.sleep(min(.05,max(0,until-time.monotonic())))
            write('descendant-finished',b'NATURAL EOF\n')
            os.write(1,('DESCENDANT EOF '+p['case']+'\n').encode())
    os._exit(0)
os.close(ready_w);os.close(release_r)
readable,_,_=select.select([ready_r],[],[],4)
if not readable or os.read(ready_r,1)!=b'R':
    os.close(release_w);raise SystemExit('synthetic descendant did not become ready')
os.close(ready_r)
write('execution-marker',b'EXECUTED\n',append=True)
os.write(1,('LEADER EXIT '+p['case']+'\n').encode())
os.write(2,('LEADER STDERR '+p['case']+'\n').encode())
write('leader-before-exit.json',canonical({'pid':os.getpid(),'before_exit_unix':time.time()}))
os.write(release_w,b'G');os.close(release_w)
os._exit(0)
'''


class Ledger:
    def __init__(self, out, report):
        self.out, self.report, self.serial = out, report, 0

    def begin(self, kind, request):
        self.serial += 1
        raw = bench.canonical(request)
        path = self.out / f"{self.serial:04d}-{kind}-request.json"
        bench.create_file(path, raw)
        event = {"sequence": self.serial, "kind": kind, "request_path": str(path),
                 "request_sha256": bench.digest(raw), "started_unix": time.time(),
                 "automatic_retry": False, "completed": False}
        self.report["calls"].append(event)
        self.save()
        return event

    def bytes(self, event, label, raw):
        path = self.out / f"{event['sequence']:04d}-{event['kind']}-{label}.json"
        bench.create_file(path, raw)
        event[label] = {"path": str(path), "bytes": len(raw), "sha256": bench.digest(raw)}

    def save(self):
        bench.save_report(self.out / "report.json", self.report)


class RecordedController(bench.Controller):
    def __init__(self, *args, ledger, **kwargs):
        self.ledger = ledger
        try:
            super().__init__(*args, **kwargs)
        except BaseException:
            if all(hasattr(self, key) for key in ("child", "reader", "resources", "stderr")):
                try:
                    ledger.report["constructor_failure_shutdown"] = self.close()
                except BaseException as cleanup:
                    ledger.report["constructor_cleanup_error"] = type(cleanup).__name__ + ": " + str(cleanup)
            elif hasattr(self, "child"):
                try:
                    self.child.terminate()
                    try:
                        self.child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.child.kill()
                        self.child.wait(timeout=10)
                    ledger.report["constructor_owned_child_wait"] = self.child.returncode
                except BaseException as cleanup:
                    ledger.report["constructor_cleanup_error"] = type(cleanup).__name__ + ": " + str(cleanup)
            raise

    def read_loop(self):
        # Preserve every inbound byte before routing, including notifications,
        # late replies and unmatched IDs which the ordinary helper only counts.
        path = self.directory / "stdio-responses.raw"
        digest, byte_count, stream = hashlib.sha256(), 0, None
        self.wire_capture = {"path": str(path), "complete": False}
        try:
            stream = path.open("xb")
            while True:
                line = self.child.stdout.readline(bench.MAX_MESSAGE + 1)
                if not line:
                    self.wire_capture["complete"] = True
                    break
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
                digest.update(line)
                byte_count += len(line)
                bench.need(len(line) <= bench.MAX_MESSAGE and line.endswith(b"\n"), "MCP response size/framing violation")
                reply = json.loads(line)
                if "id" not in reply:
                    continue
                with self.lock:
                    waiter = self.pending.pop(reply["id"], None)
                    if waiter is None:
                        self.unmatched += 1
                if waiter is not None:
                    waiter.put(reply)
        except Exception as error:
            self.reader_error = type(error).__name__ + ": " + str(error)
        finally:
            if stream is not None:
                stream.close()
            self.wire_capture.update(bytes=byte_count, sha256=digest.hexdigest(), reader_error=self.reader_error)
            with self.lock:
                pending = list(self.pending.values())
                self.pending.clear()
            for waiter in pending:
                waiter.put({"error": {"code": -32099, "message": self.reader_error or "native stdio closed"}})

    def close(self):
        receipt = super().close()
        receipt["stdio_reader_alive"] = self.reader.is_alive()
        receipt["wire_capture"] = getattr(self, "wire_capture", None)
        return receipt

    def rpc(self, method, params, timeout=50):
        # All caller RPCs are sequential; the inherited reader never emits one.
        request = {"jsonrpc": "2.0", "id": self.serial + 1, "method": method, "params": params}
        event = self.ledger.begin("native", request)
        try:
            response = super().rpc(method, params, timeout)
            self.ledger.bytes(event, "response", bench.canonical(response))
            bench.need(response.get("id", request["id"]) == request["id"], "original RPC identity differs")
            event["completed"] = True
            return response
        except BaseException as error:
            event["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            event["finished_unix"] = time.time()
            self.ledger.save()

    def notify(self, method, params):
        event = self.ledger.begin("notification", {"jsonrpc": "2.0", "method": method, "params": params})
        try:
            super().notify(method, params)
            event.update(completed=True, response_expected=False)
        except BaseException as error:
            event["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            event["finished_unix"] = time.time()
            self.ledger.save()


def native(controller, host, tool, arguments):
    bench.need(host in HOSTS and arguments["host"] == host and tool in {
        "process_start", "process_status", "process_read", "process_cancel"}, "unexpected native route")
    response = controller.rpc("tools/call", {"name": tool, "arguments": arguments})
    bench.need("error" not in response and response.get("result", {}).get("isError") is not True,
               "native canary call refused: " + host + "/" + tool)
    texts = [item["text"] for item in response["result"].get("content", []) if item.get("type") == "text"]
    bench.need(len(texts) == 1, "native JSON envelope differs")
    value = json.loads(texts[0])
    bench.need(value.get("audit_recorded") is True and "audit_warning" not in value,
               "native response lacks durable audit acknowledgement")
    if tool != "process_start":
        bench.need(value.get("job_id") == arguments["job_id"], "original job identity differs")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "profile-template", "frozen-jobs", "socket-parent", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--cancel-during-drain", action="store_true",
                        help="One x230 original-unreaped-leader observation and one native cancellation; no retry")
    args = parser.parse_args()
    out = args.out.absolute()
    bench.need(sys.platform == "linux" and out.parent == DEV_ROOT and out.resolve() == out
               and not os.path.lexists(out), "use a fresh direct x230 development directory")
    bench.need(re.fullmatch("[0-9a-f]{64}", args.expected_binary_sha256), "expected qualified binary SHA256 required")
    out.mkdir(mode=0o700)
    report = {"schema": "hepta-native-inherited-pipe-canary/v2", "passed": False,
              "started_unix": time.time(), "controller_hostname": socket.gethostname(),
              "scope": "fresh native jobs; original leader/group/output/terminal-witness recovery",
              "not_covered": ["host reboot", "power loss", "escaped process-group descendants",
                              "macOS cancellation-window qualification", "general exactly-once external effects"],
              "automatic_retries": 0, "harness_remote_signals": 0, "service_mutations": 0,
              "remote_deletions": 0, "descendant_self_exit_seconds": 8,
              "cancel_during_drain_requested": args.cancel_during_drain,
              "calls": [], "hosts": {}, "cases": [], "nonce": secrets.token_hex(12)}
    ledger = Ledger(out, report)
    active = None
    jobs, source_records, binary_before, agent_before = [], {}, None, None
    wrapper = agent = None

    def remote(host, mode, case=None):
        item = report["hosts"][host]
        payload = {key: item[key] for key in ("base", "name", "source_record_sha256")}
        payload.update(host=host, nonce=report["nonce"], mode=mode)
        if mode != "prepare":
            payload.update(fixture_identity=item["prepare"]["fixture_identity"],
                           job_id=case["job_id"], request_digest=case["record"]["request_digest"])
        event = ledger.begin("ssh-" + mode, payload)
        command = "/usr/bin/python3 -I -S - " + shlex.quote(base64.b64encode(bench.canonical(payload)).decode())
        try:
            result = subprocess.run([str(wrapper), "-T", item["ssh_target"], command], input=REMOTE.encode(),
                                    capture_output=True, timeout=20, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "SSH_AUTH_SOCK": agent})
            ledger.bytes(event, "stdout", result.stdout)
            ledger.bytes(event, "stderr", result.stderr)
            event["returncode"] = result.returncode
            bench.need(result.returncode == 0 and len(result.stdout) <= REMOTE_LIMIT
                       and len(result.stderr) <= 65536, "fixed independent helper failed")
            value = json.loads(result.stdout)
            bench.need(value.get("host") == host and value.get("mode") == mode
                       and value.get("nonce") == report["nonce"], "independent helper identity differs")
            if mode != "prepare":
                bench.need(value["fixture_identity"] == item["prepare"]["fixture_identity"], "fixture identity changed")
            event["completed"] = True
            return value
        except subprocess.TimeoutExpired as error:
            for label, raw in (("partial-stdout", error.stdout), ("partial-stderr", error.stderr)):
                if raw is not None:
                    ledger.bytes(event, label, raw)
            event["error"] = "TimeoutExpired: fixed independent SSH helper exceeded 20 seconds"
            raise
        except BaseException as error:
            event["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            event["finished_unix"] = time.time()
            ledger.save()

    def validate(case, status, output, proof):
        host, kind = case["host"], case["case"]
        files = proof["files"]
        decoded = lambda name, required=True: recovery.decoded(files, name, required)
        request = json.loads(decoded("request.json"))
        receipt = json.loads(decoded("exit.json"))
        witness = json.loads(decoded("exit.witness.json"))
        bench.need(request["job_id"] == case["job_id"] and request["request_fingerprint"] == case["record"]["request_digest"]
                   and request["executable"] == case["request"]["executable"]
                   and request["args"] == case["request"]["args"]
                   and request["cwd"] == case["request"]["cwd"] and request["env"] == {}
                   and request["timeout_seconds"] == 12, "original remote request differs")
        for value in (receipt, witness):
            bench.need(value.get("job_id") == case["job_id"] and value.get("launch_nonce") == request["launch_nonce"]
                       and value.get("terminal_publication_protocol") == 1, "terminal publication binding differs")
        bench.need(witness["exit_sha256"] == bench.digest(decoded("exit.json")), "terminal original-byte witness differs")
        bench.need(all(status.get(key) == value for key, value in receipt.items())
                   and status.get("terminal_publication_confirmed") is True, "native status/original terminal disagree")
        bench.need(decoded("execution-marker") == MARKER, "original workload did not execute exactly once")
        actual_input = json.loads(decoded("canary-input.json"))
        bench.need(actual_input == {**case["child_config"], "job_id": case["job_id"]}, "original canary input differs")
        original_child = json.loads(decoded("child.json"))
        descendant = json.loads(decoded("descendant.json"))
        leader_before_exit = json.loads(decoded("leader-before-exit.json"))
        bench.need(descendant["ppid"] == descendant["pgid"] == original_child["pid"]
                   and leader_before_exit["pid"] == original_child["pid"]
                   and descendant["job_id"] == case["job_id"] and descendant["case"] == kind
                   and descendant["self_exit_budget_seconds"] == 8,
                   "original parent/group/self-exit binding differs")
        expected_stdout = ("DESCENDANT BEGIN " + kind + "\nLEADER EXIT " + kind + "\n").encode()
        expected_stderr = ("LEADER STDERR " + kind + "\n").encode()
        if kind in ("natural", "staggered"):
            if kind == "staggered":
                expected_stdout += b"DESCENDANT STDOUT EOF staggered\n"
                expected_stderr += b"DESCENDANT STDERR EOF staggered\n"
                bench.need(decoded("stdout-finished") == b"STAGGERED STDOUT EOF\n",
                           "staggered original stdout EOF marker differs")
                expected_finished = b"STAGGERED STDERR EOF\n"
            else:
                expected_stdout += ("DESCENDANT EOF " + kind + "\n").encode()
                expected_finished = b"NATURAL EOF\n"
                bench.need(decoded("stdout-finished", False) is None, "unexpected staggered marker in natural control")
            bench.need(status.get("state") == "succeeded" and status.get("exit_code") == 0
                       and status.get("output_complete") is True and status.get("output_durable") is True
                       and not status.get("cancelled") and not status.get("timed_out")
                       and status.get("log_errors") == {"stdout": None, "stderr": None}
                       and status.get("effect_outcome") != "unknown"
                       and "child_group_signal" not in status
                       and decoded("descendant-finished") == expected_finished, "natural EOF control failed: " + kind)
        else:
            expected_signal = 15 if kind == "cancel" else 9
            expected_error = "output drain cancelled after leader exit" if kind == "cancel" else "output drain deadline exceeded after leader exit"
            bench.need(status.get("state") == "effect_unknown" and status.get("effect_outcome") == "unknown"
                       and status.get("exit_code") == 125 and status.get("child_exit_code") == 0
                       and status.get("child_reaped") is True and status.get("child_spawned") is True
                       and status.get("child_group_signal") == "submitted"
                       and status.get("child_group_signal_number") == expected_signal
                       and status.get("supervisor_error") == expected_error
                       and status.get("supervisor_cleanup_errors") == []
                       and status.get("automatic_retry") is False and status.get("status_authoritative") is False
                       and status.get("output_complete") is False and status.get("output_durable") is False
                       and status.get("cancelled") is (kind == "cancel") and not status.get("timed_out")
                       and decoded("descendant-finished", False) is None, "forced inherited-pipe recovery differs")
            bench.need(status["child_pid"] == original_child["pid"], "original leader receipt differs")
            bench.need(status.get("log_errors") == {"stdout": expected_error, "stderr": expected_error},
                       "forced capture failure differs from the original drain event")
        bench.need(status.get("automatic_retry") is False
                   and status.get("log_synced") == {"stdout": True, "stderr": True}
                   and status.get("log_truncated") == {"stdout": False, "stderr": False}
                   and status.get("log_bytes") == {
                       "stdout": {"seen": len(expected_stdout), "stored": len(expected_stdout)},
                       "stderr": {"seen": len(expected_stderr), "stored": len(expected_stderr)}},
                   "original output publication counters/barriers differ")
        for stream, expected in (("stdout", expected_stdout), ("stderr", expected_stderr)):
            part = output[stream]
            raw = bytes.fromhex(part["bytes_hex"])
            bench.need(raw == expected == decoded(stream + ".log") and part["offset"] == 0
                       and part["next_offset"] == part["size"] == len(expected) and part["eof"] is True,
                       "complete native/original output differs: " + stream)
        observation = proof["descendant_observation"]
        bench.need(observation is not None and (not observation["present"]
                   or (observation.get("original_identity_matches") is True
                       and observation["uid"] == proof["fixture_identity"][2]
                       and observation["state"].startswith("Z"))),
                   "original descendant death is unconfirmed after terminal receipt")
        case["validation"] = {"original_identity_and_witness": True, "execution_count": 1,
                              "native_and_original_output_match": True, "descendant_observation": observation,
                              "terminal_seconds_after_leader_before_exit_marker": receipt["at_unix_ms"] / 1000 - leader_before_exit["before_exit_unix"],
                              "timing_scope": "same-host wall clocks around a pre-exit marker; not an exact exit-to-signal timestamp"}

    try:
        jobs = bench.load_jobs(args.frozen_jobs)
        selected = {job["host"]: job for job in jobs if job["host"] in HOSTS}
        bench.need(set(selected) == set(HOSTS), "two configured host records required")
        candidate = args.candidate.absolute()
        binary_before = bench.digest(bench.read_file(candidate, 128 * 1024 * 1024))
        bench.need(binary_before == args.expected_binary_sha256, "qualified binary digest differs")
        report["candidate_sha256"] = binary_before
        report["source_hashes"] = {name: bench.digest(bench.read_file(path, 1024 * 1024)) for name, path in (
            ("driver", Path(__file__)), ("benchmark_helper", Path(bench.__file__)),
            ("recovery_helper", Path(recovery.__file__)))}
        report["remote_helper_sha256"], report["child_source_sha256"] = bench.digest(REMOTE.encode()), bench.digest(CHILD.encode())
        agent = os.environ["SSH_AUTH_SOCK"]
        agent_before = bench.agent_identity(agent)
        profile, report["profile"] = bench.fresh_profile(args.profile_template, out / "profile", args.socket_parent, agent)
        wrapper, report["ssh_wrapper_sha256"] = recovery.private_wrapper(json.loads(bench.read_file(profile)), agent, out / "bin")
        for host in HOSTS:
            original = selected[host]["record"]
            bench.need(original["executable"] == "/usr/bin/python3" and original["args"][:2] == ["-I", "-S"]
                       and re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]*", original["ssh_target"]), "original host provenance differs")
            old = PurePosixPath(original["remote_job_dir"])
            bench.need(old.is_absolute() and old.name == original["id"] and old.parent.name == "jobs"
                       and ".." not in old.parts, "original state provenance differs")
            name = "inherited-pipe-" + report["nonce"] + "-" + host
            report["hosts"][host] = {"base": str(old.parent.parent), "name": name,
                "fixture": str(old.parent.parent / name), "ssh_target": original["ssh_target"],
                "source_record_sha256": selected[host]["record_sha256"]}
            ledger.save()
            report["hosts"][host]["prepare"] = remote(host, "prepare")
        bench.need(len({v["prepare"]["hostname"] for v in report["hosts"].values()}) == 2,
                   "the two configured aliases did not identify two different machines")
        state = out / "state"
        state.mkdir(mode=0o700)
        (state / "jobs").mkdir(mode=0o700)
        config = out / "runtime.json"
        bench.create_file(config, bench.canonical({"state_dir": str(state), "controller_workspace_roots": [],
            "hosts": {host: {"execution_mode": "operator", "ssh_target": item["ssh_target"],
                "platform": "macos" if host == "mac" else "linux", "remote_state_dir": item["fixture"],
                "allow_execute": True, "allow_pty": False, "allow_write": False, "allow_job_network": True,
                "allow_detached_fallback": host == "mac", "privileged_actions": {}}
                for host, item in report["hosts"].items()}}))
        controller_dir = out / "controller"
        controller_dir.mkdir(mode=0o700)
        active = RecordedController(candidate, config, profile, controller_dir, 2,
                                    path_prefix=wrapper.parent, ledger=ledger)
        report["startup"] = active.startup
        planned = [(host, kind) for host in HOSTS for kind in ("natural", "staggered", "timeout")]
        if args.cancel_during_drain:
            planned.append(("x230", "cancel"))
        report["planned_cases"] = planned
        for host, kind in planned:
            item = report["hosts"][host]
            child_config = {"host": host, "case": kind, "nonce": report["nonce"],
                            "fixture": item["fixture"], "fixture_identity": item["prepare"]["fixture_identity"]}
            request = {"host": host, "executable": "/usr/bin/python3",
                       "args": ["-I", "-S", "-u", "-c", CHILD, bench.canonical(child_config).decode().strip()],
                       "cwd": item["fixture"], "env": {}, "timeout_seconds": 12,
                       "idempotency_key": "inherited-pipe-" + report["nonce"] + "-" + host + "-" + kind}
            case = {"host": host, "case": kind, "request": request, "child_config": child_config,
                    "passed": False, "start_submitted_once": False, "cleanup": {"remote_signals": 0}}
            report["cases"].append(case)
            ledger.save()
            try:
                case["start_submitted_once"] = True
                started = native(active, host, "process_start", request)
                record = started["job"]
                case.update(record=record, job_id=record["id"])
                bench.need(started.get("reused") is False and record["host"] == host
                           and record["launch_state"] == "launched" and started["launch"]["ok"] is True,
                           "new native job was not acknowledged")
                bench.need(PurePosixPath(record["remote_job_dir"]) == PurePosixPath(item["fixture"]) / "jobs" / record["id"]
                           and record["args"] == request["args"] and record["idempotency_key"] == request["idempotency_key"],
                           "new native job escaped original fixture/request")
                original_raw = bench.read_file(state / "jobs" / (record["id"] + ".json"), 131072)
                source_records[record["id"]] = original_raw
                case["controller_record_sha256"] = bench.digest(original_raw)
                reference = {"host": host, "job_id": record["id"]}
                if kind == "cancel":
                    case["unreaped_leader_proof"] = remote(host, "probe_unreaped", case)
                    bench.need(case["unreaped_leader_proof"].get("ready") is True, "cancel window missed; no cancellation submitted")
                    case["cancel_submitted_once"] = True
                    ledger.save()
                    case["cancel_response"] = native(active, host, "process_cancel", {**reference, "grace_seconds": 0})
                terminal_until = time.monotonic() + 16
                while True:
                    status = native(active, host, "process_status", reference)
                    case["last_status"] = status
                    if status.get("state") not in ("running", "activating", "finalizing"):
                        break
                    bench.need(time.monotonic() < terminal_until, "original job terminal observation deadline")
                    time.sleep(.1)
                output = native(active, host, "process_read", {**reference, "stdout_offset": 0, "stderr_offset": 0, "limit": 16384})
                proof = remote(host, "inspect", case)
                case.update(output=output, independent_proof=proof)
                validate(case, status, output, proof)
                case["passed"] = True
            except BaseException as error:
                case["error"] = type(error).__name__ + ": " + str(error)
                # An uncertain start can already have a durable original ID.
                # Retain that exact local record; never submit another start.
                if "job_id" not in case:
                    try:
                        matches = []
                        for path in (state / "jobs").glob("*.json"):
                            raw = bench.read_file(path, 131072)
                            value = json.loads(raw)
                            if value.get("idempotency_key") == request["idempotency_key"]:
                                bench.need(value.get("host") == host and value.get("args") == request["args"]
                                           and PurePosixPath(value["remote_job_dir"]) == PurePosixPath(item["fixture"]) / "jobs" / value["id"]
                                           and path.name == value["id"] + ".json", "uncertain original record differs")
                                matches.append((value, raw))
                        bench.need(len(matches) <= 1, "multiple records for the single submitted start")
                        if matches:
                            record, original_raw = matches[0]
                            case.update(record=record, job_id=record["id"], start_outcome_unknown=True)
                            source_records[record["id"]] = original_raw
                    except BaseException as binding_error:
                        case["uncertain_start_record_error"] = type(binding_error).__name__ + ": " + str(binding_error)
                # Never compensate with a relaunch or PID signal. A single
                # bounded settle gives an already-started fixed descendant its
                # own complete self-exit interval, then retains a separate read.
                case["cleanup"]["self_exit_settle_seconds"] = 8
                ledger.save()
                time.sleep(8)
                if "job_id" in case:
                    try:
                        case["cleanup"]["independent_after_settle"] = remote(host, "inspect", case)
                    except BaseException as cleanup:
                        case["cleanup"]["observation_error"] = type(cleanup).__name__ + ": " + str(cleanup)
                raise
            finally:
                ledger.save()
        report["shutdown"] = active.close()
        active = None
        shutdown = report["shutdown"]
        bench.need(shutdown["exit_code"] == 0 and shutdown["shutdown_method"] == "stdin_eof"
                   and not shutdown["observed_descendant_survivors"] and shutdown["reader_error"] is None
                   and shutdown["unmatched_responses"] == 0 and shutdown["stdio_reader_alive"] is False
                   and shutdown["wire_capture"]["complete"] is True, "original controller shutdown differs")
        report["passed"] = all(case["passed"] for case in report["cases"]) and len(report["cases"]) == len(planned)
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["passed"] = False
    finally:
        if active is not None:
            try:
                report["failure_shutdown"] = active.close()
            except BaseException as cleanup:
                report["controller_cleanup_error"] = type(cleanup).__name__ + ": " + str(cleanup)
            report["passed"] = False
        try:
            report["binary_unchanged"] = binary_before is not None and bench.digest(bench.read_file(args.candidate, 128 * 1024 * 1024)) == binary_before
            report["agent_unchanged"] = agent_before is not None and bench.agent_identity(agent) == agent_before
            report["source_records_unchanged"] = bool(jobs) and all(bench.read_file(job["path"], 65536) == job["record_bytes"] for job in jobs)
            registry = out / "state" / "jobs"
            paths = list(registry.glob("*.json")) if registry.exists() else []
            report["controller_records"] = []
            for path in paths:
                raw = bench.read_file(path, 131072)
                report["controller_records"].append({"path": str(path), "sha256": bench.digest(raw),
                    "original_bytes_unchanged": raw == source_records.get(path.stem)})
            report["exact_original_controller_records"] = (len(paths) == len(source_records) == len(report["cases"])
                and all(row["original_bytes_unchanged"] for row in report["controller_records"]))
            report["passed"] = report["passed"] and all(report[key] is True for key in (
                "binary_unchanged", "agent_unchanged", "source_records_unchanged", "exact_original_controller_records"))
        except BaseException as error:
            report["final_readback_error"] = type(error).__name__ + ": " + str(error)
            report["passed"] = False
        report["finished_unix"] = time.time()
        try:
            ledger.save()
        except BaseException as error:
            report["passed"] = False
            report["report_save_error"] = type(error).__name__ + ": " + str(error)
            fallback = out / ("report-final-" + str(time.time_ns()) + ".json")
            try:
                bench.create_file(fallback, bench.canonical(report))
            except BaseException:
                print(json.dumps({"unsaved_canary_report": report}), file=sys.stderr, flush=True)
    print(json.dumps({"report": str(out / "report.json"), "passed": report["passed"], "error": report.get("error"),
                      "jobs": [{"host": c["host"], "case": c["case"], "job_id": c.get("job_id"), "passed": c["passed"]}
                               for c in report["cases"]]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
