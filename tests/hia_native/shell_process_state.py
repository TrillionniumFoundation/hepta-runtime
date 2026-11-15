"""Actual HIA shell-owner state tests with explicitly synthetic effects.

The same 23 semantic cases and 14 refusal controls execute against an admitted
native image or replay its complete recorded byte transitions. Replay never
loads executable memory or invokes the OS process adapter. This suite does not
qualify real shell execution, original Rust equivalence, or production routing.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve()
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
KIND = "actual_native_HIA_with_synthetic_effects_not_OS_or_Rust_qualification"
PENDING = 0xfffffff0
FAIL = 0xfffffff9
PAGE = 1024
CASE_COUNT, CONTROL_COUNT, ENTRY_COUNT = 23, 14, 304
SCOPE = {
    "original_rust_compared": False, "real_shell_process_executed": False,
    "production_activated": False, "production_shell_execution_qualified": False,
    "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
}

def need(value, message):
    if not value:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def pairs(rows):
    value = {}
    for key, item in rows:
        need(key not in value, "duplicate JSON field")
        value[key] = item
    return value

def obj(raw):
    return json.loads(raw, object_pairs_hook=pairs)

def raw_file(path):
    path = Path(path)
    need(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(),
         "evidence is not an ordinary file")
    return path.read_bytes()

def pin(path):
    raw = raw_file(path)
    return {"sha256": digest(raw), "size": len(raw)}

def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=True, indent=2)
        stream.write("\n")

def hx(value):
    need(type(value) is str, "hex type")
    raw = bytes.fromhex(value)
    need(raw.hex() == value, "noncanonical hex")
    return raw

def sources():
    return {name: pin(ROOT / name) for name in (
        "tests/hia_native/shell_process_state.py", "native/shell_process.hepta",
        "scripts/hia_native_loader.py",
    )}

def member(directory, name):
    need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name),
         "native member is not a plain basename")
    return directory / name

def owner_manifest(path):
    path = Path(path).resolve(strict=True)
    supplied = raw_file(path)
    outer = obj(supplied)
    selected = path
    if outer.get("schema") == "hepta.runtime.shell-process.v1":
        relative = outer.get("owner_manifest")
        need(type(relative) is str and not Path(relative).is_absolute()
             and ".." not in Path(relative).parts, "owner manifest path")
        # The shell-process build manifest stores module paths relative to its build root.
        selected = path.parent.parent / relative
        need(pin(selected)["sha256"] == outer.get("owner_manifest_sha256"),
             "outer owner manifest binding")
    metadata = obj(raw_file(selected))
    need(metadata.get("schema") == "hepta.runtime.native-module.v1"
         and metadata.get("abi") == "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
         and metadata.get("target") == "linux-x86_64"
         and metadata.get("compiler_commit") == COMPILER, "native owner ABI/compiler")
    members = {}
    for name in ("source", "image"):
        file = member(selected.parent, metadata.get(name))
        members[name] = pin(file)
        need(members[name]["sha256"] == metadata.get(name + "_sha256"),
             "native owner member binding")
    need(members["source"] == pin(ROOT / "native/shell_process.hepta"),
         "compiled owner does not match current source")
    if selected != path:
        for name in ("source", "image"):
            need(outer.get("owner_" + name + "_sha256") == metadata[name + "_sha256"],
                 "outer owner identity")
    return {
        "supplied_manifest": pin(path), "owner_manifest": pin(selected),
        "source": members["source"], "image": members["image"],
        "supplied_manifest_path": str(path), "owner_manifest_path": str(selected),
        "compiler_commit": metadata["compiler_commit"],
    }, selected, metadata

def check_publication(row):
    before, after = hx(row["output_before_hex"]), hx(row["output_after_hex"])
    need(len(before) == len(after) == row["output_capacity"], "output extent")
    returned = row["return_u64"]
    need(type(returned) is int and 0 <= returned <= 0xffffffff, "dirty upper return")
    if returned == 96:
        need(len(after) >= 96 and before[96:] == after[96:], "event tail changed")
        words = struct.unpack("<12Q", after[:96])
        need(after[:8] == b"HSHPRR01" and 1 <= words[1] <= 6 and words[2] == 1,
             "event contract")
        need(words[7] in (0, 1, 2) and words[10] in (0, 1) and words[11] <= 7,
             "event typed fields")
    else:
        need(returned in (0, PENDING, 0xffffffff, 0xfffffffe, FAIL), "unknown return")
        need(before == after, "pending/refusal/retirement published bytes")
    need(row.get("source_and_buffer_guards_checked_by_loader") is True,
         "native guards were not observed")

class BoundarySession:
    def __init__(self, boundary, identity, output_capacity, workspace_capacity):
        self.boundary, self.identity = boundary, identity
        self.output_capacity, self.workspace_capacity = output_capacity, workspace_capacity
        self.native = None
        if boundary.native is None:
            self._output = ctypes.create_string_buffer(output_capacity + 16)
            self._workspace = ctypes.create_string_buffer(workspace_capacity + 16)
        else:
            self.native = boundary.native.session(
                output_capacity=output_capacity, workspace_capacity=workspace_capacity)
            self._output, self._workspace = self.native._output, self.native._workspace

    def invoke_raw(self, wire):
        before = ctypes.string_at(self._output, self.output_capacity)
        previous = ctypes.string_at(self._workspace, self.workspace_capacity)
        number = len(self.boundary.records) + 1
        if self.native is not None:
            returned, after, work = self.native.invoke_raw(wire)
            changes = [
                {"offset": at, "after_hex": work[at:at + PAGE].hex()}
                for at in range(0, len(work), PAGE)
                if previous[at:at + PAGE] != work[at:at + PAGE]
            ]
            row = {
                "entry": number, "session": self.identity, "input_hex": wire.hex(),
                "return_u64": returned, "output_capacity": self.output_capacity,
                "workspace_capacity": self.workspace_capacity,
                "output_before_hex": before.hex(), "output_after_hex": after.hex(),
                "workspace_before_sha256": digest(previous),
                "workspace_after_sha256": digest(work), "workspace_changes": changes,
                "source_and_buffer_guards_checked_by_loader": True,
            }
        else:
            need(number <= len(self.boundary.replay), "unrecorded native entry")
            row = self.boundary.replay[number - 1]
            need(row["entry"] == number and row["session"] == self.identity,
                 "entry/session order")
            need(hx(row["input_hex"]) == wire, "regenerated input differs")
            need(row["output_capacity"] == self.output_capacity
                 and row["workspace_capacity"] == self.workspace_capacity,
                 "invocation capacities differ")
            need(hx(row["output_before_hex"]) == before, "output before entry differs")
            need(row["workspace_before_sha256"] == digest(previous),
                 "synthetic completion/workspace before entry differs")
            changed = bytearray(previous)
            last = -PAGE
            for part in row["workspace_changes"]:
                at, raw = part["offset"], hx(part["after_hex"])
                need(type(at) is int and at % PAGE == 0 and at > last
                     and 0 <= at < len(changed)
                     and len(raw) == min(PAGE, len(changed) - at), "workspace delta extent")
                need(previous[at:at + len(raw)] != raw, "redundant workspace delta")
                changed[at:at + len(raw)] = raw
                last = at
            work = bytes(changed)
            need(row["workspace_after_sha256"] == digest(work), "workspace after entry differs")
            returned, after = row["return_u64"], hx(row["output_after_hex"])
            ctypes.memmove(self._output, after, len(after))
            ctypes.memmove(self._workspace, work, len(work))
        check_publication(row)
        if returned == PENDING:
            words = struct.unpack("<12Q", work[256:352])
            need(work[256:264] == b"HSHPRFX1" and words[1] > 0
                 and 1 <= words[2] <= 19 and words[6:] == (0, 0, 0, 0, 0, 0),
                 "pending effect contract")
        self.boundary.records.append(row)
        return returned, after, work

    def close(self):
        if self.native is not None:
            self.native.close()
        self._output = self._workspace = None

class Boundary:
    def __init__(self, native=None, replay=None):
        self.native, self.replay = native, replay
        self.records, self.sessions = [], 0

    def session(self, *, output_capacity, workspace_capacity):
        self.sessions += 1
        return BoundarySession(self, self.sessions, output_capacity, workspace_capacity)

    def invoke_raw(self, wire, *, output_capacity, workspace_capacity, output_fill, workspace_fill):
        session = self.session(output_capacity=output_capacity, workspace_capacity=workspace_capacity)
        try:
            ctypes.memset(session._output, output_fill, output_capacity)
            ctypes.memset(session._workspace, workspace_fill, workspace_capacity)
            return session.invoke_raw(wire)
        finally:
            session.close()

Q=lambda x:struct.pack('<Q',x)
u64=lambda b,at:struct.unpack_from('<Q',b,at)[0]
def frame(command=b'printf ok',cwd=b'/tmp',op=1):
    return b'HSHPRQ01'+Q(op)+Q(1)+Q(len(command) if op==1 else 0)+Q(len(cwd) if op==1 else 0)+(command+cwd if op==1 else b'')
def env_snapshot(records):
    return Q(len(records))+b''.join(Q(len(x))+x+b'\0' for x in records)
DEFAULT=[b'PATH=/bin:/usr/bin',b'X=first',b'X=last',b'=a=b',b'=x',b'bare',b'BAD=\xff',b'PAGER=wrong']
class Session:
    def __init__(self,module,wire=None):
        self.s=module.session(output_capacity=128,workspace_capacity=1<<20)
        self.wire=wire if wire is not None else frame()
        ctypes.memset(self.s._output,0xa7,128)
        self.out=bytes([0xa7])*128
        self.calls=0
        self.actions=[]
        self.events=[]
        self.ret=None
        self.work=None
    def call(self):
        old=self.out
        self.ret,self.out,self.work=self.s.invoke_raw(self.wire)
        self.calls+=1
        if self.ret in (PENDING,0,0xffffffff,0xfffffffe,FAIL):
            assert self.out==old,('publication on pending/refusal',self.ret)
        elif self.ret==96:
            assert self.out[96:]==old[96:]
            self.events.append(struct.unpack('<12Q',self.out[:96]))
        else:
            raise AssertionError(('unknown return',self.ret))
        if self.ret==PENDING:
            self.actions.append(u64(self.work,272))
        return self.ret
    def put(self,at,raw):
        ctypes.memmove(ctypes.addressof(self.s._workspace)+at,raw,len(raw))
    def complete(self,result=0,error=0,aux=0):
        assert self.ret==PENDING
        self.put(312,Q(result)+Q(error)+Q(aux)+Q(1))
        return self.call()
    def defaults(self,child=False,records=None):
        action=u64(self.work,272)
        if action==2:
            snap=env_snapshot(DEFAULT if records is None else records)
            self.put(u64(self.work,280),snap)
            return self.complete(len(snap))
        if action==5:
            return self.complete(0 if child else 1234,0,7)
        if action==10:
            return self.complete(1234)
        if action==15:
            return self.complete(100)
        return self.complete()
    def to(self,action,child=False,records=None):
        if self.ret is None:
            self.call()
        for _ in range(100):
            if self.ret==PENDING and u64(self.work,272)==action:
                return
            assert self.ret==PENDING,(self.ret,self.actions)
            self.defaults(child,records)
        raise AssertionError('no target action')
    def resume(self,op=2):
        self.wire=frame(op=op)
        return self.call()
    def close(self):
        self.s.close()

def expected_env(records):
    data={}
    for row in records:
        p=row.find(b'=',1)
        if p>=0:
            data[row[:p]]=row
    for row in [b'GIT_TERMINAL_PROMPT=0',b'DEBIAN_FRONTEND=noninteractive',b'PAGER=cat',b'GIT_PAGER=cat',b'NO_COLOR=1']:
        data[row.split(b'=',1)[0]]=row
    return [data[k] for k in sorted(data)]
def actual_env(work):
    at=u64(work,168);count=u64(work,176)
    return [work[u64(work,at+i*32):u64(work,at+i*32)+u64(work,at+i*32+8)] for i in range(count)]

def exercise(module):
    results=[]
    for records in (DEFAULT,[],[b'PATH=',b'Z=1',b'A=1',b'A=2',b'NO_COLOR=0'],[b'\xff=1',b'=a=first',b'=a=last',b'A=3']):
        s=Session(module);s.to(3,records=records)
        assert actual_env(s.work)==expected_env(records)
        results.append({'case':'environment','actions':s.actions,'calls':s.calls,
          'environment_snapshot_records_hex':[x.hex() for x in records],
          'actual_environment_records_hex':[x.hex() for x in actual_env(s.work)]});s.close()

    s=Session(module);s.to(16);assert s.complete(1,0,3<<8)==PENDING
    assert u64(s.work,272)==14 and u64(s.work,288)==0
    assert s.complete()==96 and s.events[-1][1]==2 and s.events[-1][5]==3
    assert s.resume()==0
    results.append({'case':'foreground','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0)
    assert u64(s.work,272)==15
    assert s.complete(10000000100)==96 and s.events[-1][1]==3
    assert s.resume()==PENDING and u64(s.work,272)==16
    s.complete(1,0,0);assert u64(s.work,272)==14
    assert s.complete()==96 and s.events[-1][1]==4
    assert s.resume()==0
    results.append({'case':'promotion','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0);s.complete(200)
    assert u64(s.work,272)==17
    s.wire=frame(op=3);s.complete()
    assert u64(s.work,272)==18 and u64(s.work,288)==1
    s.complete();assert u64(s.work,272)==16
    assert s.complete(0)==96 and s.events[-1][1]==5 and s.events[-1][10]==1
    assert s.resume()==PENDING and u64(s.work,272)==16
    assert s.complete(1,0,9)==0
    assert u64(s.work,56)==1
    results.append({'case':'cancel_nonblocking_ack_orphan','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0);s.complete(200)
    s.wire=frame(op=4);s.complete()
    assert u64(s.work,272)==14
    s.complete();assert u64(s.work,272)==18 and u64(s.work,288)==2
    assert s.complete()==96 and s.events[-1][1]==6
    s.resume();s.complete(1,0,9);s.complete()
    assert s.events[-1][1]==2
    assert s.resume()==0
    results.append({'case':'shutdown_group','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16)
    s.complete(0,4)
    assert u64(s.work,272)==18
    s.complete();assert u64(s.work,272)==16
    s.complete(1,0,9);s.complete()
    assert s.ret==96 and s.events[-1][1]==2 and s.events[-1][7]==1 and s.events[-1][8]==4
    assert s.events[-1][5]==0xffffffffffffffff
    assert s.resume()==0
    results.append({'case':'try_wait_eintr_is_ready_error','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(13)
    s.complete(1,2)
    assert u64(s.work,272)==16 and u64(s.work,288)==1
    s.complete(0,4);assert u64(s.work,272)==16
    s.complete(1,0,1<<8);assert u64(s.work,272)==19
    assert s.complete()==96 and s.events[-1][1]==1 and s.events[-1][8]==2
    results.append({'case':'spawn_error_reap_eintr','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module,frame(b'echo\0x'));s.call()
    assert s.complete()==96 and s.events[-1][1]==1 and s.events[-1][7]==2
    results.append({'case':'nul_spawn_error','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    for path,expected in [(b'/a:/b',[b'/a/sh',b'/b/sh']), (b':/b:',[b'sh',b'/b/sh',b'sh']), (b'', [b'sh']), (b'a'*4096+b':/b',[b'sh',b'/b/sh'])]:
        s=Session(module);s.to(11,child=True,records=[b'PATH='+path])
        seen=[]
        for candidate in expected:
            assert u64(s.work,272)==11
            at=u64(s.work,280);n=u64(s.work,288)
            seen.append(s.work[at:at+n])
            assert seen[-1]==candidate,(path[:10],seen,expected)
            s.complete(0,2)
        assert u64(s.work,272)==12 and u64(s.work,280)==2
        results.append({'case':'path_candidates','candidates':[x.hex() for x in seen],'actions':s.actions,'calls':s.calls});s.close()

    s=Session(module);s.to(11,child=True,records=[b'PATH=/a:/b'])
    s.complete(0,8)
    at=u64(s.work,280);n=u64(s.work,288)
    assert s.work[at:at+n]==b'/bin/sh' and u64(s.work,512)==1
    s.complete(0,2)
    at=u64(s.work,280);n=u64(s.work,288)
    assert s.work[at:at+n]==b'/b/sh'
    s.complete(0,13)
    assert u64(s.work,272)==12 and u64(s.work,280)==13
    results.append({'case':'enoexec_fallback_errno_continuation','actions':s.actions,'calls':s.calls});s.close()

    s=Session(module);s.call();s.wire=frame(op=3);s.complete()
    s.to(18)
    assert 5 in s.actions and 13 in s.actions and 14 in s.actions
    assert u64(s.work,288)==1
    s.complete();assert u64(s.work,272)==16
    assert s.complete(1,0,9)==96 and s.events[-1][1]==5
    assert s.resume()==0
    results.append({'case':'startup_cancel_latched_through_spawn','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0);s.complete(10000000100)
    assert s.ret==96 and s.events[-1][1]==3
    s.resume(3);assert u64(s.work,272)==16
    s.complete(1,0,0);s.complete()
    assert s.events[-1][1]==4 and 18 not in s.actions
    assert s.resume()==0
    results.append({'case':'cancel_after_promotion_does_not_kill_moved_child','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0);s.complete(10000000100);s.resume()
    s.complete(0,4)
    assert u64(s.work,272)==14
    assert s.complete()==96 and s.events[-1][1]==4 and s.events[-1][8]==4
    assert s.resume()==PENDING and u64(s.work,272)==18
    assert s.complete()==PENDING and u64(s.work,272)==16
    assert s.complete(1,0,9)==0
    results.append({'case':'background_wait_error_callback_before_drop_signal','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(2)
    assert s.complete(0,105,u64(s.work,288)+1)==0xfffffffe
    results.append({'case':'environment_capacity_is_transport_refusal','actions':s.actions,'calls':s.calls});s.close()

    s=Session(module,frame(cwd=b'/tmp/\xff'));s.to(3)
    at=u64(s.work,136);n=u64(s.work,144)
    assert s.work[at:at+n]==b'/tmp/\xff'
    results.append({'case':'cwd_retains_invalid_utf8_bytes','actions':s.actions,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0);s.complete(200)
    s.wire=frame(op=3);s.complete();s.complete();s.complete(0)
    assert s.ret==96 and s.events[-1][1]==5
    assert s.resume(4)==PENDING and u64(s.work,272)==14
    s.complete();assert u64(s.work,272)==18 and u64(s.work,288)==2
    assert s.complete()==96 and s.events[-1][1]==6
    s.resume();assert u64(s.work,272)==16
    assert s.complete(1,0,9)==0
    assert [x[1] for x in s.events]==[5,6]
    results.append({'case':'abandoned_pending_child_still_receives_shutdown_group_cleanup','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    s=Session(module);s.to(16);s.complete(0,4)
    assert u64(s.work,272)==18
    s.complete();assert u64(s.work,272)==16
    s.complete(0);assert u64(s.work,272)==14
    assert s.complete()==96 and s.events[-1][1]==2 and s.events[-1][8]==4
    assert s.events[-1][5]==0xffffffffffffffff and s.events[-1][10]==0
    s.resume(4)
    assert u64(s.work,272)==16
    assert s.complete(1,0,0)==0
    assert [x[1] for x in s.events]==[2]
    assert s.actions.count(18)==1
    results.append({'case':'foreground_wait_error_quiet_reap_never_signals_unregistered_group','actions':s.actions,'events':s.events,'calls':s.calls});s.close()

    controls=[]
    for at,val in [(264,999),(272,19),(280,8),(288,1),(296,1),(304,1),(344,1),(336,2),(328,1),(320,4096)]:
        s=Session(module);s.call()
        s.put(312,Q(0)+Q(0)+Q(0)+Q(1))
        s.put(at,Q(val))
        assert s.call()==FAIL,(at,val,s.ret)
        controls.append({'offset':at,'value':val});s.close()
    for wire,output,work,expected in [(b'',128,1<<20,0xffffffff),(frame(b'\xff'),128,1<<20,0xffffffff),(frame(),95,1<<20,0xfffffffe),(frame(),128,8191,0xfffffffe)]:
        result,out,w=module.invoke_raw(wire,output_capacity=output,workspace_capacity=work,output_fill=0xa7,workspace_fill=0)
        assert result==expected and out==bytes([0xa7])*output
        controls.append({'wire_hex':wire.hex(),'output':output,'workspace':work,'return':result})
    return results, controls

def validate_report(report):
    need(type(report) is dict and report.get("schema") == "hepta.runtime.shell-process-state.v1"
         and report.get("status") == "PASS" and report.get("kind") == KIND, "scope/status")
    need(all(report.get(key) is value for key, value in SCOPE.items()), "overstated scope")
    rows = report.get("actual_entries")
    need(type(rows) is list and type(report.get("native_entries")) is int
         and len(rows) == report["native_entries"] == ENTRY_COUNT, "entry coverage")
    need(type(report.get("case_count")) is int
         and report["case_count"] == len(report["cases"]) == CASE_COUNT, "semantic coverage")
    need(type(report.get("control_count")) is int
         and report["control_count"] == len(report["controls"]) == CONTROL_COUNT, "refusal coverage")
    boundary = Boundary(replay=rows)
    cases, controls = exercise(boundary)
    need(len(boundary.records) == len(rows), "unconsumed actual entries")
    need(obj(json.dumps(cases)) == report["cases"], "semantic results differ from byte replay")
    need(controls == report["controls"], "refusals differ from byte replay")
    return {"cases": len(cases), "controls": len(controls), "entries": len(rows)}

def reader_controls(report):
    result = []
    pending = next(i for i, row in enumerate(report["actual_entries"]) if row["return_u64"] == PENDING)
    event = next(i for i, row in enumerate(report["actual_entries"]) if row["return_u64"] == 96)
    for name in (
        "pending_output_write", "event_output_tail_write", "missing_entry",
        "dirty_return_upper_bits", "false_guard_flag",
    ):
        changed = copy.deepcopy(report)
        if name in ("pending_output_write", "event_output_tail_write"):
            index = pending if name == "pending_output_write" else event
            row = changed["actual_entries"][index]
            raw = bytearray(hx(row["output_after_hex"]))
            raw[0 if index == pending else -1] ^= 1
            row["output_after_hex"] = raw.hex()
        elif name == "missing_entry":
            changed["actual_entries"].pop()
        elif name == "dirty_return_upper_bits":
            changed["actual_entries"][pending]["return_u64"] += 1 << 32
        else:
            changed["actual_entries"][pending]["source_and_buffer_guards_checked_by_loader"] = False
        try:
            validate_report(changed)
        except (ValueError, AssertionError) as error:
            result.append({"name": name, "rejected": True, "reason": str(error)})
        else:
            raise ValueError("reader accepted corrupted evidence: " + name)
    return result

def execute_child(folder):
    """Only this explicit child entry point imports the native executable loader."""
    folder = Path(folder).resolve(strict=True)
    loader = folder / "hia_native_loader.py"
    spec = importlib.util.spec_from_file_location("shell_state_native_loader", loader)
    need(spec is not None and spec.loader is not None, "cannot load recorded native loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = folder / "native/manifest.json"
    with module.NativeModule(manifest, manifest_sha256=digest(raw_file(manifest))) as native:
        boundary = Boundary(native=native)
        cases, controls = exercise(boundary)
        report = {
            "schema": "hepta.runtime.shell-process-state.v1", "status": "PASS", "kind": KIND,
            "case_count": len(cases), "control_count": len(controls),
            "native_entries": len(boundary.records), "cases": cases, "controls": controls,
            "actual_entries": boundary.records, "source_sha256": native.metadata["source_sha256"],
            "image_sha256": native.metadata["image_sha256"],
            "driver": pin(SOURCE), "loader": pin(loader), "manifest": pin(manifest), **SCOPE,
        }
        need((len(cases), len(controls), len(boundary.records))
             == (CASE_COUNT, CONTROL_COUNT, ENTRY_COUNT), "actual case inventory changed")
    write_json(folder / "native-results.json", report)
    return {
        "status": "PASS", "kind": KIND, "case_count": len(cases), "control_count": len(controls),
        "native_entries": len(boundary.records), "result_file": "native-results.json",
        "result": pin(folder / "native-results.json"),
        "optimization_level": sys.flags.optimize,
    }

def run(native_manifest, output):
    binding, selected, metadata = owner_manifest(native_manifest)
    source_files = sources()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "native").mkdir()
    copies = {
        "state_driver.py": SOURCE, "hia_native_loader.py": ROOT / "scripts/hia_native_loader.py",
        "native/manifest.json": selected, "supplied-manifest.json": Path(native_manifest).resolve(),
        "native/" + metadata["source"]: member(selected.parent, metadata["source"]),
        "native/" + metadata["image"]: member(selected.parent, metadata["image"]),
    }
    for name, source in copies.items():
        shutil.copyfile(source, output / name)
    command = [sys.executable, str(output / "state_driver.py"), "--_execute", str(output)]
    environment = os.environ.copy()
    environment.pop("PYTHONOPTIMIZE", None)
    started_ns = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               cwd=output, env=environment)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    finished_ns = time.monotonic_ns()
    (output / "stdout.bin").write_bytes(stdout)
    (output / "stderr.bin").write_bytes(stderr)
    receipt = {
        "schema": "hepta.runtime.shell-process-state-execution.v1", "command": command,
        "cwd": str(output), "pid": process.pid, "returncode": process.returncode,
        "completed": True, "timed_out": timed_out, "started_ns": started_ns,
        "finished_ns": finished_ns, "elapsed_ns": finished_ns - started_ns,
        "optimization_disabled": True, "stdout": pin(output / "stdout.bin"),
        "stderr": pin(output / "stderr.bin"), **SCOPE,
    }
    write_json(output / "process.json", receipt)
    need(process.returncode == 0 and not timed_out and not stderr,
         "actual state suite child did not finish successfully")
    need(sources() == source_files and owner_manifest(native_manifest)[0] == binding,
         "qualification source/image changed during actual execution")
    files = tuple(copies) + ("stdout.bin", "stderr.bin", "process.json", "native-results.json")
    report = {
        "schema": "hepta.runtime.shell-process-state-evidence.v1", "status": "PASS",
        "source_files": source_files, "native": binding, "recorded_directory": str(output),
        "files": {name: pin(output / name) for name in files}, **SCOPE,
    }
    write_json(output / "report.json", report)
    return read_evidence(output, native_manifest)

def read_evidence(folder, native_manifest=None):
    """Read, reconstruct, and reject altered evidence without executing native code."""
    need(sys.flags.optimize == 0, "state suite must run with Python assertions enabled")
    folder = Path(folder).resolve(strict=True)
    report = obj(raw_file(folder / "report.json"))
    need(report.get("schema") == "hepta.runtime.shell-process-state-evidence.v1"
         and report.get("status") == "PASS", "evidence schema/status")
    need(all(report.get(key) is value for key, value in SCOPE.items()), "overstated scope")
    need(report.get("source_files") == sources(), "qualification source differs")
    manifest_raw = raw_file(folder / "native/manifest.json")
    metadata = obj(manifest_raw)
    need(metadata.get("schema") == "hepta.runtime.native-module.v1"
         and metadata.get("abi") == "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
         and metadata.get("target") == "linux-x86_64"
         and metadata.get("compiler_commit") == COMPILER, "copied compiler/ABI pin")
    source_name = "native/" + member(Path(), metadata.get("source")).name
    image_name = "native/" + member(Path(), metadata.get("image")).name
    expected_files = {
        "state_driver.py", "hia_native_loader.py", "native/manifest.json",
        "supplied-manifest.json", source_name, image_name,
        "stdout.bin", "stderr.bin", "process.json", "native-results.json",
    }
    need(type(report.get("files")) is dict and set(report["files"]) == expected_files,
         "evidence file inventory")
    for name in expected_files:
        need(pin(folder / name) == report["files"][name], "evidence member changed: " + name)
    need(pin(folder / "state_driver.py") == pin(SOURCE), "executed driver bytes differ")
    need(pin(folder / "hia_native_loader.py") == pin(ROOT / "scripts/hia_native_loader.py"),
         "executed loader bytes differ")
    need(pin(folder / source_name) == pin(ROOT / "native/shell_process.hepta")
         and pin(folder / source_name)["sha256"] == metadata.get("source_sha256"),
         "executed HIA source differs")
    need(pin(folder / image_name)["sha256"] == metadata.get("image_sha256"), "executed image differs")
    native = report["native"]
    for key, path in (
        ("supplied_manifest", "supplied-manifest.json"), ("owner_manifest", "native/manifest.json"),
        ("source", source_name), ("image", image_name),
    ):
        need(native[key] == pin(folder / path), "recorded native binding differs")
    need(native["compiler_commit"] == COMPILER, "recorded compiler differs")
    outer = obj(raw_file(folder / "supplied-manifest.json"))
    if outer.get("schema") == "hepta.runtime.shell-process.v1":
        need(outer.get("owner_manifest_sha256") == digest(manifest_raw)
             and outer.get("owner_source_sha256") == metadata["source_sha256"]
             and outer.get("owner_image_sha256") == metadata["image_sha256"],
             "copied outer binding differs")
    else:
        need(raw_file(folder / "supplied-manifest.json") == manifest_raw,
             "supplied standalone owner differs")
    if native_manifest is not None:
        current, _, _ = owner_manifest(native_manifest)
        for key in ("supplied_manifest", "owner_manifest", "source", "image", "compiler_commit"):
            need(current[key] == native[key], "current native binding differs")
    process = obj(raw_file(folder / "process.json"))
    need(process.get("schema") == "hepta.runtime.shell-process-state-execution.v1"
         and process.get("completed") is True and process.get("timed_out") is False
         and type(process.get("returncode")) is int and process["returncode"] == 0,
         "actual process did not complete")
    need(all(process.get(key) is value for key, value in SCOPE.items()), "process scope")
    directory = report["recorded_directory"]
    need(type(directory) is str and Path(directory).is_absolute(), "recorded execution directory")
    command = process["command"]
    need(type(command) is list and len(command) == 4 and Path(command[0]).is_absolute()
         and command[1:] == [str(Path(directory) / "state_driver.py"), "--_execute", directory]
         and process["cwd"] == directory and process.get("optimization_disabled") is True,
         "actual process invocation differs")
    need(type(process.get("pid")) is int and process["pid"] > 0, "missing process identity")
    need(type(process["started_ns"]) is int and type(process["finished_ns"]) is int
         and process["finished_ns"] >= process["started_ns"]
         and process["elapsed_ns"] == process["finished_ns"] - process["started_ns"],
         "actual process timing differs")
    need(process["stdout"] == pin(folder / "stdout.bin")
         and process["stderr"] == pin(folder / "stderr.bin")
         and raw_file(folder / "stderr.bin") == b"", "actual process streams differ")
    summary = obj(raw_file(folder / "stdout.bin"))
    need(summary.get("status") == "PASS" and summary.get("kind") == KIND
         and summary.get("optimization_level") == 0
         and summary.get("result_file") == "native-results.json"
         and summary.get("result") == pin(folder / "native-results.json"), "child stdout differs")
    actual = obj(raw_file(folder / "native-results.json"))
    need(actual.get("driver") == pin(folder / "state_driver.py")
         and actual.get("loader") == pin(folder / "hia_native_loader.py")
         and actual.get("manifest") == pin(folder / "native/manifest.json")
         and actual.get("source_sha256") == metadata["source_sha256"]
         and actual.get("image_sha256") == metadata["image_sha256"], "actual entry source binding")
    for key in ("case_count", "control_count", "native_entries"):
        need(summary[key] == actual[key], "child summary count differs")
    facts = validate_report(actual)
    controls = reader_controls(actual)
    return {
        "status": "PASS", "schema": "hepta.runtime.shell-process-state-readback.v1",
        "verification": "portable-byte-evidence-with-state-replay", **facts,
        "reader_controls": controls, "reader_control_count": len(controls),
        "source_sha256": metadata["source_sha256"],
        "report_sha256": digest(raw_file(folder / "report.json")), **SCOPE,
    }

def main():
    need(sys.flags.optimize == 0, "state suite must run with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--_execute", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._execute is not None:
        result = execute_child(args._execute)
    elif args.verify is not None:
        result = read_evidence(args.verify, args.native_manifest)
    else:
        if args.native_manifest is None or args.output is None:
            parser.error("--native-manifest and --output are required for actual execution")
        result = run(args.native_manifest, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
