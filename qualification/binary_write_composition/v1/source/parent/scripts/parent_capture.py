#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete frozen inputs through unchanged original and actual standalone HIA."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import struct
import sys
import time
import traceback

sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from buffer_store import Writer
from carrier import Carrier
from parent_protocol import wire,result as parent_result
from protocol import U,stat_value,proc_fds

LANES=("original-1","original-2","native-observed","native-unobserved")
MAGICS={b"HBPWHK01":"parent",b"HBWTHK01":"write",b"HPUBHK01":"publish",b"HBRDHK01":"read",b"HMDTHK01":"metadata",b"HENTHK01":"entropy"}


def projection(root):
    """Retain every reachable node and every byte; unreadable nodes are explicit."""
    root=Path(root)
    rows={}
    pending=[root]
    while pending:
        path=pending.pop()
        name="."if path==root else path.relative_to(root).as_posix()
        info=path.lstat()
        row=dict(stat=stat_value(info))
        if stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink",target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row["kind"]="directory"
            try:children=sorted(path.iterdir())
            except OSError as error:
                row["children_error"]=dict(type=type(error).__name__,errno=error.errno)
            else:
                row["children"]=[p.name for p in children]
                pending.extend(reversed(children))
        elif stat.S_ISREG(info.st_mode):
            raw=path.read_bytes()
            row.update(kind="regular",bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),hex=raw.hex())
        elif stat.S_ISFIFO(info.st_mode):
            row["kind"]="fifo"
        else:raise ValueError("unexpected fixture node kind")
        rows[name]=row
    return rows


def setup(root):
    require(not root.exists(),"fresh exclusively owned fixture")
    root.mkdir()
    for name in ("a/b","directory","denied","back\\slash","x"*255):
        (root/name).mkdir(parents=True)
    deep=root
    for index in range(12):
        deep=deep/("d"+str(index));deep.mkdir()
    (root/"ordinary").write_bytes(b"ordinary parent\n")
    (root/"existing.bin").write_bytes(b"retained prior bytes\0\xff")
    (root/"linkdir").symlink_to("a",target_is_directory=True)
    (root/"outside-link").symlink_to("/",target_is_directory=True)
    (root/"targetlink").symlink_to("existing.bin")
    os.mkfifo(root/"fifo",0o600)
    (root/"denied").chmod(0)
    return projection(root)


def discard(root):
    if root.exists():
        (root/"denied").chmod(0o700)
        shutil.rmtree(root)


def concrete(case,root,observed):
    value=str(root)
    replace=lambda text:text.replace("{R0}",value.lstrip("/")).replace("{R}",value)
    return dict(op="write",root=replace(case["root"]),path=replace(case["path"]),
                expected_version=case["expected_version"],data_base64=case["data_base64"],observer=observed)


class Hooks:
    def __init__(self,carrier,case,store):
        self.carrier=carrier;self.case=case;self.store=store
        self.events=[];self.eof=[];self.limit=None

    def consume(self,raw):
        require(len(raw)==64,"one complete before-effect notification")
        if raw[:8]==b"HBWTEOF1":
            require(not self.eof,"one final live descriptor witness")
            self.eof.append(dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),fds=proc_fds(self.carrier.pid)))
            return bytes(8)
        require(raw[:8]in MAGICS,"fixed parent/child observer family")
        words=list(struct.unpack("<7Q",raw[8:]))
        row=dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),owner=MAGICS[raw[:8]],words=words)
        if self.case["nofile"] and self.limit is None and raw[:8]==b"HBPWHK01" and words[3]==1:
            current=proc_fds(self.carrier.pid)
            require(sorted(map(int,current))==[0,1,2,3,4,5],"fixed six-channel descriptor profile")
            before=resource.prlimit(self.carrier.pid,resource.RLIMIT_NOFILE)
            during=(self.case["nofile"],before[1])
            resource.prlimit(self.carrier.pid,resource.RLIMIT_NOFILE,during)
            require(resource.prlimit(self.carrier.pid,resource.RLIMIT_NOFILE)==during,"actual bounded descriptor limit")
            self.limit=dict(before=list(before),during=list(during),fds=current)
        row["fds"]=proc_fds(self.carrier.pid)
        self.events.append(row)
        return bytes(8)

    def restore_limit(self):
        if self.limit is not None and "after"not in self.limit:
            resource.prlimit(self.carrier.pid,resource.RLIMIT_NOFILE,tuple(self.limit["before"]))
            self.limit["after"]=list(resource.prlimit(self.carrier.pid,resource.RLIMIT_NOFILE))
            require(self.limit["after"]==self.limit["before"],"actual original descriptor limit restored")


def eligible(case,lane):
    return lane!="native-unobserved"or not(case["fault_plans"]or case["descriptor_actor"]or case["nofile"])


def capture_case(case,lane,root,output,binary,store):
    started=time.monotonic_ns()
    output.mkdir()
    native=lane.startswith("native")
    observed=lane!="native-unobserved"
    initial=setup(root)
    query=concrete(case,root,observed)
    argv=None if native else [Path(sys.executable).resolve(),"-I","-S","-B",SOURCE/"scripts/reference_worker.py",SOURCE]
    program=binary if native else Path(sys.executable).resolve()
    carrier=Carrier(program,output,store,argv)
    hooks=Hooks(carrier,case,store);carrier.hooks=hooks
    row=dict(input=case,lane=lane,query=query,setup=initial,events=[],controls=[],snapshots={},kernel_observer_required=True)
    complete=False

    def exchange(command,payload=b"",application=False):
        raw,index=carrier.exchange(command,0,payload,application=application)
        row["events"].append(dict(command=command,exchange=index,result=U(raw,8),payload=store.put(raw[64:])))
        return raw,index

    def snapshot(command,name):
        raw,index=exchange(command)
        require(U(raw,8)==0,"complete native owned snapshot")
        result=dict(exchange=index,bytes=store.put(raw[64:]))
        row["snapshots"][name]=result
        if command==4:result["actual_process_bytes"]=carrier.observed_context(raw[64:])
        return raw[64:]

    try:
        raw,_=exchange(8 if observed else 9)
        require(U(raw,8)==0,"fresh actual context")
        if native and case["id"]==0:
            before=snapshot(4,"admission_control_before")
            for offset in(272,280):
                raw,index=exchange(28,struct.pack("<Q",offset))
                after=snapshot(4,"admission_control_after_"+str(offset))
                require(U(raw,8)==0xfffffffd and after==before,"actual inconsistent ownership destroy refusal")
                row["controls"].append(dict(label="idle-owned-flag-"+str(offset),exchange=index,result=U(raw,8)))
        if case["fd0"]:
            raw,_=exchange(17);require(U(raw,8)==0,"actual input-pipe move, target FD0 remains ordinary")
        if case["fsize"]is not None:
            raw,_=exchange(24,struct.pack("<Q",case["fsize"]));require(U(raw,8)==0,"actual regular-file limit")
        if case["fault_plans"]:
            raw,_=exchange(18,b"".join(struct.pack("<7Q",*plan)for plan in case["fault_plans"]))
            require(U(raw,8)==0,"complete actual kernel fault plan armed")
        if case["descriptor_actor"]:
            raw,_=exchange(27,struct.pack("<Q",case["descriptor_actor"]))
            require(U(raw,8)==0,"one frozen actual descriptor-table actor armed")
        raw,_=exchange(23);require(U(raw,8)==0,"real pre-exit descriptor witness armed")
        packet=wire(query)if native else encoded(query)
        row["application_input"]=store.put(packet)
        raw,index=exchange(1,packet,application=True)
        hooks.restore_limit()
        require(U(raw,8)==(64 if native else 0)and U(raw,24)==2 and U(raw,32)==1 and U(raw,40)==0,
                "one real application did not produce its complete held result")
        row["application_exchange"]=index
        row["application_frame"]=store.put(raw[64:])
        row["result"]=parent_result(raw[64:])if native else decode(raw[64:])
        row["after_application"]=projection(root)
        row["fds_with_result"]=proc_fds(carrier.pid)
        row["process_with_result"]=carrier.observed_process()
        if native:
            for command,name in ((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(11,"pool"),(21,"entropy"),(22,"entropy_workspace")):
                snapshot(command,name)
            if not row["result"]["ok"]:
                formatted,index=exchange(13)
                require(U(formatted,8)==U(formatted,16),"actual complete retained error formatter output")
                row["formatter"]=dict(exchange=index,bytes=store.put(formatted[64:]))
                row["result"]["error"]["exact_str"]=formatted[64:].decode()
            if case["id"]==0:
                before=snapshot(4,"control_before")
                for label,command,payload,expected in (("borrowed-invoke",1,packet,0xfffffffd),
                    ("borrowed-destroy",3,b"",0xfffffffd),("null-pool",25,b"",(1<<64)-22),
                    ("null-entropy",26,b"",(1<<64)-22)):
                    refusal,number=exchange(command,payload)
                    after=snapshot(4,"control_after_"+label)
                    require(U(refusal,8)==expected and before==after,"actual lifetime/capability refusal changed bytes")
                    row["controls"].append(dict(label=label,exchange=number,result=expected))
        raw,index=exchange(2)
        require(U(raw,8)==0 and U(raw,24)==0 and U(raw,40)==0,"complete actual result release")
        row["release_exchange"]=index
        row["fds_after_release"]=proc_fds(carrier.pid)
        if native:
            snapshot(11,"pool_after_release")
        raw,index=exchange(3)
        require(U(raw,8)==0 and U(raw,24)==0,"actual context destruction")
        row["destroy_exchange"]=index
        row["fds_after_destroy"]=proc_fds(carrier.pid)
        if native:
            snapshot(11,"pool_after_destroy")
        receipt=carrier.finish()
        require(not(Path("/proc")/str(carrier.pid)).exists(),"target process remains after final reap")
        row.update(hooks=dict(events=hooks.events,eof=hooks.eof,limit=hooks.limit,
                              result_substitutions=0,ack_only_eight_zero_bytes=True),process=receipt,
                   after_exit=projection(root),elapsed_ns=time.monotonic_ns()-started,
                   whole_process_exited=True)
        require(row["elapsed_ns"]<180_000_000_000,"original per-case 180 second budget")
        (output/"CASE.json").write_bytes(encoded(row))
        complete=True
        return dict(id=case["id"],name=case["name"],lane=lane,case=pin(output/"CASE.json"),elapsed_ns=row["elapsed_ns"])
    except BaseException as error:
        failure=dict(status="HOLD",observations=row,error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
        try:failure["retained_filesystem"]=projection(root)
        except BaseException as secondary:failure["filesystem_capture_error"]=repr(secondary)
        try:failure["retained_fds"]=proc_fds(carrier.pid)
        except BaseException as secondary:failure["descriptor_capture_error"]=repr(secondary)
        (output/"CASE_FAILURE.json").write_bytes(encoded(failure))
        raise
    finally:
        carrier.cleanup()
        if complete:discard(root)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    identity=source_evidence(SOURCE)
    domain=decode((SOURCE/"DOMAIN.json").read_bytes())
    require(domain["case_count"]==len(domain["cases"])==256,"complete frozen original input matrix")
    require(sys.version_info[:3]==(3,12,3),"qualification requires the exact original interpreter")
    require(pin(Path(sys.executable).resolve())=={key:domain["original_python"][key]for key in("bytes","sha256")},"original interpreter whole bytes")
    build=args.build.resolve(strict=True)
    build_record=decode((build/"BUILD.json").read_bytes())
    binary=build/"binary-parent-owner-callable.elf"
    require(pin(binary)==build_record["executable"],"exact actual composed HIA executable")
    output=args.output.absolute()
    require(not output.exists(),"fresh complete capture required")
    output.mkdir(parents=True)
    started=time.monotonic_ns()
    store=Writer(output/"buffers")
    rows=[];retry_rows=[]
    planned=[(case,lane)for case in domain["cases"]for lane in LANES if eligible(case,lane)]
    try:
        for case,lane in planned:
            require(time.monotonic_ns()-started<1800_000_000_000,"complete original 1800-second capture budget")
            folder=output/("case-%03d-"%case["id"]+lane)
            row=capture_case(case,lane,output/"fixture",folder,binary,store)
            rows.append(row)
            print(json.dumps(dict(completed=len(rows),planned=len(planned),id=case["id"],lane=lane,seconds=round(row["elapsed_ns"]/1e9,3)),sort_keys=True),flush=True)
        from retry_capture import run_retry
        for case in domain["retry_controls"]:
            for lane in domain["retry_lanes"]:
                require(time.monotonic_ns()-started<1800_000_000_000,"complete original 1800-second capture budget")
                folder=output/("retry-%02d-"%case["id"]+lane)
                row=run_retry(case,lane,output/"fixture",folder,binary,store,SOURCE)
                retry_rows.append(row)
                print(json.dumps(dict(retry_completed=len(retry_rows),retry_planned=6,id=case["id"],lane=lane,
                    seconds=round(row["elapsed_ns"]/1e9,3)),sort_keys=True),flush=True)
        require(source_evidence(SOURCE)==identity,"whole frozen source changed during capture")
        require(time.monotonic_ns()-started<1800_000_000_000,"complete frozen capture exceeded the original total budget")
        record=dict(schema="hepta.runtime.binary-parent-capture.v1",status="COMPLETE_ACTUAL_CAPTURE",
                    source=identity,domain=pin(SOURCE/"DOMAIN.json"),build=pin(build/"BUILD.json"),
                    executable=pin(binary),cases=rows,planned=len(planned),completed=len(rows),
                    retry_controls=retry_rows,retry_planned=6,retry_completed=len(retry_rows),
                    elapsed_ns=time.monotonic_ns()-started,limits=domain["limits"],
                    buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
                    runtime_python_required=False,oracle_python_required=True,whole_runtime_replaced=False,
                    comparison_performed=False,public_binary_write_registered=False)
        (output/"CAPTURE.json").write_bytes(encoded(record))
    except BaseException as error:
        (output/"FAILURE.json").write_bytes(encoded(dict(status="HOLD",completed=len(rows),planned=len(planned),retry_completed=len(retry_rows),retry_planned=6,
            source=identity,elapsed_ns=time.monotonic_ns()-started,error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc())))
        raise


if __name__=="__main__":main()
