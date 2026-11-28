"""New direct owner controls; every valid checkpoint comes from the complete actual producer."""
from pathlib import Path
import struct,sys
CONTROL_ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
import control_common as rc
from common import ROOT,encoded,loads,pin,read,require,source
from owner_cases import INVALID,CAPACITY,checkpoints,plans
def run(build,observed,output):
    import ctypes as C,gzip,os,sys,time
    sys.path.insert(0,str(ROOT/"scripts"))
    from hia_native import NativeModule
    identity=source();control_identity=rc.source();output.mkdir(parents=True,exist_ok=False);selected=checkpoints(observed);wanted=plans(selected);rows=[];done=False
    manifest=build/"modules/namespace-fingerprint/manifest.json"
    with NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"]) as machine,(output/"buffers.bin.gz").open("xb") as raw,gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw,mtime=0) as stream:
        stream.write(b"HNFCT001")
        try:
            for index,plan in enumerate(wanted):
                request,work,no=plan["request"],plan["work"],plan["output_capacity"]
                buffers=[C.create_string_buffer(v,len(v)) for v in (request+b"\xc3"*16,b"\xa5"*(no+16),work+b"\x5a"*16)]
                before=[x.raw for x in buffers];start=time.monotonic_ns()
                returned=int(machine._entry(C.addressof(buffers[0]),len(request),C.addressof(buffers[1]),no,C.addressof(buffers[2]),len(work)))
                elapsed=time.monotonic_ns()-start;after=[x.raw for x in buffers]
                row=dict(index=index,name=plan["name"],origin=plan["origin"],returned=returned,expected=plan["expected"],input_bytes=len(request),
                         output_capacity=no,workspace_capacity=len(work),elapsed_ns=elapsed,before=[pin(x) for x in before],after=[pin(x) for x in after])
                meta=encoded(row);stream.write(b"HNFCALL1"+struct.pack("<6Q",index,returned,len(request),no,len(work),len(meta))+meta)
                for body in before+after:stream.write(body)
                rows.append(row)
                require(returned==plan["expected"] and after[0]==before[0] and after[1][no:]==b"\xa5"*16 and after[2][len(work):]==b"\x5a"*16,"actual direct owner result/guards: "+plan["name"])
                if returned in (INVALID,CAPACITY):require(after[1:]==before[1:],"whole refusal atomicity: "+plan["name"])
                else:require(after[1]==plan["expected_output"]+b"\xa5"*16 and after[2]==plan["expected_work"]+b"\x5a"*16,"exact deterministic checkpoint replay")
            stream.write(b"HNFCEND1"+struct.pack("<Q",len(rows)));done=True
        finally:(output/"CALLS.json").write_bytes(encoded(rows))
    require(done and source()==identity and rc.source()==control_identity,"complete same-source direct controls")
    report=dict(schema="hepta.namespace-fingerprint.hia-controls.v1",status="PASS",source_manifest_sha256=identity,control_source_sha256=control_identity,checkpoints=len(selected),actual_calls=len(rows),
        refusals=sum(r["expected"] in (INVALID,CAPACITY) for r in rows),replays=sum(r["expected"] not in (INVALID,CAPACITY) for r in rows),
        pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),source_root=str(ROOT),build_root=str(build),output_root=str(output),observed_root=str(observed),
        module_manifest=pin(read(manifest)),calls=pin(read(output/"CALLS.json")),buffers=pin(read(output/"buffers.bin.gz")),actual_filesystem_operations=0,original_rust_replay=0)
    (output/"CONTROLS.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")

def verify(folder,observed,manifest):
    import gzip
    report=loads(read(folder/"CONTROLS.json"));selected=checkpoints(observed);wanted=plans(selected);rows=loads(read(folder/"CALLS.json"))
    require(report["schema"]=="hepta.namespace-fingerprint.hia-controls.v1" and report["status"]=="PASS" and report["source_manifest_sha256"]==source() and report["control_source_sha256"]==rc.source() and
        report["checkpoints"]==len(selected) and report["actual_calls"]==len(rows)==len(wanted) and report["module_manifest"]==pin(read(manifest)) and
        report["calls"]==pin(read(folder/"CALLS.json")) and report["buffers"]==pin(read(folder/"buffers.bin.gz")) and
        report["actual_filesystem_operations"]==report["original_rust_replay"]==0,"complete direct ABI control inventory")
    total=0
    with (folder/"buffers.bin.gz").open("rb") as raw,gzip.GzipFile(fileobj=raw,mode="rb") as stream:
        def take(n):
            nonlocal total
            result=stream.read(n);require(len(result)==n,"complete direct control buffer");total+=n;return result
        require(take(8)==b"HNFCT001","complete direct control header")
        for index,plan in enumerate(wanted):
            require(take(8)==b"HNFCALL1","complete direct control marker");i,ret,ni,no,nw,nm=struct.unpack("<6Q",take(48))
            require((i,ret,ni,no,nw)==(index,plan["expected"],len(plan["request"]),plan["output_capacity"],len(plan["work"])) and 0<nm<65536,"exact source-owned direct control")
            row=loads(take(nm));before=[take(n+16) for n in (ni,no,nw)];after=[take(n+16) for n in (ni,no,nw)]
            require(row==rows[index] and row==dict(index=index,name=plan["name"],origin=plan["origin"],returned=ret,expected=plan["expected"],
                input_bytes=ni,output_capacity=no,workspace_capacity=nw,elapsed_ns=row["elapsed_ns"],before=[pin(x) for x in before],after=[pin(x) for x in after]) and
                type(row["elapsed_ns"]) is int and row["elapsed_ns"]>=0,"every actual direct control record")
            require(before==[plan["request"]+b"\xc3"*16,b"\xa5"*(no+16),plan["work"]+b"\x5a"*16],"complete source-bound preimages")
            if ret in (INVALID,CAPACITY):require(after==before,"whole actual refusal buffers unchanged")
            else:require(after==[before[0],plan["expected_output"]+b"\xa5"*16,plan["expected_work"]+b"\x5a"*16],"whole exact successful repeat/recovery buffers")
        require(take(8)==b"HNFCEND1" and struct.unpack("<Q",take(8))[0]==len(wanted) and not stream.read(1),"complete direct control footer")
    refusals=sum(r["expected"] in (INVALID,CAPACITY) for r in wanted)
    require(report["refusals"]==refusals and report["replays"]==len(wanted)-refusals,"all direct control domains")
    return dict(status="COMPLETE_DIRECT_FINGERPRINT_CONTROLS_PASS",checkpoints=len(selected),actual_calls=len(wanted),refusals=refusals,replays=len(wanted)-refusals,
                complete_buffer_bytes=total,native_or_rust_executions=0,reader_writes=0)

if __name__=="__main__":
    import argparse,sys
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",type=Path,required=True);p.add_argument("--observed",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.observed.resolve(strict=True),a.output.absolute())
