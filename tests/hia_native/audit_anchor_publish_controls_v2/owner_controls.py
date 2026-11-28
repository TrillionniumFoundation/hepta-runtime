"""New direct owner ABI controls; complete physical checkpoints from the frozen producer."""
from pathlib import Path
import struct,sys
CONTROL_ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
import control_common as rc
from common import ROOT,encoded,loads,pin,read,require,source
from protocol import INVALID,CAPACITY,word,put,domain
def checkpoints(capture):
    import gzip
    selected=[];seen=set();domains=[]
    for group in domain(ROOT)["groups"]:
        folder=capture/("native-observed-"+group)
        rows=loads(read(folder/"INVOCATIONS.json"));index=0
        with (folder/"buffers.bin.gz").open("rb") as raw,gzip.GzipFile(fileobj=raw,mode="rb") as stream:
            def take(n):
                value=stream.read(n);require(len(value)==n,"entire actual checkpoint extent");return value
            require(take(8)==b"AIOLOG01","whole actual checkpoint journal")
            for row in rows:
                require(take(8)==b"AIOCAL01","actual checkpoint marker");v=struct.unpack("<9Q",take(72))
                require(v[0]==index,"ordered actual checkpoint");index+=1
                ni,no,nw=v[5:8];before=[take(n+16) for n in (ni,no,nw)];after=[take(n+16) for n in (ni,no,nw)]
                require(row["before"]==[pin(x) for x in before] and row["after"]==[pin(x) for x in after] and
                        row["module"]==v[3] and row["result"]==v[4] and row["input_bytes"]==ni and
                        row["output_capacity"]==no and row["workspace_capacity"]==nw,
                        "all complete actual checkpoint buffers and inventory")
                if v[3]!=0:continue
                request=before[0][:ni];work=before[2][:nw];ack=request[:8]==b"HAPUACK1"
                key=(request[:8],word(work,8),word(work,40),word(work,48),word(work,64),word(work,72),
                     word(request,40) if ack else 0,word(request,48) if ack else 0)
                if key in seen:continue
                seen.add(key)
                require(no==8192 and nw==32768 and request[:8] in (b"HAPURQ01",b"HAPUACK1"),"fixed actual owner checkpoint")
                selected.append(dict(origin=group+"/"+str(row["index"]),case=row["case"],step=row["step"],request=request,work=work,
                                     returned=v[4],output=after[1][:no],after_work=after[2][:nw]))
            require(take(8)==b"AIOEND01" and struct.unpack("<Q",take(8))[0]==len(rows) and not stream.read(1),"complete source checkpoint footer")
        domains.append(group)
    phases={word(r["work"],48) for r in selected if r["request"][:8]==b"HAPUACK1"}
    require(phases=={11,21,31,41,51,61,71,101,111,121,131,141,151,161,201,901,911},
            "all actual entropy/publication/cleanup continuation phases")
    require(len(domains)==9 and selected,"all unchanged original environment groups")
    return selected
def plans(saved):
    result=[]
    def add(cp,name,request=None,work=None,no=8192,expected=INVALID):
        result.append(dict(name=cp["origin"]+"/"+name,origin=cp["origin"],request=cp["request"] if request is None else request,
            work=cp["work"] if work is None else work,output_capacity=no,expected=expected,
            expected_output=cp["output"] if expected==cp["returned"] else None,
            expected_work=cp["after_work"] if expected==cp["returned"] else None))
    def changed(raw,at,value):
        other=bytearray(raw);put(other,at,value);return bytes(other)
    for cp in saved:
        request=cp["request"];work=cp["work"];ack=request[:8]==b"HAPUACK1"
        add(cp,"exact-replay",expected=cp["returned"])
        for at in range(8):
            other=bytearray(request);other[at]^=0x40;add(cp,"magic-%d"%at,request=bytes(other))
        for n in dict.fromkeys((0,1,7,8,127,len(request)-1)):
            add(cp,"truncate-%d"%n,request=request[:n])
        add(cp,"extra",request=request+b"\0")
        for no in (0,127,8191):add(cp,"output-%d"%no,no=no,expected=CAPACITY)
        add(cp,"workspace-16383",work=work[:16383],expected=CAPACITY)
        if ack:
            for at,value in ((8,word(request,8)+1),(16,word(request,16)+1),(24,9),(32,99),(40,2),(48,4096),
                             (64,(1<<64)-1),(72,(1<<64)-1)):
                add(cp,"ack-header-%d"%at,request=changed(request,at,value))
            for at in range(80,128,8):add(cp,"ack-reserved-%d"%at,request=changed(request,at,1))
            for at,value in ((0,0),(8,2),(16,0),(24,0),(32,0),(40,3),(48,999),(56,0),(64,9),(72,99),
                             (120,word(work,24)),(128,4097),(136,4097),(144,word(work,24)),(152,33),(192,word(work,24)),
                             (256,0),(264,0),(272,0),(280,0)):
                add(cp,"pending-work-%d"%at,work=changed(work,at,value))
            for at in (80,88,96):add(cp,"pending-arg-%d"%at,work=changed(work,at,word(work,at)^1))
            for at in range(320,384,8):add(cp,"pending-reserved-%d"%at,work=changed(work,at,1))
            add(cp,"pending-sequence-overflow",work=changed(work,56,(1<<64)-2))
            if word(request,40)==1:
                add(cp,"failure-no-errno",request=changed(request,48,0))
                add(cp,"failure-value",request=changed(request,56,1))
            else:
                op=word(request,32)
                if op in (1,18):bad=word(work,24)
                elif op in (4,17,5):bad=4097
                elif op==19:bad=0
                else:bad=1
                add(cp,"success-invalid-value",request=changed(request,56,bad))
        else:
            for at,value in ((8,0),(8,2),(16,0),(24,0)):
                add(cp,"initial-%d-%d"%(at,value),request=changed(request,at,value))
            for at in range(64,128,8):add(cp,"initial-reserved-%d"%at,request=changed(request,at,1))
            if word(work,0)==int.from_bytes(b"HAPUWS01","little"):
                for at,value in ((8,1),(16,0),(24,0),(32,0),(40,3),(48,1),(64,1),(72,1),
                                 (80,1),(88,1),(96,1),(120,word(work,24)),(128,4097),(136,4097),
                                 (144,word(work,24)),(152,33),(192,word(work,24))):
                    add(cp,"stable-work-%d"%at,work=changed(work,at,value))
                add(cp,"generation-reused",request=changed(request,16,word(work,16)))
                add(cp,"root-changed",request=changed(request,24,word(work,24)+1))
        add(cp,"same-checkpoint-recovery",expected=cp["returned"])
    require(len({r["name"] for r in result})==len(result),"unique complete source-owned ABI control cases")
    return result

def run(build,observed,output):
    import ctypes as C,gzip,os,sys,time
    sys.path.insert(0,str(ROOT/"scripts"))
    from hia_native import NativeModule
    identity=source();control_identity=rc.source();output.mkdir(parents=True,exist_ok=False);selected=checkpoints(observed);wanted=plans(selected);rows=[];done=False
    manifest=build/"modules/audit-anchor-publish/manifest.json"
    with NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"]) as machine,(output/"buffers.bin.gz").open("xb") as raw,gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw,mtime=0) as stream:
        stream.write(b"HAPCT001")
        try:
            for index,plan in enumerate(wanted):
                request,work,no=plan["request"],plan["work"],plan["output_capacity"]
                buffers=[C.create_string_buffer(v,len(v)) for v in (request+b"\xc3"*16,b"\xa5"*(no+16),work+b"\x5a"*16)]
                before=[x.raw for x in buffers];start=time.monotonic_ns()
                returned=int(machine._entry(C.addressof(buffers[0]),len(request),C.addressof(buffers[1]),no,C.addressof(buffers[2]),len(work)))
                elapsed=time.monotonic_ns()-start;after=[x.raw for x in buffers]
                row=dict(index=index,name=plan["name"],origin=plan["origin"],returned=returned,expected=plan["expected"],input_bytes=len(request),
                         output_capacity=no,workspace_capacity=len(work),elapsed_ns=elapsed,before=[pin(x) for x in before],after=[pin(x) for x in after])
                meta=encoded(row);stream.write(b"HAPCALL1"+struct.pack("<6Q",index,returned,len(request),no,len(work),len(meta))+meta)
                for body in before+after:stream.write(body)
                rows.append(row)
                require(returned==plan["expected"] and after[0]==before[0] and after[1][no:]==b"\xa5"*16 and after[2][len(work):]==b"\x5a"*16,"actual direct owner result/guards: "+plan["name"])
                if returned in (INVALID,CAPACITY):require(after[1:]==before[1:],"whole refusal atomicity: "+plan["name"])
                else:require(after[1]==plan["expected_output"]+b"\xa5"*16 and after[2]==plan["expected_work"]+b"\x5a"*16,"exact deterministic checkpoint replay")
            stream.write(b"HAPCEND1"+struct.pack("<Q",len(rows)));done=True
        finally:(output/"CALLS.json").write_bytes(encoded(rows))
    require(done and source()==identity and rc.source()==control_identity,"complete same-source direct controls")
    report=dict(schema="hepta.audit-anchor-publish.hia-controls.v1",status="PASS",source_manifest_sha256=identity,control_source_sha256=control_identity,checkpoints=len(selected),actual_calls=len(rows),
        refusals=sum(r["expected"] in (INVALID,CAPACITY) for r in rows),replays=sum(r["expected"] not in (INVALID,CAPACITY) for r in rows),
        pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),source_root=str(ROOT),build_root=str(build),output_root=str(output),observed_root=str(observed),
        module_manifest=pin(read(manifest)),calls=pin(read(output/"CALLS.json")),buffers=pin(read(output/"buffers.bin.gz")),actual_filesystem_operations=0,original_rust_replay=0)
    (output/"CONTROLS.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")

def verify(folder,observed,manifest):
    import gzip
    report=loads(read(folder/"CONTROLS.json"));selected=checkpoints(observed);wanted=plans(selected);rows=loads(read(folder/"CALLS.json"))
    require(report["schema"]=="hepta.audit-anchor-publish.hia-controls.v1" and report["status"]=="PASS" and report["source_manifest_sha256"]==source() and report["control_source_sha256"]==rc.source() and
        report["checkpoints"]==len(selected) and report["actual_calls"]==len(rows)==len(wanted) and report["module_manifest"]==pin(read(manifest)) and
        report["calls"]==pin(read(folder/"CALLS.json")) and report["buffers"]==pin(read(folder/"buffers.bin.gz")) and
        report["actual_filesystem_operations"]==report["original_rust_replay"]==0,"complete direct ABI control inventory")
    total=0
    with (folder/"buffers.bin.gz").open("rb") as raw,gzip.GzipFile(fileobj=raw,mode="rb") as stream:
        def take(n):
            nonlocal total
            result=stream.read(n);require(len(result)==n,"complete direct control buffer");total+=n;return result
        require(take(8)==b"HAPCT001","complete direct control header")
        for index,plan in enumerate(wanted):
            require(take(8)==b"HAPCALL1","complete direct control marker");i,ret,ni,no,nw,nm=struct.unpack("<6Q",take(48))
            require((i,ret,ni,no,nw)==(index,plan["expected"],len(plan["request"]),plan["output_capacity"],len(plan["work"])) and 0<nm<65536,"exact source-owned direct control")
            row=loads(take(nm));before=[take(n+16) for n in (ni,no,nw)];after=[take(n+16) for n in (ni,no,nw)]
            require(row==rows[index] and row==dict(index=index,name=plan["name"],origin=plan["origin"],returned=ret,expected=plan["expected"],
                input_bytes=ni,output_capacity=no,workspace_capacity=nw,elapsed_ns=row["elapsed_ns"],before=[pin(x) for x in before],after=[pin(x) for x in after]) and
                type(row["elapsed_ns"]) is int and row["elapsed_ns"]>=0,"every actual direct control record")
            require(before==[plan["request"]+b"\xc3"*16,b"\xa5"*(no+16),plan["work"]+b"\x5a"*16],"complete source-bound preimages")
            if ret in (INVALID,CAPACITY):require(after==before,"whole actual refusal buffers unchanged")
            else:require(after==[before[0],plan["expected_output"]+b"\xa5"*16,plan["expected_work"]+b"\x5a"*16],"whole exact successful repeat/recovery buffers")
        require(take(8)==b"HAPCEND1" and struct.unpack("<Q",take(8))[0]==len(wanted) and not stream.read(1),"complete direct control footer")
    refusals=sum(r["expected"] in (INVALID,CAPACITY) for r in wanted)
    require(report["refusals"]==refusals and report["replays"]==len(wanted)-refusals,"all direct control domains")
    return dict(status="COMPLETE_DIRECT_PUBLISHER_CONTROLS_PASS",checkpoints=len(selected),actual_calls=len(wanted),refusals=refusals,replays=len(wanted)-refusals,
                complete_buffer_bytes=total,native_or_rust_executions=0,reader_writes=0)

if __name__=="__main__":
    import argparse,sys
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",type=Path,required=True);p.add_argument("--observed",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.observed.resolve(strict=True),a.output.absolute())
