"""Full old captured buffers against only the new fixed-eight HIA image.

No original image, Rust, Watcher syscall boundary or application is executed.
The four post-HIA observer bookkeeping words are reconstructed from the exact
unchanged native adapter. All other context bytes and live pin pages are exact.
"""
import argparse,gzip,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import encoded,loads,pin,read,require,source
GROUPS=("ordinary","lru","wide-128","wide-258")
KEYS={"index","kind","offset","case","step","operation","meta","buffers"}
word=lambda b,n:struct.unpack_from("<Q",b,n)[0]

def take(s,n):
    raw=s.read(n);require(len(raw)==n,"whole retained frame");return raw

def frames(path):
    with gzip.open(path,"rb")as s:
        require(take(s,8)==b"HNWLOG01","complete stream magic")
        offset=8;index=0
        while True:
            head=take(s,8)
            if head==b"HNWEND01":
                require(word(take(s,8),0)==index and s.read(1)==b"","complete footer and gzip EOF")
                return
            size=word(head,0);require(0<size<=16*1024*1024,"bounded complete header")
            raw=take(s,size);row=loads(raw)
            require(set(row)==KEYS and type(row["index"])is int and type(row["offset"])is int and row["index"]==index and row["offset"]==offset
                and raw==encoded(row) and type(row["buffers"])is list and len(row["buffers"])<=1024,
                "entire ordered canonical frame metadata")
            buffers=[]
            for r in row["buffers"]:
                require(set(r)=={"bytes","sha256"} and type(r["bytes"])is int and 0<=r["bytes"]<=2*1024*1024,
                    "whole bounded physical buffer")
                b=take(s,r["bytes"]);require(pin(b)==r,"full captured buffer hash");buffers.append(b)
            yield row,tuple(buffers)
            offset+=8+size+sum(map(len,buffers));index+=1

def old_calls(prior,group,counts):
    for role in ("native-observed","native-off"):
        root=prior/"run"/("paired-"+group)/"roles"/role/"capture"
        report=loads(read(root/"NATIVE.json"));indices=[];pending=None;calls=0;byte_count=0
        require(report["status"]=="PASS" and report["role"]==role and report["group"]==group
            and report["errors"]==[] and loads(read(root/"OBSERVER-ERRORS.json"))==[],
            "each actual prior native stream completed")
        for row,raws in frames(root/"complete-native-buffers.bin.gz"):
            indices.append(row);byte_count+=sum(map(len,raws))
            if pending is not None:
                before_row,before=pending;pending=None
                require(row["kind"]=="observation" and raws and len(raws[0])==131072,"immediate complete owner after")
                event=raws[0][24960:25088];old_event=before[0][24960:25088]
                require(event[:8]==b"HNWOWN01" and word(event,8)==1 and row["meta"]["event"]==event.hex(),
                    "actual owner after event")
                require(all(row[k]==before_row[k] for k in ("case","step","operation"))
                    and row["meta"]["context"]==before_row["meta"]["context"]
                    and row["meta"]["pins"]==before_row["meta"]["pins"] and raws[1:]==before[1:],
                    "same actual owner turn and every entire pin page unchanged")
                expected_event=bytearray(old_event)
                struct.pack_into("<Q",expected_event,8,1);struct.pack_into("<Q",expected_event,16,word(event,16))
                require(bytes(expected_event)==event,"all observation fields except actual after phase/return unchanged")
                require(word(raws[0],64)==(word(before[0],64)+1)&((1<<64)-1)
                    and word(raws[0],120)==word(event,16) and word(event,16)<=0xffffffff,
                    "exact native u32-return and owner-call counter bookkeeping")
                expected=bytearray(before[0])
                expected[24704:24832]=raws[0][24704:24832]
                expected[32768:98304]=raws[0][32768:98304]
                stripped=bytearray(raws[0])
                for at in (64,120,24968,24976):stripped[at:at+8]=before[0][at:at+8]
                require(expected==stripped,"no change outside complete HIA output/workspace and four exact observer words")
                calls+=1
                yield dict(role=role,before_index=before_row["index"],after_index=row["index"],
                    kind="observed-owner",case=row["case"],step=row["step"],operation=row["operation"],
                    original_before=pin(encoded(before_row)),original_after=pin(encoded(row)),
                    input_length=word(old_event,56),returned=word(event,16)),(before[0]+b"\x5a"*16,),(bytes(expected)+b"\x5a"*16,)
                continue
            if row["kind"]=="observation":
                require(raws and len(raws[0])==131072,"entire actual native context")
                event=raws[0][24960:25088]
                require(row["meta"]["event"]==event.hex() and event[:8]in(b"HNWOWN01",b"HNWBN001")
                    and word(event,8)in(0,1),"actual native event envelope")
                if event[:8]==b"HNWOWN01":
                    require(word(event,8)==0,"owner after cannot occur without its before")
                    ptr=row["meta"]["context"]
                    require(type(ptr)is int and ptr>0 and word(event,48)==ptr+8192
                        and 96<=word(event,56)<=16480 and word(event,56)==word(raws[0],112)
                        and word(event,64)==ptr+24704 and word(event,72)==128
                        and word(event,80)==ptr+32768 and word(event,88)==65536,
                        "exact actual HIA input/output/workspace extents")
                    pending=(row,raws)
            elif row["kind"]=="private-owner":
                require(len(raws)==6 and len(raws[0])>=112 and len(raws[1])==144
                    and len(raws[2])==65552 and tuple(map(len,raws[:3]))==tuple(map(len,raws[3:])),
                    "complete private owner before/after buffers")
                calls+=1
                yield dict(role=role,before_index=row["index"],after_index=row["index"],
                    kind="private-owner",case=row["case"],step=row["step"],operation=row["operation"],
                    original_before=pin(encoded(row)),original_after=pin(encoded(row)),
                    input_length=len(raws[0])-16,returned=row["meta"]["returned"]),raws[:3],raws[3:]
        require(pending is None and indices==loads(read(root/"RECORDS.json")) and report["records"]==len(indices),
            "all original ordered indices and complete footer")
        require(calls==report["actual_hia_calls"]+report["private_owner_calls"],"all actual original HIA calls retained")
        counts.append(dict(role=role,records=len(indices),complete_buffer_bytes=byte_count,
            original_hia_calls=calls,stream=pin(read(root/"complete-native-buffers.bin.gz"))))

class Writer:
    def __init__(self,path):
        self.raw=path.open("xb");self.s=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0)
        self.s.write(b"HNWLOG01");self.rows=[];self.offset=8
    def add(self,meta,before,after,returned):
        buffers=tuple(before)+tuple(after)
        row=dict(index=len(self.rows),kind="new-owner-comparison",offset=self.offset,
            case=meta["case"],step=meta["step"],operation=meta["operation"],
            meta=dict(meta,new_returned=returned,before_buffers=len(before)),buffers=[pin(b)for b in buffers])
        header=encoded(row);body=struct.pack("<Q",len(header))+header+b"".join(buffers)
        self.s.write(body);self.offset+=len(body);self.rows.append(row)
    def close(self,success):
        try:
            if success:self.s.write(b"HNWEND01"+struct.pack("<Q",len(self.rows)))
            self.s.close()
        finally:self.raw.close()

def image(build):
    fixed=loads(read(ROOT/"NEW-BUILD-PINS.json"))
    p=build/"modules/namespace-watcher"
    manifest=read(p/"manifest.json");m=loads(manifest)
    require(pin(read(p/"module.image.bin"))==fixed["expected_owner"]
        and m["image_sha256"]==fixed["expected_owner"]["sha256"]
        and m["source_sha256"]==fixed["expected_owner_source"]["sha256"],"exact actual new fixed-eight image")
    return p/"manifest.json",pin(manifest)

def run(prior,build,output,group):
    import ctypes as C
    from hia_native import NativeModule
    require(group in GROUPS,"frozen complete prior stream group")
    identity=source();start=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    manifest,manifest_pin=image(build);counts=[];writer=Writer(output/"complete-new-buffers.bin.gz");passed=False
    try:
        with NativeModule(manifest,manifest_sha256=manifest_pin["sha256"])as owner:
            for meta,before,expected in old_calls(prior,group,counts):
                buffers=[C.create_string_buffer(b,len(b))for b in before]
                copied=tuple(b.raw for b in buffers);require(copied==before,"complete actual copied input buffers")
                if meta["kind"]=="observed-owner":
                    base=C.addressof(buffers[0])
                    returned=int(owner._entry(base+8192,meta["input_length"],base+24704,128,base+32768,65536))
                else:
                    returned=int(owner._entry(C.addressof(buffers[0]),meta["input_length"],
                        C.addressof(buffers[1]),128,C.addressof(buffers[2]),65536))
                after=tuple(b.raw for b in buffers)
                writer.add(meta,copied,after,returned)
                require(returned==meta["returned"] and after==expected,"all new HIA return and complete before/after bytes equal old capture")
        passed=True
    finally:
        try:writer.close(passed)
        finally:
            (output/"RECORDS.json").write_bytes(encoded(writer.rows))
            (output/"RESULT.json").write_bytes(encoded(dict(status="PASS"if passed else"FAIL",
                group=group,pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),source_manifest_sha256=identity,image=loads(read(ROOT/"NEW-BUILD-PINS.json"))["expected_owner"],
                module_manifest=manifest_pin,calls=len(writer.rows),prior_streams=counts,
                elapsed_seconds=time.monotonic()-start,timeout_seconds=60,
                old_native_applications=0,rust_executions=0,new_hia_calls=len(writer.rows),
                watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False)))
    require(source()==identity,"full comparison source unchanged")
    print(encoded(loads(read(output/"RESULT.json"))).decode(),end="")

def verify(prior,build,output,group):
    identity=source();manifest,manifest_pin=image(build)
    report=loads(read(output/"RESULT.json"))
    require(set(report)=={"status","group","pid","parent_pid","pgid","source_manifest_sha256","image","module_manifest","calls","prior_streams","elapsed_seconds",
        "timeout_seconds","old_native_applications","rust_executions","new_hia_calls","watcher_qualified","namespace_version_qualified","public_handler_qualified"}
        and type(report["elapsed_seconds"])is float and all(type(report[k])is int for k in("calls","timeout_seconds","old_native_applications","rust_executions","new_hia_calls","pid","parent_pid","pgid"))
        and all(report[k]is False for k in("watcher_qualified","namespace_version_qualified","public_handler_qualified")),"complete exact result fields/types/scope")
    require(report["status"]=="PASS" and report["group"]==group and report["source_manifest_sha256"]==identity
        and report["image"]==loads(read(ROOT/"NEW-BUILD-PINS.json"))["expected_owner"]
        and report["module_manifest"]==manifest_pin and report["timeout_seconds"]==60
        and 0<=report["elapsed_seconds"]<=60 and report["old_native_applications"]==report["rust_executions"]==0,
        "complete actual source/image/deadline record")
    counts=[];new=frames(output/"complete-new-buffers.bin.gz");actual=[];sentinel=object();total=0
    for meta,before,expected in old_calls(prior,group,counts):
        item=next(new,sentinel);require(item is not sentinel,"no omitted captured call")
        row,raws=item;n=len(before)
        require(row["kind"]=="new-owner-comparison" and all(type(row[k])is type(meta[k])and row[k]==meta[k]for k in("case","step","operation"))
            and encoded(row["meta"])==encoded(dict(meta,new_returned=meta["returned"],before_buffers=n))
            and raws==tuple(before)+tuple(expected),"complete new actual buffers and return against all old bytes")
        actual.append(row);total+=sum(map(len,raws))
    require(next(new,sentinel)is sentinel and actual==loads(read(output/"RECORDS.json"))
        and report["calls"]==report["new_hia_calls"]==len(actual)
        and encoded(report["prior_streams"])==encoded(counts),"all actual complete calls, indices, old streams and gzip footer")
    require(source()==identity,"complete reader source unchanged")
    return dict(status="FULL_CAPTURED_FIXED_EIGHT_COMPARISON_READ_PASS",group=group,calls=len(actual),
        new_complete_buffer_bytes=total,old_records=sum(r["records"]for r in counts),
        old_complete_buffer_bytes=sum(r["complete_buffer_bytes"]for r in counts),
        reader_native_executions=0,reader_rust_executions=0)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",choices=("run","verify"),required=True)
    for name in("prior","build","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",choices=GROUPS,required=True);a=p.parse_args()
    if a.phase=="run":run(a.prior.resolve(strict=True),a.build.resolve(strict=True),a.output.absolute(),a.group)
    else:print(encoded(verify(a.prior.resolve(strict=True),a.build.resolve(strict=True),a.output.resolve(strict=True),a.group)).decode(),end="")
