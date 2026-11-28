"""Read all engineering buffers and real libc bindings without native execution."""
import argparse,gzip,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from read_libc import verify as libc
from read_callable_prepare import verify as build_read
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def take(stream,size):
    out=bytearray()
    while len(out)<size:
        part=stream.read(size-len(out));require(part,"complete physical stream extent");out+=part
    return bytes(out)
def verify(build,authored,output):
    identity=source();admission=build_read(build,authored)
    require(loads(read(output/"ADMISSION.json"))==admission,"same actual admitted build")
    library=libc(output)
    report=loads(read(output/"PROBE.json"));rows=loads(read(output/"RECORDS.json"))
    require(report["status"]=="PASS" and report["source_manifest_sha256"]==identity
        and report["build"]==admission and report["errors"]==[]==loads(read(output/"OBSERVER-ERRORS.json"))
        and report["cases"]==["ordinary","content","lru","zero-limit","shared-caller-release",
            "non-directory","two-watchers","drop-reinit"],"all exact actual engineering cases")
    require(report["original_rust_executions"]==0 and report["original_comparison_qualified"] is False
        and report["namespace_version_qualified"] is False and report["public_handler_qualified"] is False,
        "engineering scope not original/private semantic qualification")
    counts=dict(entries=0,hia=0,boundaries=0);pending=None;offset=8;total=0
    with (output/"complete-native-buffers.bin.gz").open("rb") as physical:
        with gzip.GzipFile(fileobj=physical,mode="rb") as stream:
            require(take(stream,8)==b"HNWLOG01","complete native stream header")
            for index,row in enumerate(rows):
                require(row["index"]==index and row["offset"]==offset,"complete physical stream index")
                size=struct.unpack("<Q",take(stream,8))[0];require(size<=1<<20,"bounded complete physical record")
                header=take(stream,size);require(loads(header)==row and header==encoded(row),"actual physical record equals full retained index")
                offset+=8+size;raws=[]
                for item in row["buffers"]:
                    require(set(item)=={"bytes","sha256"} and type(item["bytes"])is int and item["bytes"]<=1<<20,"exact physical buffer descriptor")
                    raw=take(stream,item["bytes"]);require(pin(raw)==item,"whole physical buffer bytes")
                    raws.append(raw);offset+=len(raw);total+=len(raw)
                kind=row["kind"]
                if kind=="observation":
                    require(raws and len(raws[0])==131072,"entire actual native context")
                    ctx=raws[0];event=ctx[24960:25088];meta=row["meta"]
                    require(event.hex()==meta["event"] and len(raws)==1+len(meta["pins"]),"all actual observation buffers")
                    magic=event[:8];phase=word(event,8);require(magic in(b"HNWOWN01",b"HNWBN001")and phase in(0,1),"no poisoned transport accepted")
                    for ptr,page in zip(meta["pins"],raws[1:]):
                        require(ptr>0 and ptr%4096==0 and len(page)==4096 and page[:8]==b"HNWFP001"
                            and word(page,8)>0 and word(page,24)==4096,"complete actual live pin page")
                    if phase==0:
                        require(pending is None,"one actual before/after borrow")
                        pending=(magic,event,ctx)
                    else:
                        require(pending is not None and pending[0]==magic,"same actual before/after boundary")
                        old_event,old=pending[1:];pending=None
                        require(old_event[24:48]==event[24:48],"generation, command and effect unchanged")
                        if magic==b"HNWOWN01":
                            ni=word(old_event,56);base=meta["context"]
                            require(word(old_event,48)==base+8192 and 96<=ni<=16480
                                and word(old_event,64)==base+24704 and word(old_event,72)==128
                                and word(old_event,80)==base+32768 and word(old_event,88)==65536,"actual fixed HIA borrowed extents")
                            require(old[8192:8192+ni+16]==ctx[8192:8192+ni+16]
                                and ctx[8192+ni:8192+ni+16]==b"\xc3"*16
                                and old[24832:24848]==ctx[24832:24848]==b"\xa5"*16
                                and old[98304:98320]==ctx[98304:98320]==b"\x5a"*16,
                                "entire immutable HIA input and actual guard bytes")
                            require(word(event,16)==word(ctx,120)==128 and word(ctx,64)==word(old,64)+1,
                                "actual HIA return and invocation count")
                            require(ctx[24704:24712]==b"HNWR0001","complete actual HIA response")
                            counts["hia"]+=1
                        else:
                            require(old_event[48:80]==event[48:80] and 1<=word(event,40)<=8,
                                "same exact requested native boundary")
                            require(word(ctx,128)==word(old,128)+1,"one actual native boundary count")
                            counts["boundaries"]+=1
                else:
                    require(pending is None,"outer record only after complete native borrow")
                    if kind=="entry":
                        require(len(raws)==6 and row["meta"]["returned"]==128,"complete actual native entry buffers")
                        before,after=raws[:3],raws[3:]
                        require(len(before[0])==112 and before[0]==after[0]
                            and len(before[1])==len(after[1])==144
                            and before[1]==b"\xa5"*144 and after[1][128:]==b"\xa5"*16
                            and len(before[2])==len(after[2])==131088
                            and after[2][131072:]==b"\x5a"*16,"every complete outer buffer and tail")
                        require(after[1][:8]==b"HNWR0001" and word(after[1],8)in(0,1)
                            and word(after[1],16)==row["meta"]["generation"]
                            and word(after[1],32)==row["meta"]["cmd"] and word(after[2],8)==0,"actual terminal result")
                        counts["entries"]+=1
                    else:
                        require(kind in("initialize","bind","pin-adopt","pin-release","dispose"),"fixed observed native exports")
            require(take(stream,16)==b"HNWEND01"+struct.pack("<Q",len(rows)) and stream.read()==b"","whole complete gzip stream/footer")
    require(pending is None and report["complete_record_count"]==len(rows)
        and report["native_entry_calls"]==counts["entries"] and report["actual_hia_owner_calls"]==counts["hia"]
        and report["actual_native_boundaries"]==counts["boundaries"],"all actual counts independently rebuilt")
    return dict(status="COMPLETE_NATIVE_ENGINEERING_READ_PASS",cases=8,physical_records=len(rows),
        complete_buffer_bytes=total,counts=counts,libc=library,source_manifest_sha256=identity,
        original_comparison_qualified=False,namespace_version_qualified=False,
        public_handler_qualified=False,reader_native_or_rust_executions=0)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True)
    p.add_argument("--authored",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();print(encoded(verify(a.build.resolve(strict=True),a.authored.resolve(strict=True),a.output.resolve(strict=True))).decode(),end="")
