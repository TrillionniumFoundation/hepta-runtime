"""Physical mutation refusals and independent complete-copy admissions over completed actual bytes."""
import argparse,copy,gzip,hashlib,json,os,shutil,struct,sys,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require,files
from versions_contract import q
from read_completed import verify
from read_only_guard import guarded
from export import directories
CONTROLS=(
("admit-a",None),
("image-byte","all original/native states join independently decoded complete native physical buffers"),
("parent-input-guard","entire parent input guard"),
("parent-output-tail","whole input immutability and output prefix/tail"),
("parent-work-guard","entire parent output/workspace guards"),
("pin-unused-tail","entire actual File page unused bytes"),
("child-work-guard","whole actual child workspace/output guards"),
("kernel-unused-tail","every kernel read leaves all unwritten physical tail bytes unchanged"),
("kernel-returned-byte","all actual native read arguments, real errno, count and kernel bytes match the complete live buffer"),
("admit-b",None))
def choose(folder,kind):
    rows=loads(read(folder/"RECORDS.json"))
    for r in rows:
        k=r["kind"];m=r["meta"];refs=r["buffers"]
        if kind=="image-byte"and k=="loaded-image":return r,0,64
        if kind=="parent-output-tail"and k=="entry":return r,5,128
        if kind=="pin-unused-tail"and k=="pin-adopt":return r,0,4095
        if k!="observation":continue
        e=bytes.fromhex(m["event"]);stage=q(e,8);phase=q(e,16)
        if kind=="parent-input-guard"and stage==1 and phase==0:return r,4,2144
        if kind=="parent-work-guard"and stage==1:return r,4,77824
        if kind=="child-work-guard"and stage==7 and phase==1:return r,1,98304
        if kind in("kernel-unused-tail","kernel-returned-byte")and stage==3 and phase==1:
            # Read the whole object below; the nested qualified record carries actual operation and return.
            digest=refs[1]["sha256"]
            raw=read_object(folder,digest);legacy=raw[24960:25088]
            if legacy[:8]!=b"HNWBN001"or q(legacy,40)!=2:continue
            returned=q(legacy,96)
            if kind=="kernel-unused-tail"and returned==(1<<64)-1:return r,1,114719
            if kind=="kernel-returned-byte"and 0<returned<=16384:return r,1,98336
    raise ValueError("whole physical control target absent: "+kind)
def read_object(folder,digest):
    index=loads(read(folder/"OBJECTS.json"));require(digest in index,"physical target exists")
    with gzip.open(folder/"complete-native-buffers.bin.gz","rb")as stream:
        stream.seek(index[digest]["offset"]);require(stream.read(8)==b"NVOBJ001","whole physical target object framing")
        length=struct.unpack("<Q",stream.read(8))[0];require(stream.read(32).hex()==digest,"actual physical target hash")
        raw=stream.read(length);require(pin(raw)=={k:index[digest][k]for k in("bytes","sha256")},"every selected physical target byte")
        return raw
def mutate(folder,kind):
    selected,buffer_index,at=choose(folder,kind);old=selected["buffers"][buffer_index]
    raw=read_object(folder,old["sha256"]);require(0<=at<len(raw),"actual whole-object mutation offset")
    changed=raw[:at]+bytes([raw[at]^1])+raw[at+1:];new=pin(changed);require(new["bytes"]==old["bytes"]and new["sha256"]!=old["sha256"],"one physical byte changes")
    original=folder/"complete-native-buffers.bin.gz";replacement=folder/"complete-native-buffers.rewritten.bin.gz"
    objects={};records=[];logical=0;position=8;references=0;old_pin=pin(read(original))
    with gzip.open(original,"rb")as inp,replacement.open("xb")as raw_out,gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=raw_out,mtime=0)as out:
        def take(n):
            data=inp.read(n);require(len(data)==n,"complete copied control input stream");return data
        require(take(8)==b"HNVLOG02","whole copied control stream header");out.write(b"HNVLOG02")
        while True:
            tag=take(8)
            if tag==b"NVOBJ001":
                length=struct.unpack("<Q",take(8))[0];digest=take(32).hex();body=take(length)
                require(pin(body)==dict(bytes=length,sha256=digest),"all copied control object bytes before rewrite")
                if digest==old["sha256"]:body=changed;digest=new["sha256"]
                require(digest not in objects,"unique complete rewritten physical object")
                objects[digest]=dict(bytes=length,sha256=digest,offset=position)
                wire=tag+struct.pack("<Q",length)+bytes.fromhex(digest)+body;out.write(wire);position+=len(wire)
            elif tag==b"NVREC001":
                length=struct.unpack("<Q",take(8))[0];r=loads(take(length));r["offset"]=position
                require(r["index"]==len(records),"whole actual record ordering preserved")
                for ref in r["buffers"]:
                    if ref["sha256"]==old["sha256"]:ref["sha256"]=new["sha256"];references+=1
                    logical+=ref["bytes"]
                body=encoded(r);wire=tag+struct.pack("<Q",len(body))+body
                out.write(wire);position+=len(wire);records.append(r)
            elif tag==b"NVEND001":
                footer=struct.unpack("<3Q",take(24));require(footer==(len(records),len(objects),logical)and not inp.read(1),"whole old physical stream footer and EOF")
                out.write(tag+struct.pack("<3Q",len(records),len(objects),logical));break
            else:raise ValueError("unexpected complete physical object tag")
    require(references>0,"every target physical alias updated")
    # The untouched original stream is retained alongside the mutated version, never silently erased.
    preserved=folder/"complete-native-buffers.before-control.bin.gz";original.rename(preserved);replacement.rename(original)
    (folder/"RECORDS.before-control.json").write_bytes(read(folder/"RECORDS.json"))
    (folder/"OBJECTS.before-control.json").write_bytes(read(folder/"OBJECTS.json"))
    (folder/"RECORDS.json").write_bytes(encoded(records));(folder/"OBJECTS.json").write_bytes(encoded(objects))
    if kind=="image-byte":
        report=loads(read(folder/"NATIVE.json"));(folder/"NATIVE.before-control.json").write_bytes(read(folder/"NATIVE.json"))
        report["callable"]=new;(folder/"NATIVE.json").write_bytes(encoded(report))
    return dict(kind=kind,record_index=selected["index"],buffer_index=buffer_index,byte_offset=at,
        old_object=old,new_object=new,old_byte=raw[at],new_byte=changed[at],all_aliases_rewritten=references,
        objects=len(objects),records=len(records),logical_bytes=logical,stream_before=old_pin,stream_after=pin(read(original)),
        whole_stream_metadata_rewritten=True,complete_pre_mutation_stream_retained=True)
def run(workspace):
    identity=source();dependency=loads(read(ROOT/"UPLOAD_DEPENDENCIES.json"))["groups"]["fd3-global-names-content"];baseline=workspace/"retained"
    before=files(baseline);before_dirs=directories(baseline);output=workspace/"run/controls";output.mkdir()
    results=[]
    for label,refusal in CONTROLS:
        start=time.monotonic();clone=output/label;shutil.copytree(baseline,clone,copy_function=shutil.copy2)
        require(files(clone)==before and directories(clone)==before_dirs,"every full physical copy byte, directory and mode")
        require(all((baseline/name).stat().st_ino!=(clone/name).stat().st_ino for name in before),"every whole physical clone owns distinct files")
        mutation=None if refusal is None else mutate(clone/"run/group/roles/native-observed/capture",label)
        def check():
            try:result=verify(clone,dependency["group"],dependency)
            except ValueError as error:return dict(accepted=False,exception=str(error))
            return dict(accepted=True,status=result["status"],source_operations=result["source_operations"],
                complete_native_records=sum(r["records"]for r in result["native"]),
                complete_native_logical_bytes=sum(r["logical_bytes"]for r in result["native"]))
        checked=guarded(check,roots=[ROOT,clone],foreign_path="/tmp/namespace-versions-controls-forbidden/CAPTURE.json")
        e=checked["evidence"]
        if refusal is None:require(e["accepted"]is True,"whole independent physical control admitted")
        else:require(e["accepted"]is False and refusal in e["exception"],"specific deep physical refusal beyond rewritten hashes: "+str(e))
        require(time.monotonic()-start<=180,"each whole physical control deadline")
        record=dict(label=label,expected_refusal=refusal,mutation=mutation,guarded=checked,elapsed_seconds=time.monotonic()-start,
            clone_files=len(before),clone_bytes=sum(r["bytes"]for r in before.values()),clone_directories=len(before_dirs),
            independent_complete_physical_files=True,original_applications=0,native_applications=0,application_replays=0,files_deleted=0)
        (output/(label+".json")).write_bytes(encoded(record));results.append(dict(label=label,accepted=e["accepted"],exception=e.get("exception"),
            guard_probes=len(checked["probes"]),elapsed_seconds=record["elapsed_seconds"],file=label+".json",**pin(read(output/(label+".json")))))
        print("NAMESPACE_PHYSICAL_CONTROL "+label+" PASS",flush=True)
    require(source()==identity and files(baseline)==before and directories(baseline)==before_dirs,"whole baseline and frozen control sources unchanged")
    report=dict(schema="hepta.namespace-versions.physical-control.v1",status="NAMESPACE_VERSIONS_PHYSICAL_CONTROLS_PASS",source_manifest_sha256=identity,
        actual_source_manifest_sha256=dependency["source_manifest_sha256"],controls=results,admissions=2,refusals=8,
        guard_probes=sum(r["guard_probes"]for r in results),all_control_clones_retained=True,files_deleted=0,
        original_applications=0,native_applications=0,application_replays=0,namespace_version_qualified=False)
    (workspace/"run/CONTROLS.json").write_bytes(encoded(report))
    uploaded=loads(read(workspace/"run/GATE.json"));require(uploaded["status"]=="NAMESPACE_VERSIONS_UPLOADED_GROUP_PASS","complete prior uploaded admission")
    combined=dict(schema="hepta.namespace-versions.uploaded-physical-controls-gate.v1",
        status="NAMESPACE_VERSIONS_UPLOADED_PHYSICAL_CONTROLS_PASS",source_manifest_sha256=identity,uploaded=uploaded,controls=report,
        application_replays=0,new_native_applications=0,new_original_applications=0)
    (workspace/"run/GATE.json").write_bytes(encoded(combined))
    print("NAMESPACE_PHYSICAL_CONTROLS_BEGIN");print(encoded(combined).decode(),end="");print("NAMESPACE_PHYSICAL_CONTROLS_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True))
