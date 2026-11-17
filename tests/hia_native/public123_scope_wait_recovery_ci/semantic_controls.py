"""Physical corruptions with honest outer receipts; no target execution."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,shutil,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
source=Path(os.environ["WAIT_SOURCE"]).resolve(strict=True)
sys.path[:0]=[str(HERE),str(source),str(source/"build_reader")]
import atomic_frames,read_capture_fixed as original_reader,read_lifetime as reader
import read_only_guard as guard
from capture_common import file_pin
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def doc(path):return json.loads(path.read_bytes())
def mutate_trace(path,sequence,event,span,offset,value):
    original=path.with_suffix(path.suffix+".before")
    path.rename(original)
    old_pin=file_pin(original);digest=hashlib.sha256();size=0;changed=0
    with gzip.open(original,"rb") as inp,path.open("xb") as target,gzip.GzipFile(filename="",fileobj=target,mode="wb",compresslevel=1,mtime=0) as out:
        def read(n):
            raw=inp.read(n);assert len(raw)==n;return raw
        def write(raw):
            nonlocal size
            out.write(raw);digest.update(raw);size+=len(raw)
        while True:
            magic=inp.read(8)
            if not magic:break
            assert len(magic)==8
            if magic==b"HPTREV01":
                header=magic+read(120);w=struct.unpack_from("<15Q",header,8)
                an,bn,cn=w[8:11];payload=read(an+bn+cn)
                if w[1]==sequence:
                    assert w[2]==event
                    start={"a":0,"b":an,"c":an+bn}[span];length={"a":an,"b":bn,"c":cn}[span]
                    assert 0<=offset<=length-8
                    before=payload[start+offset:start+offset+8];after=struct.pack("<Q",value);assert before!=after
                    payload=payload[:start+offset]+after+payload[start+offset+8:];changed+=1
                write(header);write(payload)
            elif magic==b"HXLTR001":
                header=magic+read(56);w=struct.unpack_from("<7Q",header,8);write(header);write(read(w[4]+w[5]))
            else:
                assert magic in atomic_frames.FIXED
                write(magic);write(read(atomic_frames.FIXED[magic]-8))
    assert changed==1
    return original,{"compressed":file_pin(path),"uncompressed":{"bytes":size,"sha256":digest.hexdigest()},"before":old_pin}
def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    capture=a.capture.resolve(strict=True);output=a.output.absolute();assert not output.exists();output.mkdir(parents=True)
    inputs=doc(capture/"INPUTS_READY.json")
    candidates=[]
    for i in range(4):
        rows=[doc(capture/side/("%03d"%i)/"CASE.json") for side in ("original","native")]
        metadata=[reader.structural_snapshots([x[1]["complete_metadata"] for x in reader.snapshots(row)]) for row in rows]
        if metadata[0]!=metadata[1]:candidates.append(i)
    assert len(candidates)==1
    case_number=candidates[0];case_dir="%03d"%case_number
    actual=atomic_frames.inspect(capture/"native"/case_dir/"process")
    finals=[f for f in actual["atomic_frames"] if f["context"]["stage"]==7];assert len(finals)==2
    final=finals[-1];context_sequence=final["context"]["trace_sequence"]
    cases=[
        ("rename-ack-not-consumed",final["trace_sequence"],11,"b",336,0,"actual consumed successful rename acknowledgment"),
        ("rename-returned-errno",final["trace_sequence"],11,"b",320,5,"actual consumed successful rename acknowledgment"),
        ("different-final-effect",final["trace_sequence"],11,"b",272,9,"actual last rename request"),
        ("temporary-fd-still-open",context_sequence,9,"c",2384,0,"both actual native temporary and read descriptors closed"),
        ("read-fd-still-owned",context_sequence,9,"c",2048+72,1,"both actual native temporary and read descriptors closed")]
    rows=[]
    for name,seq,event,span,offset,value,message in cases:
        working=output.parent/("semantic-control-"+name);assert not working.exists()
        shutil.copytree(capture,working,copy_function=os.link)
        evidence=output/name;evidence.mkdir()
        changed={}
        def replace(relative,raw):
            path=working/relative
            if relative not in changed:
                index=len(changed);before=evidence/("%03d-before.bin"%index);after=evidence/("%03d-after.bin"%index)
                before.write_bytes(path.read_bytes());changed[relative]={"before":before.name,"after":after.name,"mode":path.stat().st_mode&0o777}
            row=changed[relative];path.unlink();path.write_bytes(raw);os.chmod(path,row["mode"]);(evidence/row["after"]).write_bytes(raw)
        process_rel="native/"+case_dir+"/process/"
        process=doc(working/process_rel/"complete-process.json")
        item=process["fixed_capabilities"]["host-trace"]
        trace_rel=process_rel+Path(item["path"]).name
        trace=working/trace_rel
        # Remove only this hardlink before creating the controlled changed copy.
        mode=trace.stat().st_mode&0o777;old=trace.read_bytes();trace.unlink();trace.write_bytes(old);os.chmod(trace,mode)
        previous,pins=mutate_trace(trace,seq,event,span,offset,value)
        os.chmod(trace,mode)
        before=evidence/"trace-before.bin";after=evidence/"trace-after.bin"
        before.write_bytes(previous.read_bytes());after.write_bytes(trace.read_bytes());previous.unlink()
        changed[trace_rel]={"before":before.name,"after":after.name,"mode":mode}
        for name2 in ("process.json","complete-process.json"):
            relative=process_rel+name2;record=doc(working/relative)
            if "fixed_capabilities" in record:
                record["fixed_capabilities"]["host-trace"].update({k:pins[k] for k in ("compressed","uncompressed")})
                replace(relative,(json.dumps(record,sort_keys=True,indent=2)+"\n").encode())
        process=doc(working/process_rel/"complete-process.json")
        relative="native/"+case_dir+"/CASE.json";case=doc(working/relative);case["process"]=process
        replace(relative,(json.dumps(case,sort_keys=True,indent=2)+"\n").encode())
        report=doc(working/"native/CAPTURE.json");report["cases"][case_number]["case"]=file_pin(working/relative)
        replace("native/CAPTURE.json",(json.dumps(report,sort_keys=True,indent=2)+"\n").encode())
        def verify():
            pair=[reader.read_selected(working/side,side,{k:inputs[side][k] for k in ("bytes","sha256")},case_number) for side in ("original","native")]
            # The complete previous reader accepts every resealed physical
            # stream and state, then the added lifetime proof must reject.
            try:reader.compare(*pair)
            except ValueError as error:
                assert message in str(error),(message,str(error))
                return {"status":"RESEALED_LIFETIME_PRECONDITION_REJECTED","error":str(error),"changed_case_complete_readers_passed":True}
            raise AssertionError("proved-lifetime reader accepted corrupted physical state")
        proof=guard.guarded(verify,roots=[working,HERE,source],foreign_path=Path("/dev/null"))
        put(evidence/"READ.json",proof)
        for relative,row in changed.items():
            row["before_pin"]=file_pin(evidence/row["before"]);row["after_pin"]=file_pin(evidence/row["after"])
            assert row["before_pin"]==file_pin(capture/relative)
        put(evidence/"MUTATION.json",{"sequence":seq,"event":event,"span":span,"offset":offset,"value":value,"changed":changed,"outer_receipts_recomputed_from_actual_changed_bytes":True})
        files=0
        for path in sorted(working.rglob("*")):
            if not path.is_file():continue
            relative=path.relative_to(working).as_posix();other=evidence/changed[relative]["after"] if relative in changed else capture/relative
            assert path.read_bytes()==other.read_bytes()
            assert path.stat().st_mode&0o777==(changed[relative]["mode"] if relative in changed else other.stat().st_mode&0o777)
            files+=1
        put(evidence/"RETIREMENT.json",{"all_files":files,"complete_bytes_and_modes_compared":True})
        shutil.rmtree(working)
        rows.append({"name":name,"status":proof["evidence"]["status"],"guard_probes":len(proof["probes"]),"changed_files":len(changed),"complete_files":files})
    result={"status":"FIVE_RESEALED_PHYSICAL_LIFETIME_CONTROLS_PASS","cases":rows,"application_executions":0}
    put(output/"CONTROLS.json",result);print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
