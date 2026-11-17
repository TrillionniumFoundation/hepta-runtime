"""Private trace-only native diagnostic. Captured original semantics are never replayed."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,struct,sys,traceback
sys.dont_write_bytecode=True
p=argparse.ArgumentParser();p.add_argument("--capture-source",type=Path,required=True);p.add_argument("--fixture",type=Path,required=True);a=p.parse_args()
source=a.capture_source.resolve(strict=True);fixture=a.fixture.resolve(strict=True);out=fixture/"diagnostic"
assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists();out.mkdir()
sys.path[:0]=[str(source),str(source/"build_reader")]
import callable_common,read_capture,read_only_guard as guard
from run import invoke
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
assert hashlib.sha256((source/"SOURCE_MANIFEST.json").read_bytes()).hexdigest()=="12710deffd920a6c95f4b8c6a8d13172cc7f326a5fe90a56e8874ea4c6135529"
put(out/"SOURCE.json",callable_common.syntax(source));shutil.copytree(source,out/"recipe-source")
build=json.loads((fixture/"BUILD.json").read_bytes());assert build["status"]=="SHARED123_TEST_WAIT_FIXTURE_BUILD_PASS"
m=json.loads((fixture/"build/wait-control/manifest.json").read_bytes());binary=fixture/"build/wait-control"/m["elf"]
assert callable_common.pin(binary)==build["elf"]
status={"status":"RUNNING_DIAGNOSTIC","original_executions":0,"production_changed":False,"qualified":False,"native_cases_limit":4,"exchange_seconds":60,"lane_seconds":180}
put(out/"RUN.json",status)
try:
    invoke(out,"native",[sys.executable,"-I","-S","-B",str(source/"capture.py"),"--binary",str(binary),"--output",str(out/"native"),"--work","/tmp/hia-extract-contention-ordinary-a-legacy/work","--domain","ordinary-a-legacy","--side","native"],limit=180)
    status["status"]="NATIVE_DIAGNOSTIC_ALL_FOUR_CAPTURED"
except BaseException as error:
    status.update(status="NATIVE_DIAGNOSTIC_FAILURE_RETAINED",error=repr(error),traceback=traceback.format_exc())
finally:put(out/"RUN.json",status)
fixed={b"HRGTR002":224,b"HRCNAK02":128,b"HWDIOAK2":160,b"HFSPCL02":80,b"HFSPAK02":192,b"HVRDACK1":128,b"HFLKEYFX":128}
def trace(raw):
    at=0;events=[];counts={}
    while at<len(raw):
        magic=raw[at:at+8]
        if magic==b"HPTREV01":
            if len(raw)-at<128:break
            words=struct.unpack_from("<15Q",raw,at+8)
            size,seq,event,hgen,gen,node,engine,clock,an,bn,cn,phase,written,capacity,zero=words
            assert size==128+an+bn+cn and size<=len(raw)-at
            frame=raw[at:at+size];pa=frame[128:128+an];pb=frame[128+an:128+an+bn];pc=frame[128+an+bn:]
            e={"magic":"HPTREV01","offset":at,"header_words":list(words),"frame":read_capture.pin(frame)}
            for name,value in (("a",pa),("b",pb),("c",pc)):e[name+"_first_words"]=list(struct.unpack_from("<"+"Q"*min(len(value)//8,20),value))
            if event==9 and an>=1200:e["pending"]={str(o):struct.unpack_from("<Q",pa,o)[0] for o in (88,104,120,136,144,232,480,1152,1160,1168,1176)}
            key="task:"+str(event)
        elif magic==b"HXLTR001":
            assert len(raw)-at>=64
            words=struct.unpack_from("<7Q",raw,at+8);size=64+words[4]+words[5];assert size<=len(raw)-at
            e={"magic":"HXLTR001","offset":at,"words":list(words),"frame":read_capture.pin(raw[at:at+size])};key="fixed:"+str(words[6])
        else:
            if magic not in fixed:break
            size=fixed[magic];assert size<=len(raw)-at
            e={"magic":magic.decode(),"offset":at,"words":list(struct.unpack_from("<"+"Q"*((size-8)//8),raw,at+8)),"frame":read_capture.pin(raw[at:at+size])};key=magic.decode()
        events.append(e);counts[key]=counts.get(key,0)+1;at+=size
    return {"full_retained_bytes":read_capture.pin(raw),"parsed_bytes":at,"remaining_bytes":len(raw)-at,"remaining_prefix_hex":raw[at:at+128].hex(),"counts":counts,"all_events":events}
def inspect():
    results=[]
    for case in sorted((out/"native").iterdir()):
        if not case.is_dir():continue
        row=json.loads((case/"CASE.json").read_bytes());folder=case/"process"
        process=json.loads((folder/"complete-process.json").read_bytes())
        value={"case":case.name,"name":row["name"],"status":row["status"],"steps":[{"label":s["label"],"kind":s["kind"]} for s in row["steps"]],"process":{k:process[k] for k in ("exit_code","kill_requested","timed_out","cleanup_error")},"failure":row.get("failure")}
        for name in ("stdout","stderr"):
            raw=read_capture.raw_stream(folder,process["streams"][name]);value[name]={"pin":read_capture.pin(raw),"text":raw.decode("utf-8","backslashreplace") if len(raw)<100000 else None}
        for path in sorted((folder/"controls").glob("*.json")):
            c=json.loads(path.read_bytes());read_capture.raw_stream(path.parent,c["output"])
        raw=read_capture.raw_stream(folder,process["fixed_capabilities"]["host-trace"])
        value["trace"]=trace(raw);results.append(value)
    return {"status":"COMPLETE_DIAGNOSTIC_BYTES_READ","application_executions":0,"cases":results}
proof=guard.guarded(inspect,roots=[out,source],foreign_path=Path("/dev/null"));put(out/"READ_ONLY.json",proof)
for case in proof["evidence"]["cases"]:
    print("ACTUAL_DIAGNOSTIC",json.dumps({k:v for k,v in case.items() if k!="trace"},sort_keys=True))
    trace=case["trace"]
    print("ACTUAL_TRACE_COUNTS",json.dumps({k:v for k,v in trace.items() if k!="all_events"},sort_keys=True))
    events=[x for x in trace["all_events"] if x["magic"]=="HRGTR002"]
    print("LAST_ACTUAL_HIA",json.dumps([{"offset":e["offset"],"sequence":e["words"][0],"slot":e["words"][1],"event":e["words"][2],"result":e["words"][3],"work_capacity":e["words"][4],"output_capacity":e["words"][5],"phase":e["words"][6],"hia_sequence":e["words"][7],"output_extent":e["words"][8],"action_hex_words":[hex(x) for x in e["words"][9:]],"frame":e["frame"]} for e in events[-30:]],sort_keys=True))
print(json.dumps({"status":status,"guarded_reader":proof["evidence"]["status"],"guards":len(proof["probes"])},sort_keys=True))
