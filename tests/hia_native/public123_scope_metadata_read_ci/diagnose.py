"""Read exactly the retained original/native four; no application execution."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
for name in ("capture-source","native-source","output"):p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args();source=a.capture_source.resolve(strict=True);native=a.native_source.resolve(strict=True);out=a.output.absolute()
assert not out.exists();out.mkdir(parents=True)
sys.path[:0]=[str(native),str(source),str(source/"build_reader"),str(HERE)]
import callable_common,read_only_guard as guard,read_capture_fixed as reader,atomic_frames
from restore_inputs import flat_archive
from restore_graph import download
from capture_common import file_pin
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=json.loads((HERE/"INPUTS.json").read_bytes())
assert file_pin(source/"SOURCE_MANIFEST.json")==identity["capture_source_manifest"]
assert file_pin(native/"SOURCE_MANIFEST.json")==identity["native_source_manifest"]
for root,label in ((HERE,"recipe"),(source,"capture"),(native,"native")):put(out/(label+"-SOURCE.json"),callable_common.syntax(root))
archive=out/"producer.zip";download(archive,identity["artifact"])
put(out/"ARCHIVE_READ.json",flat_archive(archive,identity,out/"retained"))
actual=out/"retained/capture"
for captured,frozen in ((out/"retained/recipe-source",source),(actual/"recipe-extension",native)):
    assert (captured/"SOURCE_MANIFEST.json").read_bytes()==(frozen/"SOURCE_MANIFEST.json").read_bytes()
    for row in json.loads((frozen/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        assert (captured/row["path"]).read_bytes()==(frozen/row["path"]).read_bytes()
def differences(a,b,path=""):
    if type(a) is not type(b):return [{"path":path,"original":a,"native":b}]
    if isinstance(a,dict):
        if a.keys()!=b.keys():return [{"path":path,"original":a,"native":b}]
        result=[]
        for k in a:result.extend(differences(a[k],b[k],path+"/"+str(k)))
        return result
    if isinstance(a,list):
        if len(a)!=len(b):return [{"path":path,"original":a,"native":b}]
        result=[]
        for i,(x,y) in enumerate(zip(a,b,strict=True)):result.extend(differences(x,y,path+"/"+str(i)))
        return result
    return [] if a==b else [{"path":path,"original":a,"native":b}]
def inspect():
    inputs=json.loads((actual/"INPUTS_READY.json").read_bytes())
    pair=[reader.read(actual/side,side,{k:inputs[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
    result=[]
    for i,(left,right) in enumerate(zip(*pair,strict=True)):
        fields={}
        for field in ("stdout","stderr","exit_code","tail","files","metadata","milestones"):
            fields[field]={"equal":left[field]==right[field]}
            if left[field]!=right[field]:
                fields[field]["differences"]=differences(left[field],right[field])
                fields[field]["complete_original"]=left[field]
                fields[field]["complete_native"]=right[field]
        final=[]
        for x,y in zip(left["trace"]["final"],right["trace"]["final"],strict=True):
            final.append({"phase":x["phase"],"state_equal":x["state"]==y["state"],"holders_equal":x["private"]["fixture_holders"]==y["private"]["fixture_holders"]})
        raw=[]
        for side in ("original","native"):
            case=json.loads((actual/side/("%03d"%i)/"CASE.json").read_bytes())
            snapshots=[case["initial"]]+[s["snapshot"] for s in case["steps"] if "snapshot" in s]+[case["final"]]
            raw.append({"side":side,"snapshots":[s["complete_metadata"] for s in snapshots]})
        atomic=atomic_frames.inspect(actual/"native"/("%03d"%i)/"process") if i==3 else None
        result.append({"atomic":atomic,"case":i,"name":left["name"],"fields":fields,"final":final,"complete_raw_metadata":raw,"native_complete_scope_context_observations":len(right["trace"]["request_scope_mappings"])})
    return {"status":"COMPLETE_RETAINED_PAIR_DIAGNOSTIC_READ","application_executions":0,"qualified":False,"cases":result}
proof=guard.guarded(inspect,roots=[out,source,native,HERE],foreign_path=Path("/dev/null"))
put(out/"READ_ONLY.json",proof)
for row in proof["evidence"]["cases"]:
    print("ACTUAL_COMPLETE_FIELD_COMPARISON",json.dumps({k:v for k,v in row.items() if k not in ("complete_raw_metadata","atomic")},sort_keys=True),flush=True)
for row in proof["evidence"]["cases"]:
    if row["case"]!=3:continue
    print("ACTUAL_RAW_METADATA_IDENTITY",json.dumps({"case":row["case"],"name":row["name"],"raw":row["complete_raw_metadata"]},sort_keys=True),flush=True)
for row in proof["evidence"]["cases"]:
    if row["atomic"] is not None:print("ACTUAL_ATOMIC_LIFETIME",json.dumps(row["atomic"],sort_keys=True),flush=True)
put(out/"RESULT.json",{"status":proof["evidence"]["status"],"application_executions":0,"guard_probes":len(proof["probes"]),"qualified":False})
