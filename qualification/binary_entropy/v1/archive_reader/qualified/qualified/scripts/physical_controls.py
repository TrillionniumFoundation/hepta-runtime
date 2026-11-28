#!/usr/bin/env python3
"""Seven actual retained-byte mutations and two complete relocations, zero application replay."""
from pathlib import Path
import argparse,copy,shutil,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,sha,source_evidence
from protocol import events,HEADER
from process import Recorder
from readonly import guarded
import read_capture
CASES=[("source-byte","frozen source bytes/mode differ"),("native-result","complete actual callable result"),
    ("native-work","entire actual HIA result and complete persistent workspace"),
    ("native-boundary","actual capability request equals HIA output"),
    ("original-error","unchanged CPython actual result agrees with fixed fault input"),
    ("image-entry","one complete immutable actual code image"),
    ("forgotten-descriptor","all actual new/cache/forgotten descriptor transitions"),
    ("relocation-a",None),("relocation-b",None)]
def files(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*"))if p.is_file()}
def mutate(folder,name):
    if name=="source-byte":
        path=folder/"source/trusted-build/native/binary_entropy.hepta";raw=path.read_bytes()
        path.write_bytes(bytes([raw[0]^1])+raw[1:]);return
    if name.startswith("relocation-"):return
    role="original"if name=="original-error"else"native"
    case="getrandom-error-5"if name=="original-error"else"cache-stat-5"if name=="forgotten-descriptor"else"normal"
    root=folder/"application"/role/case
    rows=[decode(line)for line in(root/"results.jsonl").read_bytes().splitlines()]
    raw=(root/"events.bin").read_bytes()
    if name=="native-result":
        value=bytearray.fromhex(rows[1]["result"]["response_hex"]);value[64]^=1
        rows[1]["result"]["response_hex"]=value.hex()
    elif name in("native-work","native-boundary"):
        wanted=11 if name=="native-work"else 8
        event=next(e for e in events(raw)if e["kind"]==wanted)
        mutable=bytearray(raw);at=event["start"]+HEADER.size+4096+(4095 if name=="native-work"else 24)
        mutable[at]^=1;raw=bytes(mutable);(root/"events.bin").write_bytes(raw)
    elif name=="original-error":
        rows[1]["result"]["error"]["errno"]=22
        rows[1]["original_observations"][0]["error"]["errno"]=22
    elif name=="image-entry":rows[0]["image_mapping"]["exports"]["binary_entropy_body_call_displacement"]+=1
    elif name=="forgotten-descriptor":del rows[2]["after_fds"][str(rows[0]["next_fd"])]
    else:raise ValueError("unfrozen physical input")
    for row in rows[1:-1]:
        for key in("event_start","event_end"):row[key]["sha256"]=sha(raw[:row[key]["bytes"]])
    rows[-1]["events"]["sha256"]=sha(raw)
    (root/"results.jsonl").write_bytes(b"".join(encoded(row)for row in rows))
    capture_path=folder/"application"/role/"CAPTURE.json";capture=decode(capture_path.read_bytes())
    selected=next(r for r in capture["completed"]if r["case"]==case)
    selected["files"]=files(root);capture_path.write_bytes(encoded(capture))
def verify_copy(source,application,runtime,name):
    message=dict(CASES)[name]
    try:value=read_capture.verify(source,application,runtime)
    except ValueError as error:
        require(message is not None and message in str(error),"mutation rejected for an unrelated reason: "+str(error))
        return dict(status="TARGETED_PHYSICAL_REFUSAL",name=name,message=str(error))
    require(message is None,"physical mutation was accepted")
    return dict(status="COMPLETE_RELOCATED_ENTROPY_PASS",name=name,qualification=value)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","read"])
    for key in("source","application","runtime","output"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--name");a=p.parse_args()
    source=a.source.resolve(strict=True);application=a.application.resolve(strict=True);runtime=a.runtime.resolve(strict=True)
    if a.stage=="read":
        result=guarded(lambda:verify_copy(source,application,runtime,a.name),roots=[ROOT,source,application,runtime])
        print(encoded(result).decode(),end="");return
    identity=source_evidence(source);require(not a.output.exists(),"fresh physical control roots")
    a.output.mkdir();recorder=Recorder(source,a.output/"processes");results=[]
    for name,message in CASES:
        work=a.output/name;work.mkdir();working=work/"working";working.mkdir()
        origins={"source":source,"application":application,"runtime":runtime}
        for label,path in origins.items():shutil.copytree(path,working/label,copy_function=shutil.copy2)
        before=files(working);mutate(working,name);after=files(working)
        require(set(before)==set(after),"physical mutation changed file inventory")
        changes={p:dict(before=before[p],after=after[p])for p in before if before[p]!=after[p]}
        require(bool(changes)==(message is not None),"physical case did not change exactly its intended scope")
        raw,process=recorder.run(name,[sys.executable,"-I","-S","-B",Path(__file__).resolve(),"read",
            "--source",working/"source","--application",working/"application","--runtime",working/"runtime",
            "--output",work/"unused","--name",name],timeout=180)
        proof=decode(raw);(work/"READONLY.json").write_bytes(raw)
        require(proof["before"]==proof["after"]and len(proof["probes"])==11,"actual mutation reader is fully guarded")
        require(files(working)==after,"full physical input changed during read")
        results.append(dict(name=name,process=process,guard=pin(work/"READONLY.json"),result=proof["evidence"],
            changes=changes,origins={label:str(working/label)for label in origins},
            original_source=str(ROOT),retained_complete_files=len(after)))
    result=dict(status="SEVEN_PHYSICAL_REFUSALS_TWO_RELOCATIONS_PASS",source=identity,cases=results,
        processes=recorder.records,guard_probes=99,application_executions=0,all_expanded_copies_retained=True)
    (a.output/"CONTROLS.json").write_bytes(encoded(result))
    require(source_evidence(source)==identity,"physical controls changed frozen source")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
