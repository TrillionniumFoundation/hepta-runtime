#!/usr/bin/env python3
"""Four honestly resealed physical refusals and two full source/capture relocations."""
from pathlib import Path
import argparse,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
from readonly import guarded
import read_private
CASES=[("result-byte","complete private response, capacity header and unused output tail"),
    ("work-guard","complete input, arena extents and all guard bytes"),
    ("native-owner","native full no-mutation rejection"),
    ("retry-capacity","complete private response, capacity header and unused output tail"),
    ("relocation-a",None),("relocation-b",None)]
def files(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*"))if p.is_file()}
def mutate(folder,name):
    if name.startswith("relocation-"):return
    native=name=="native-owner";root=folder/"capture"/("native"if native else"hia")
    rows=decode((root/"CALLS.json").read_bytes())
    if native:row=rows[0];ref=row["buffers"]["after"];at=248
    else:
        label="flow/exact-capacity-retry-and-malformed-resumes/5"if name=="retry-capacity"else"flow/normal-raw-and-uuid/1"
        row=next(r for r in rows if r["label"]==label)
        ref=row["after"]["work"if name=="work-guard"else"output"]
        at=4111 if name=="work-guard"else 32 if name=="retry-capacity"else 64
    path=root/ref["path"];raw=bytearray(path.read_bytes());raw[at]^=1;path.write_bytes(raw)
    ref.update(pin(path));(root/"CALLS.json").write_bytes(encoded(rows))
def verify_copy(source,capture,name):
    message=dict(CASES)[name]
    try:value=read_private.verify(source,capture)
    except ValueError as error:
        require(message is not None and message in str(error),"private mutation rejected for unrelated reason: "+str(error))
        return dict(status="TARGETED_PHYSICAL_REFUSAL",name=name,message=str(error))
    require(message is None,"private physical mutation accepted")
    return dict(status="COMPLETE_PRIVATE_RELOCATION_PASS",name=name,qualification=value)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","read"])
    for key in("source","capture","output"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--name");a=p.parse_args()
    source=a.source.resolve(strict=True);capture=a.capture.resolve(strict=True)
    if a.stage=="read":
        result=guarded(lambda:verify_copy(source,capture,a.name),roots=[ROOT,source,capture])
        print(encoded(result).decode(),end="");return
    identity=source_evidence(source);require(not a.output.exists(),"fresh private physical root")
    a.output.mkdir();recorder=Recorder(source,a.output/"processes");results=[]
    for name,message in CASES:
        work=a.output/name;work.mkdir();working=work/"working";working.mkdir()
        for label,path in(("source",source),("capture",capture)):
            shutil.copytree(path,working/label,copy_function=shutil.copy2)
        before=files(working);mutate(working,name);after=files(working)
        require(set(before)==set(after),"private physical mutation changed inventory")
        changes={p:dict(before=before[p],after=after[p])for p in before if before[p]!=after[p]}
        require(len(changes)==(2 if message is not None else 0),"private physical mutation/reseal extent")
        raw,process=recorder.run(name,[sys.executable,"-I","-S","-B",Path(__file__).resolve(),"read",
            "--source",working/"source","--capture",working/"capture","--output",work/"unused","--name",name],timeout=180)
        proof=decode(raw);(work/"READONLY.json").write_bytes(raw)
        require(proof["before"]==proof["after"]and len(proof["probes"])==11,"fully guarded private control")
        require(files(working)==after,"private physical bytes changed during read")
        results.append(dict(name=name,process=process,guard=pin(work/"READONLY.json"),
            result=proof["evidence"],changes=changes,retained_complete_files=len(after)))
    result=dict(status="FOUR_PRIVATE_REFUSALS_TWO_RELOCATIONS_PASS",source=identity,cases=results,
        processes=recorder.records,guard_probes=66,application_executions=0,all_expanded_copies_retained=True)
    (a.output/"CONTROLS.json").write_bytes(encoded(result))
    require(source_evidence(source)==identity,"private physical control changed source")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
