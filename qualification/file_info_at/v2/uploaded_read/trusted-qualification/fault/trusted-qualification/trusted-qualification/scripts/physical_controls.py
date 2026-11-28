#!/usr/bin/env python3
"""Eight real evidence alterations and two complete relocations; no replay."""
from pathlib import Path
import argparse,copy,gzip,hashlib,json,os,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,encoded,decode,pin,require
import read_capture
from readonly import guarded
def identity(p):return dict(**pin(p),mode=p.stat().st_mode&0o777)
def tree(source,target):
    shutil.copytree(source,target,copy_function=os.link)
def replace(path,raw):
    mode=path.stat().st_mode&0o777;tmp=path.with_name(path.name+".new")
    tmp.write_bytes(raw);tmp.chmod(mode);os.replace(tmp,path)
def rewrite_cases(folder,change):
    file=folder/"cases.jsonl.gz"
    with gzip.open(file,"rb")as stream:values=[decode(row)for row in stream]
    change(values);rows=[encoded(v)for v in values];raw=b"".join(rows)
    replace(file,gzip.compress(raw,compresslevel=1,mtime=0))
    report=decode((folder/"CAPTURE.json").read_bytes())
    report.update(cases_file=pin(file),cases_raw=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
        case_rows=[dict(id=v["input"]["id"],bytes=len(r),sha256=hashlib.sha256(r).hexdigest())for v,r in zip(values,rows)])
    replace(folder/"CAPTURE.json",encoded(report))
def alter_result(values):
    value=values[0]["actual"]["chain"]["invocations"][0]["result"]
    if value["ok"]:value["value"]["size"]+=1
    else:value["error"]["message"]+=" physically altered"
def outcome(source,data,name):
    try:read_capture.verify(source,data,name)
    except (ValueError,OSError,EOFError,KeyError)as e:
        return dict(status="REJECTED",error_type=type(e).__name__,message=str(e))
    raise ValueError("physically altered evidence unexpectedly passed")
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--data",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--baseline",type=Path,required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);data=a.data.resolve(strict=True);identity_before=source_evidence(source)
    baseline=decode(a.baseline.read_bytes());require(baseline["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_INFO_PASS","actual original baseline guard")
    require(not a.output.exists(),"fresh physical controls");a.output.mkdir(parents=True)
    names=["native-buffer","original-stdout","native-journal","original-case","native-image","source-manifest","honest-native-result","honest-original-result"]
    results=[]
    for number,name in enumerate(names):
        root=a.output/name;root.mkdir();selected=root/"data";tree(data,selected)
        selected_source=source
        if name=="source-manifest":selected_source=root/"source";tree(source,selected_source)
        if name=="native-buffer":file=sorted((selected/"native/buffers").glob("*.gz"))[0]
        elif name=="original-stdout":file=sorted((selected/"original/carriers").glob("*/carrier.stdout.gz"))[0]
        elif name=="native-journal":file=sorted((selected/"native/carriers").glob("*/carrier.journal.gz"))[0]
        elif name=="original-case":file=selected/"original/cases.jsonl.gz"
        elif name=="native-image":file=selected/"production/file-info-at-callable.elf"
        elif name=="source-manifest":file=selected_source/"SOURCE_MANIFEST.json"
        else:file=selected/("native"if name=="honest-native-result"else"original")/"cases.jsonl.gz"
        before=file.read_bytes();before_identity=identity(file);(root/"changed-before.bin").write_bytes(before)
        if name=="native-buffer":
            raw=gzip.decompress(before);require(raw,"nonempty actual buffer block");replace(file,gzip.compress(bytes([raw[0]^1])+raw[1:],compresslevel=1,mtime=0))
        elif name=="source-manifest":replace(file,before+b"\nACTUAL_BAD_SOURCE\n")
        elif name.startswith("honest-"):rewrite_cases(file.parent,alter_result)
        else:require(before,"nonempty actual retained file");replace(file,bytes([before[0]^1])+before[1:])
        after=file.read_bytes();require(after!=before,"actual physical mutation absent");(root/"changed-after.bin").write_bytes(after)
        mutation=dict(name=name,file=str(file),before=before_identity,after=identity(file),
            before_bytes=pin(root/"changed-before.bin"),after_bytes=pin(root/"changed-after.bin"),honestly_resealed=name.startswith("honest-"))
        (root/"MUTATION.json").write_bytes(encoded(mutation))
        guard=guarded(lambda:outcome(selected_source,selected,a.group),roots=[ROOT,selected_source,selected])
        expected={"native-buffer":"complete block bytes changed","original-stdout":"complete stdout compressed identity",
            "native-journal":"Not a gzipped file","original-case":"complete case archive identity",
            "native-image":"retained native ELF bytes","source-manifest":"Extra data",
            "honest-native-result":"actual native terminal result","honest-original-result":"actual original value"}[name]
        require(guard["evidence"]["status"]=="REJECTED"and expected in guard["evidence"]["message"],"wrong physical rejection reason: "+name)
        (root/"READONLY.json").write_bytes(encoded(guard));results.append(dict(name=name,mutation=mutation,guard_probes=len(guard["probes"]),evidence=guard["evidence"]))
    relocations=[]
    for number in(1,2):
        root=a.output/("relocated-"+str(number));root.mkdir();new_source=root/"source";new_data=root/"data"
        tree(source,new_source);tree(data,new_data)
        guard=guarded(lambda:read_capture.verify(new_source,new_data,a.group),roots=[ROOT,new_source,new_data])
        require(guard["evidence"]==baseline["evidence"],"complete relocation changed qualification")
        (root/"READONLY.json").write_bytes(encoded(guard));relocations.append(dict(name=root.name,guard_probes=len(guard["probes"]),entries=guard["entries"],evidence=guard["evidence"]))
    require(source_evidence(source)==identity_before,"source changed by controls")
    result=dict(status="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS",group=a.group,physical=results,relocations=relocations,
        guard_probes=sum(x["guard_probes"]for x in results+relocations),application_executions=0)
    (a.output/"RESULT.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":main()
