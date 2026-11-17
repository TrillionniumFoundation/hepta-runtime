"""Four physical rehashed reader refusals; no HIA or Rust executions."""
import argparse,copy,gzip,os,shutil,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source,files
from compare_captured import frames,verify
NAMES=("actual-input-byte","actual-workspace-byte","omitted-call","image-binding")
def model(base,name):
    items=[(copy.deepcopy(row),raws)for row,raws in frames(base/"complete-new-buffers.bin.gz")]
    result=loads(read(base/"RESULT.json"))
    if name in("actual-input-byte","actual-workspace-byte"):
        i=next(i for i,(row,raws)in enumerate(items)if row["meta"]["kind"]=="observed-owner")
        row,raws=items[i];raws=list(raws);which=0 if name=="actual-input-byte"else row["meta"]["before_buffers"]
        data=bytearray(raws[which]);data[8192 if which==0 else 32768+88]^=1;raws[which]=bytes(data);items[i]=(row,tuple(raws))
    elif name=="omitted-call":
        require(len(items)>1,"meaningful complete ordinary call omission");items.pop()
        result["calls"]-=1;result["new_hia_calls"]-=1
    elif name=="image-binding":result["image"]=dict(result["image"],sha256="0"*64)
    else:raise ValueError("unknown exact physical control")
    offset=8;out=[]
    for i,(row,raws)in enumerate(items):
        row=dict(row,index=i,offset=offset,buffers=[pin(b)for b in raws])
        header=encoded(row);offset+=8+len(header)+sum(map(len,raws));out.append((row,raws))
    return out,result
def write_clone(base,target,name):
    shutil.copytree(base,target);items,result=model(base,name)
    with (target/"complete-new-buffers.bin.gz").open("wb")as physical:
        with gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=physical,mtime=0)as s:
            s.write(b"HNWLOG01")
            for row,raws in items:
                head=encoded(row);s.write(struct.pack("<Q",len(head))+head+b"".join(raws))
            s.write(b"HNWEND01"+struct.pack("<Q",len(items)))
    (target/"RECORDS.json").write_bytes(encoded([r for r,_ in items]))
    (target/"RESULT.json").write_bytes(encoded(result))
def rejection(prior,build,clone):
    try:verify(prior,build,clone,"ordinary")
    except ValueError as error:return dict(type=type(error).__name__,message=str(error))
    raise ValueError("physical altered evidence was accepted")
def create(workspace):
    identity=source();start=time.monotonic();out=workspace/"run/reader-controls";out.mkdir()
    base=workspace/"run/groups/ordinary";prior=workspace/"prior/complete";build=workspace/"fresh/complete/run/build"
    rows=[]
    for name in NAMES:
        clone=out/name;write_clone(base,clone,name);error=rejection(prior,build,clone)
        rows.append(dict(name=name,error=error,files=files(clone)))
    report=dict(status="FOUR_PHYSICAL_FIXED_EIGHT_REFUSALS_PASS",source_manifest_sha256=identity,
        names=list(NAMES),rows=rows,pid=os.getpid(),parent_pid=os.getppid(),pgid=os.getpgrp(),
        elapsed_seconds=time.monotonic()-start,timeout_seconds=180,native_executions=0,rust_executions=0)
    (out/"CONTROLS.json").write_bytes(encoded(report));return report
def verify_controls(workspace):
    identity=source();out=workspace/"run/reader-controls";report=loads(read(out/"CONTROLS.json"))
    require(report["status"]=="FOUR_PHYSICAL_FIXED_EIGHT_REFUSALS_PASS"
        and report["source_manifest_sha256"]==identity and report["names"]==list(NAMES)
        and len(report["rows"])==4 and report["timeout_seconds"]==180 and type(report["elapsed_seconds"])is float
        and 0<=report["elapsed_seconds"]<=180 and report["native_executions"]==report["rust_executions"]==0,
        "all complete physical control records and unchanged budget")
    base=workspace/"run/groups/ordinary";prior=workspace/"prior/complete";build=workspace/"fresh/complete/run/build"
    for name,row in zip(NAMES,report["rows"],strict=True):
        clone=out/name;require(row["name"]==name and row["files"]==files(clone),"complete retained physical clone identity")
        wanted,result=model(base,name);actual=list(frames(clone/"complete-new-buffers.bin.gz"))
        require(len(actual)==len(wanted) and all(encoded(a)==encoded(w)and ab==wb for (a,ab),(w,wb)in zip(actual,wanted,strict=True)) and read(clone/"RECORDS.json")==encoded([r for r,_ in wanted])
            and read(clone/"RESULT.json")==encoded(result)
            and set(files(clone))=={"complete-new-buffers.bin.gz","RECORDS.json","RESULT.json"},
            "only the exact frozen complete rehashed mutation")
        require(rejection(prior,build,clone)==row["error"],"same actual strict rejection without creating or writing clone")
    require(source()==identity,"complete control reader source unchanged")
    return report
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--workspace",type=Path,required=True)
    p.add_argument("--phase",choices=("create","verify"),required=True);a=p.parse_args()
    result=create(a.workspace.resolve(strict=True))if a.phase=="create"else verify_controls(a.workspace.resolve(strict=True))
    print(encoded(result).decode(),end="")
