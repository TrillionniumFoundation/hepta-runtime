"""Reopen the already qualified full catalog domain and select actual native Tool bytes."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import mmap
import os
import socket
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode=True
INSTALLED=("host_list","effective_config","execution_shadow_admit","view","workdir",
           "directory_create","file_move","directory_move","text_editor","extract_lines")
ARTIFACT=14201568537
RUN=43813791993

def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {"bytes":len(raw),"sha256":sha(raw)}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def snapshot(root):
    files={}
    for path in sorted(root.rglob("*")):
        assert not path.is_symlink()
        if path.is_dir():continue
        before=path.stat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
        with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
        after=path.stat()
        assert (before.st_size,before.st_mtime_ns,before.st_ino,before.st_mode)==(after.st_size,after.st_mtime_ns,after.st_ino,after.st_mode)
        files[path.relative_to(root).as_posix()]={"bytes":before.st_size,"sha256":digest,"mode":before.st_mode & 0o777}
    return files

def objects(raw):
    text=raw.decode("utf-8")
    decoder=json.JSONDecoder()
    assert text.startswith("{") and text.endswith("}")
    at=1;top={}
    while text[at]!="}":
        key,end=decoder.raw_decode(text,at)
        assert isinstance(key,str) and key not in top and text[end]==":"
        begin=end+1
        value,end=decoder.raw_decode(text,begin)
        top[key]=(begin,end,value)
        if text[end]=="}":
            assert end==len(text)-1
            at=end
        else:
            assert text[end]==","
            at=end+1
    begin,end,tools=top["tools"]
    assert isinstance(tools,list) and text[begin]=="[" and text[end-1]=="]"
    items=[];at=begin+1
    while at<end-1:
        obj,last=decoder.raw_decode(text,at)
        assert type(obj) is dict and isinstance(obj["name"],str)
        items.append((obj["name"],text[at:last].encode()))
        if last==end-1:at=last
        else:
            assert text[last]==","
            at=last+1
    assert [json.loads(raw) for _,raw in items]==tools
    assert len({name for name,_ in items})==len(items)
    return top,items

def main():
    p=argparse.ArgumentParser()
    for name in ("capture","reader-source","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    root=(a.capture/"retained").resolve(strict=True)
    archive=json.loads((a.capture/"ARCHIVE_READBACK.json").read_bytes())
    assert archive["status"]=="PASS" and archive["run"]==RUN and archive["artifact"]==ARTIFACT
    before=snapshot(root)
    assert {k:{x:r[x] for x in ("bytes","sha256")} for k,r in before.items()}==archive["complete_files"]
    sys.path.insert(0,str(a.reader_source.resolve(strict=True)))
    import read_catalog
    import run_recipe
    # Preload all lazy compression helpers before the immutable reader guard.
    gzip.compress(b"preload",mtime=0)
    assert read_catalog.TRUSTED_PROFILE_BYTES==(root/"source/source-profile.json").read_bytes()
    read_catalog.reference_module(root/"source")
    active=[False];denied=[]
    blocked={"subprocess.Popen","os.system","os.posix_spawn","os.fork","os.forkpty","pty.spawn",
        "socket.__new__","socket.connect","socket.bind","ctypes.dlopen","ctypes.dlsym","mmap.__new__",
        "os.mkdir","os.rmdir","os.remove","os.rename","os.link","os.symlink","os.chmod","os.chown","os.utime",
        "os.truncate","os.exec","os.spawn","os.kill","os.killpg"}
    write_flags=os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND
    def audit(event,args):
        if not active[0]:return
        refuse=event in blocked or event.startswith("os.exec") or event.startswith("os.spawn")
        if event=="open":
            mode=args[1] if len(args)>1 else None
            flags=args[2] if len(args)>2 else 0
            refuse=(isinstance(mode,str) and any(c in mode for c in "wax+")) or (isinstance(flags,int) and bool(flags & write_flags))
        if refuse:
            denied.append(event)
            raise PermissionError("readonly catalog evidence guard: "+event)
    sys.addaudithook(audit)
    probe=root/"__reader_probe__"
    checks=[
      ("process",lambda:subprocess.Popen(["/bin/true"])),
      ("shell",lambda:os.system("true")),
      ("spawn",lambda:os.posix_spawn("/bin/true",["true"],{})),
      ("socket",lambda:socket.socket()),
      ("foreign-library",lambda:ctypes.CDLL(None)),
      ("file-write",lambda:open(probe,"wb")),
      ("descriptor-write",lambda:os.open(probe,os.O_WRONLY|os.O_CREAT,0o600)),
      ("mkdir",lambda:os.mkdir(probe)),
      ("rename",lambda:os.rename(probe,root/"__reader_probe2__")),
      ("unlink",lambda:os.unlink(probe)),
      ("chmod",lambda:os.chmod(root/"result.json",0o600)),
      ("native-map",lambda:mmap.mmap(-1,4096,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC))]
    probes=[];active[0]=True;started=time.monotonic()
    try:
        for name,fn in checks:
            count=len(denied)
            try:fn()
            except PermissionError:pass
            else:raise AssertionError("readonly guard probe allowed: "+name)
            assert len(denied)==count+1
            probes.append({"name":name,"event":denied[-1],"denied":True})
        count=len(denied)
        verified=run_recipe.verify(root)
        assert verified["status"]=="PASS" and verified["process_launches"]==0 and len(denied)==count
        after=snapshot(root)
        assert before==after
        matrix=json.loads((root/"native/result.json").read_bytes())
        assert matrix["status"]=="PASS" and len(matrix["shapes"])==18
        shapes=[row for row in matrix["shapes"] if row["flags"]==1 and row["modern"] in (0,1)]
        assert sorted(row["modern"] for row in shapes)==[0,1]
        selected={}
        copied={}
        for row in shapes:
            label="modern" if row["modern"] else "ordinary"
            name=row["name"]
            assert isinstance(name,str) and "/" not in name and ".." not in name
            typed=gzip.decompress((root/("native/"+name+".typed-json.gz")).read_bytes())
            top,items=objects(typed)
            assert top["resultType"][2]=="complete" and len(items)==row["count"]
            if row["modern"]:
                assert top["ttlMs"][2]==0 and top["cacheScope"][2]=="public"
            else:
                assert "ttlMs" not in top and "cacheScope" not in top
            chosen=[(tool,raw) for tool,raw in items if tool in INSTALLED]
            assert len(chosen)==len(INSTALLED) and {tool for tool,_ in chosen}==set(INSTALLED)
            subset=b"["+b",".join(raw for _,raw in chosen)+b"]"
            copied["actual/"+label+".typed.json"]=typed
            copied["selected/"+label+".tools.json"]=subset
            selected[label]={"flags":1,"modern":row["modern"],"shape":name,"actual_count":len(items),
                "actual_typed":{"path":"actual/"+label+".typed.json",**pin(typed)},
                "selected_tools":{"path":"selected/"+label+".tools.json",**pin(subset)},
                "installed_in_original_router_order":[name for name,_ in chosen],
                "actual_native_calls":row["calls"],"actual_serde_call":row["serde"],"actual_sdk_call":row["sdk"]}
            records=[*row["calls"],row["serde"],row["sdk"]]
            for record in records:
                prefix=record["prefix"]
                assert "/" not in prefix and ".." not in prefix
                for suffix in ("input.gz","output.gz","workspace.gz"):
                    relative="native/"+prefix+"."+suffix
                    copied["retained/"+relative]=(root/relative).read_bytes()
            for suffix in ("policy-json.gz","canonical-json.gz","typed-json.gz"):
                relative="native/"+name+"."+suffix
                copied["retained/"+relative]=(root/relative).read_bytes()
        assert copied["selected/ordinary.tools.json"]==copied["selected/modern.tools.json"]
        source_profile=(root/"source/source-profile.json").read_bytes()
        copied["retained/source-profile.json"]=source_profile
        copied["retained/native-result.json"]=(root/"native/result.json").read_bytes()
        copied["retained/native-matrix.process.json"]=(root/"processes/native-matrix.process.json").read_bytes()
        copied["retained/native-matrix.stdout"]=(root/"processes/native-matrix.stdout").read_bytes()
        copied["retained/native-matrix.stderr"]=(root/"processes/native-matrix.stderr").read_bytes()
        copied["retained/catalog-input.json"]=(root/"source/catalog-input.json").read_bytes()
        copied["retained/declarations.json"]=(root/"source/declarations.json").read_bytes()
    finally:
        active[0]=False
    for name,raw in copied.items():
        path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    evidence={"schema":"hepta.runtime.extract-catalog-retained-readonly.v1","status":"PASS",
        "archive_run":RUN,"archive_artifact":ARTIFACT,"elapsed_seconds":time.monotonic()-started,
        "archive_zip":archive["zip"],"archive_tar":archive["tar"],"complete_archive_files":archive["files"],
        "source_profile":pin(source_profile),"before":sha(encoded(before)),"after":sha(encoded(after)),
        "probes":probes,"reader_unexpected_denials":0,"native_executions":0,"rust_executions":0,
        "reader_writes":0,"complete_reader_result":verified,"new_original_capture":False}
    (a.output/"READONLY.json").write_bytes(encoded(evidence))
    (a.output/"ARCHIVE_READBACK.json").write_bytes((a.capture/"ARCHIVE_READBACK.json").read_bytes())
    assets={"schema":"hepta.runtime.extract-actual-catalog-assets.v1","status":"RETAINED_NATIVE_ASSETS_ADMITTED",
        "run":RUN,"artifact":ARTIFACT,"target_commit":"d3d75c30719db966b004756f610007a7c723729e",
        "declared_input_tools":136,"installed_tools":list(INSTALLED),"shapes":selected,
        "files":{name:pin(raw) for name,raw in sorted(copied.items())},
        "data_origin":"actual native policy -> serde Value -> SDK catalog output",
        "original_expected_wire_used_as_implementation":False,"native_reexecutions":0,"rust_executions":0,
        "full_public_handler_qualified":False,"whole_runtime_replaced":False}
    (a.output/"ASSETS.json").write_bytes(encoded(assets))
    print(json.dumps({"status":assets["status"],"shapes":{k:{"shape":v["shape"],"actual_count":v["actual_count"],"selected_tools":v["selected_tools"]} for k,v in selected.items()},
        "guards":len(probes),"native_executions":0,"rust_executions":0},sort_keys=True))

if __name__=="__main__":main()
