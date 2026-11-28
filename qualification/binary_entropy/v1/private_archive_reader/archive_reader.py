#!/usr/bin/env python3
"""Download and independently read the complete qualified entropy archive, never execute it."""
from pathlib import Path
import argparse,ast,hashlib,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import archive_restore
decode=archive_restore.decode;encoded=archive_restore.encode;pin=archive_restore.pin;require=archive_restore.require
def source(root,expected=None):
    raw=(root/"SOURCE_MANIFEST.json").read_bytes()
    if expected is not None:require(hashlib.sha256(raw).hexdigest()==expected,"exact frozen independent source")
    rows=decode(raw)["files"];actual={p.relative_to(root).as_posix()for p in root.rglob("*")if p.is_file()}
    require(actual=={r["path"]for r in rows}|{"SOURCE_MANIFEST.json"}and len(rows)==len(actual)-1,"complete independent source")
    for row in rows:
        archive_restore.safe(row["path"]);path=root/row["path"];body=path.read_bytes()
        require(path.resolve()==path.absolute()and path.stat().st_mode&0o777==0o644
            and pin(path)=={k:row[k]for k in("bytes","sha256")}
            and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],
            "every independent source byte mode and Git object")
    return dict(manifest=pin(root/"SOURCE_MANIFEST.json"),files=len(rows))
def same(left,right):
    a={p.relative_to(left).as_posix():p for p in left.rglob("*")if p.is_file()}
    b={p.relative_to(right).as_posix():p for p in right.rglob("*")if p.is_file()}
    require(set(a)==set(b),"complete qualified/recovered source set")
    for key in a:require(a[key].read_bytes()==b[key].read_bytes()and a[key].stat().st_mode&0o777==b[key].stat().st_mode&0o777,
        "exact complete source-owned independent reader")
def prepare(input_work):
    base=input_work/"original/restored";qualified=ROOT/"qualified";same(qualified,base/"source")
    sys.path.insert(0,str(qualified/"scripts"))
    import read_evidence,build_reuse
    build_reuse.prepare_imports(base/"run/build-reuse")
    from readonly import guarded
    return base,read_evidence,guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","fetch","unpack","read","export"])
    p.add_argument("--input",type=Path,required=True);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path)
    a=p.parse_args();identity=source(ROOT,a.source_manifest_sha256);input_work=a.input.absolute();capture=a.capture.absolute()
    binding=decode((ROOT/"ARCHIVE_INPUT.json").read_bytes())
    if a.stage in("fetch","unpack"):
        function=archive_restore.fetch if a.stage=="fetch"else archive_restore.unpack
        print(encoded(function(input_work,binding)).decode(),end="");return
    if a.stage=="read":
        base,reader,guarded=prepare(input_work)
        result=guarded(lambda:reader.verify(base/"source",base/"run"),
            roots=[ROOT,input_work/"download",input_work/"original"])
        require(source(ROOT,a.source_manifest_sha256)==identity,"independent reader changed frozen source")
        print(encoded(result).decode(),end="");return
    sys.path.insert(0,str(ROOT/"qualified/scripts"))
    from process import Recorder
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh independent proof export")
        a.output.mkdir();recorder=Recorder(ROOT,a.output/"processes")
        raw,process=recorder.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"export_proof.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,
            process=process,archive=result,new_application_executions=0)))
        print(encoded(result).decode(),end="");return
    require(not input_work.exists()and not capture.exists(),"fresh independent input and output")
    input_work.mkdir();capture.mkdir();recorder=Recorder(ROOT,capture/"processes")
    result=None
    try:
        for stage,limit in(("fetch",60),("unpack",180),("read",180)):
            raw,process=recorder.run(stage,[sys.executable,"-I","-S","-B",Path(__file__).resolve(),stage,
                "--input",input_work,"--capture",capture,"--source-manifest-sha256",a.source_manifest_sha256],timeout=limit)
            value=decode(raw)
            (capture/(stage.upper()+".json")).write_bytes(raw)
            if stage=="read":
                require(value["before"]==value["after"]and len(value["probes"])==11,"complete independent pure guard")
                result=value
        gate=dict(status="PASS",source=identity,input=binding,processes=recorder.records,read=result["evidence"],
            unchanged_entries=result["entries"],new_guard_probes=11,new_native_or_original_applications=0,
            every_original_logical_file_fully_restored=True,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(gate))
        require(source(ROOT,a.source_manifest_sha256)==identity,"source changed during independent read")
        print(encoded(dict(status="INDEPENDENT_ENTROPY_PRIVATE_COMPLETE_ARCHIVE_PASS",input=binding,
            unchanged_entries=result["entries"],new_guard_probes=11,read=result["evidence"],
            new_native_or_original_applications=0,whole_runtime_replaced=False)).decode(),end="")
    except BaseException as error:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,input=binding,
            processes=recorder.records,error_type=type(error).__name__,message=str(error),
            new_native_or_original_applications=0,whole_runtime_replaced=False)))
        if recorder.records:print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
