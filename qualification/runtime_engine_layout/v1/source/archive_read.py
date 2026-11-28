"""Restore and independently read the complete retained archive, without native replay."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,stat,sys,tarfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import read,put,pin,source
from process import Recorder
def identity(path):
    before=path.stat()
    with path.open("rb") as handle:digest=hashlib.file_digest(handle,"sha256").hexdigest()
    after=path.stat()
    assert (before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return dict(bytes=before.st_size,sha256=digest,mode=stat.S_IMODE(before.st_mode))
def process(row,folder,budget):
    assert row["completed"] is True and row["exit_code"]==0 and row["timed_out"] is False
    assert row["timeout_seconds"]==budget and row["elapsed_seconds"]<budget and row["pid"]==row["pgid"]
    for name in ("stdout","stderr"):
        value=row[name];assert pin(read(folder/value["file"]))=={k:value[k] for k in ("bytes","sha256")}
def proof(value,files,prefixes):
    assert value["before"]==value["after"] and len(value["probes"])==12
    assert value["native_or_rust_executions"]==0 and value["reader_writes"]==0
    actual=set()
    for key,item in value["before"].items():
        if item["sha256"] is None:continue
        root,path=key.split(":",1);logical=prefixes[int(root)]+"/"+path;actual.add(logical)
        expected=files[logical]
        assert item["sha256"]==expected["sha256"] and item["bytes"]==expected["bytes"]
        assert stat.S_IMODE(item["mode"])==expected["mode"]
    expected={key for key in files if any(key.startswith(prefix+"/") for prefix in prefixes)}
    assert actual==expected
def main():
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();binding=source(a.source_manifest_sha256)
    archive=a.archive.resolve(strict=True);before=identity(archive)
    assert not a.output.exists();a.output.mkdir(parents=True);out=a.output.resolve()
    objects=out/"objects";objects.mkdir();observed={};manifest=None
    with tarfile.open(archive,"r|gz") as stream:
        while member:=stream.next():
            assert member.isfile() and member.name not in observed and member.size>=0
            if member.name=="artifact-manifest.json":
                raw=stream.extractfile(member).read();assert len(raw)==member.size
                observed[member.name]=dict(**pin(raw),mode=member.mode);manifest=json.loads(raw)
            else:
                assert re.fullmatch(r"objects/[0-9a-f]{64}-[0-7]{3}",member.name)
                target=objects/member.name.split("/",1)[1]
                with stream.extractfile(member) as origin,target.open("xb") as handle:
                    shutil.copyfileobj(origin,handle,1<<20)
                target.chmod(member.mode);observed[member.name]=identity(target)
            stream.members.clear()
    assert manifest and manifest["schema"]=="hepta.runtime.engine-layout.complete-archive.v1"
    assert manifest["gate_status"]=="PASS" and manifest["native_or_rust_executions"]==0
    files=manifest["files"];expected_objects={}
    for logical,value in files.items():
        path=Path(logical)
        assert not path.is_absolute() and ".." not in path.parts and path.parts[0] in {"source","run"}
        assert value["object"]=="objects/"+value["sha256"]+"-"+format(value["mode"],"03o")
        expected={key:value[key] for key in ("bytes","sha256","mode")}
        assert observed[value["object"]]==expected
        if value["object"] in expected_objects:assert expected_objects[value["object"]]==expected
        expected_objects[value["object"]]=expected
    assert set(observed)==set(expected_objects)|{"artifact-manifest.json"}
    assert files["source/SOURCE_MANIFEST.json"]["sha256"]==binding
    restored=out/"restored";restored.mkdir()
    for logical,value in sorted(files.items()):
        target=restored/logical;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(out/value["object"],target);target.chmod(value["mode"])
        assert identity(target)=={k:value[k] for k in ("bytes","sha256","mode")}
    assert {p.relative_to(restored).as_posix() for p in restored.rglob("*") if p.is_file()}==set(files)
    gate=json.loads(read(restored/"run/GATE.json"));assert gate["status"]=="PASS"
    assert gate["source_manifest_sha256"]==binding and gate["stage"]=="complete" and gate["failure"] is None
    budgets={"build":900,"native":60,"read-only-admission":180,"physical-controls":180}
    assert [row["name"] for row in gate["processes"]]==list(budgets)
    for row in gate["processes"]:process(row,restored/"run/processes",budgets[row["name"]])
    base=json.loads(read(restored/"run/admission.json"))
    assert base["pid"]==gate["processes"][2]["pid"] and base["evidence"]["status"]=="PASS"
    proof(base,files,["source","run/build","run/native"])
    controls=json.loads(read(restored/"run/controls/CONTROLS.json"))
    assert controls["status"]=="PASS" and controls["physical_mutants"]==4 and controls["relocated_admissions"]==2
    assert controls["guard_probes"]==72 and controls["source_manifest_sha256"]==binding and len(controls["records"])==6
    names=["high-work-bit","borrowed-work-byte","engine-guard-permission","compiled-image-byte","relocation-1","relocation-2"]
    assert [row["name"] for row in controls["records"]]==names
    for number,row in enumerate(controls["records"]):
        process(row["process"],restored/"run/controls/processes",180)
        prefix="run/controls/"+row["name"];raw=read(restored/prefix/"proof.json")
        assert pin(raw)==row["proof"];value=json.loads(raw)
        assert value["pid"]==row["process"]["pid"] and value["evidence"]["status"]==("EXPECTED_REFUSAL" if number<4 else "PASS")
        proof(value,files,[prefix+"/source" if number>=4 else "source",prefix+"/build",prefix+"/native"])
    rec=Recorder(restored/"source",out/"processes")
    raw,row=rec.run("independent-archive-admission",[sys.executable,"-I","-B",restored/"source/verify_readonly.py",
        "--build",restored/"run/build","--native",restored/"run/native","--proof",out/"admission.json",
        "--source-manifest-sha256",binding],timeout=180)
    actual=json.loads(read(out/"admission.json"));assert actual["evidence"]==base["evidence"]
    proof(actual,files,["source","run/build","run/native"])
    assert identity(archive)==before and source()==binding
    result=dict(schema="hepta.runtime.engine-layout.independent-archive.v1",status="PASS",archive=before,
        source_manifest_sha256=binding,logical_files=len(files),logical_bytes=sum(v["bytes"] for v in files.values()),
        unique_objects=len(expected_objects),unique_bytes=sum(v["bytes"] for v in expected_objects.values()),
        all_object_bytes_and_modes_read=True,all_logical_bytes_and_modes_restored=True,
        guard_proofs=8,guard_probes=96,independent_admission=actual["evidence"],
        native_or_rust_executions=0,reader_writes=0,whole_runtime_replaced=False)
    put(out/"ARCHIVE_READ.json",result);print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
