"""Read the entire uploaded recovery ZIP/TAR and every restored logical file and mode."""
from pathlib import Path
import argparse,hashlib,io,shutil,sys,tarfile,zipfile
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from independent_support import source,expected,relative,need,pin,read,loads,encoded,files

def restore(archive,destination,report):
    identity=source();e=expected()
    need(not destination.exists(),"fresh independent relocation")
    raw=read(archive);need(pin(raw)==e["zip"],"complete uploaded recovery ZIP identity")
    names={e["tar_name"],e["tar_name"]+".json"}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(len(z.infolist())==2 and set(z.namelist())==names and z.testzip() is None,"complete ZIP domain and CRC")
        packed=z.read(e["tar_name"]);producer=loads(z.read(e["tar_name"]+".json"))
    need(pin(packed)==e["tar"] and producer==e["archive_receipt"],"complete uploaded TAR and actual exporter receipt")
    destination.mkdir(parents=True,exist_ok=False)
    objects=destination.parent/(destination.name+"-objects");objects.mkdir(exist_ok=False)
    seen={};manifest=None;manifest_raw=None
    with tarfile.open(fileobj=io.BytesIO(packed),mode="r:gz") as tar:
        for item in tar:
            relative(item.name);need(item.isfile() and item.name not in seen,"unique regular complete member")
            with tar.extractfile(item) as f:body=f.read()
            need(len(body)==item.size,"entire TAR member")
            row=dict(**pin(body),mode=item.mode);seen[item.name]=row
            if item.name=="artifact-manifest.json":
                need(item.mode==0o644,"original complete manifest mode")
                manifest_raw=body;manifest=loads(body)
            else:
                need(item.name=="objects/"+row["sha256"]+"-"+format(item.mode,"03o"),"whole content/mode identity")
                p=objects/relative(item.name);p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(body);p.chmod(item.mode)
    need(manifest["schema"]=="hepta.audit-record-callable.recovery-archive.v1" and
         manifest["git_head"]==e["head"] and manifest["run_id"]==str(e["run"]) and
         manifest["reader_adapter_source_sha256"]==e["reader_source_sha256"] and
         manifest["original_source_manifest_sha256"]==e["original_source_sha256"] and
         manifest["original_head"]==e["original_head"] and manifest["original_run"]==e["original_run"] and
         manifest["original_status"]=="FAIL" and manifest["original_all_files_unchanged"] is True and
         manifest["original_zip"]==e["original_zip"] and manifest["original_tar"]==e["original_tar"] and
         manifest["gate"]["status"]=="PASS" and manifest["native_or_rust_executions"]==manifest["original_rust_replay"]==0 and
         manifest["archive_and_hot_cache_qualified"] is False and manifest["begin_finish_caller_qualified"] is False and
         manifest["public_handler_qualified"] is False and manifest["whole_runtime_replaced"] is False,
         "exact completed recovery source/process and preserved original failure")
    logical=manifest["files"]
    need(len(logical)==e["archive_receipt"]["logical_files"] and
         sum(r["bytes"] for r in logical.values())==e["archive_receipt"]["logical_bytes"],"all logical records and bytes")
    objects_expected={}
    for name,row in logical.items():
        p=destination/relative(name)
        need(set(row)=={"bytes","sha256","mode","object"} and type(row["mode"]) is int and
             row["object"]=="objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"exact complete logical mapping")
        value={k:row[k] for k in ("bytes","sha256","mode")}
        need(seen[row["object"]]==value,"every full logical byte and mode")
        objects_expected[row["object"]]=value;p.parent.mkdir(parents=True,exist_ok=True)
        with (objects/relative(row["object"])).open("rb") as src,p.open("xb") as dst:shutil.copyfileobj(src,dst,1<<20)
        p.chmod(row["mode"])
    objects_expected["artifact-manifest.json"]=seen["artifact-manifest.json"]
    need(objects_expected==seen and len(seen)==1+e["archive_receipt"]["unique_objects"],"complete exact physical objects")
    wanted={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in logical.items()}
    need(files(destination)==wanted,"all newly restored full logical files independently read")
    old=loads(read(destination/"admission/ORIGINAL_ARCHIVE_MANIFEST.json"))
    old_wanted={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in old["files"].items()}
    need(len(old_wanted)==44786 and sum(v["bytes"] for v in old_wanted.values())==2581124108 and
         files(destination/"original")==old_wanted,"all original failed files retained byte/mode exact")
    need(pin(read(destination/"recovery-source/RECOVERY_SOURCE.json"))["sha256"]==e["reader_source_sha256"] and
         pin(read(destination/"original/source/SOURCE.json"))["sha256"]==e["original_source_sha256"],
         "both complete immutable source roots")
    report.parent.mkdir(parents=True,exist_ok=True)
    (report.parent/"ARCHIVE_MANIFEST.json").write_bytes(manifest_raw)
    result=dict(status="PASS",schema="hepta.audit-record-callable.independent-archive.v1",
        independent_source_sha256=identity,zip=e["zip"],tar=e["tar"],
        logical_files=len(logical),logical_bytes=sum(v["bytes"] for v in logical.values()),
        unique_objects=len(seen)-1,all_objects_and_modes_read=True,all_logical_files_read=True,
        original_files_unchanged=44786,original_bytes_unchanged=2581124108,
        original_status="FAIL",native_or_rust_executions=0,public_handler_qualified=False)
    report.write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--destination",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args();restore(a.archive.resolve(strict=True),a.destination.absolute(),a.report.absolute())
