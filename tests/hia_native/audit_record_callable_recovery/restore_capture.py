"""Restore every complete file/mode of the fixed failed capture without replay."""
from pathlib import Path
import argparse,hashlib,io,os,shutil,sys,tarfile,zipfile
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from recovery_common import source,relative,need,pin,read,loads,encoded,files,BASE_SOURCE

ZIP=dict(bytes=156028150,sha256="50dea39e1347a4d3bc18ca6534f872fc5ede0c3d9ddca271b54dfa32442aa9ff")
TAR=dict(bytes=156027265,sha256="ac3b4ecb8d3233138f7327bcc3ca7c7dfd02c1cb6c98112abf4be97ef0599b3b")

def restore(archive,destination,report):
    identity=source()
    need(not destination.exists(),"fresh independent complete relocation")
    raw=read(archive);need(pin(raw)==ZIP,"whole original failed ZIP identity")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(len(z.infolist())==2 and set(z.namelist())==
             {"audit-record-callable.tar.gz","audit-record-callable.tar.gz.json"} and z.testzip() is None,
             "all complete exact ZIP members and CRC")
        packed=z.read("audit-record-callable.tar.gz")
        producer=loads(z.read("audit-record-callable.tar.gz.json"))
    need(pin(packed)==TAR,"whole original failed TAR identity")
    need(producer["status"]=="NO_FINAL_GATE" and
         all(producer[k]==TAR[k] for k in TAR) and
         producer["logical_files"]==44786 and producer["logical_bytes"]==2581124108 and
         producer["unique_objects"]==2593 and producer["source_manifest_sha256"]==BASE_SOURCE and
         producer["all_logical_files_reread"] is True and producer["all_objects_and_modes_reread"] is True,
         "complete original failed exporter receipt")
    destination.mkdir(parents=True,exist_ok=False)
    objects=destination.parent/(destination.name+"-objects");objects.mkdir(exist_ok=False)
    seen={};manifest=None;manifest_raw=None
    with tarfile.open(fileobj=io.BytesIO(packed),mode="r:gz") as tar:
        for item in tar:
            relative(item.name)
            need(item.isfile() and item.name not in seen,"unique ordinary original member")
            with tar.extractfile(item) as stream:body=stream.read()
            need(len(body)==item.size,"complete original TAR member")
            row=dict(**pin(body),mode=item.mode);seen[item.name]=row
            if item.name=="artifact-manifest.json":
                need(item.mode==0o644,"exact original manifest mode")
                manifest_raw=body;manifest=loads(body)
            else:
                need(item.name=="objects/"+row["sha256"]+"-"+format(item.mode,"03o"),
                     "complete original object identity and mode")
                out=objects/relative(item.name);out.parent.mkdir(parents=True,exist_ok=True)
                out.write_bytes(body);out.chmod(item.mode)
    need(manifest["schema"]=="hepta.audit-record-callable.archive.v1" and
         manifest["git_head"]=="f7273eb417e1f90c4e11b0556f7d6c7d2758bd33" and
         manifest["run_id"]=="44061230103" and manifest["source_manifest_sha256"]==BASE_SOURCE and
         manifest["gate"]==dict(status="NO_FINAL_GATE") and manifest["original_rust_replay"]==0 and
         manifest["archive_and_hot_cache_qualified"] is False and manifest["begin_finish_caller_qualified"] is False and
         manifest["public_handler_qualified"] is False and manifest["whole_runtime_replaced"] is False,
         "unchanged failed producer identity, result and qualification boundary")
    logical=manifest["files"]
    need(len(logical)==44786 and sum(x["bytes"] for x in logical.values())==2581124108,
         "complete original logical domain")
    expected={}
    for name,row in logical.items():
        target=destination/relative(name)
        need(set(row)=={"bytes","sha256","mode","object"} and type(row["mode"]) is int and
             row["object"]=="objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),
             "exact original logical object binding")
        identity_row={k:row[k] for k in ("bytes","sha256","mode")}
        need(seen[row["object"]]==identity_row,"every complete original logical file/mode")
        expected[row["object"]]=identity_row
        target.parent.mkdir(parents=True,exist_ok=True)
        with (objects/relative(row["object"])).open("rb") as src,target.open("xb") as dst:
            shutil.copyfileobj(src,dst,1<<20)
        target.chmod(row["mode"])
    expected["artifact-manifest.json"]=seen["artifact-manifest.json"]
    need(expected==seen and len(expected)==2594,"complete exact object set")
    current=files(destination)
    need(current=={name:{k:row[k] for k in ("bytes","sha256","mode")} for name,row in logical.items()},
         "every relocated complete logical file independently reread")
    need(pin(read(destination/"source/SOURCE.json"))["sha256"]==BASE_SOURCE,"same producer source")
    report.parent.mkdir(parents=True,exist_ok=True)
    (report.parent/"ORIGINAL_ARCHIVE_MANIFEST.json").write_bytes(manifest_raw)
    result=dict(schema="hepta.audit-record-callable.recovery-archive-admission.v1",status="PASS",
        reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
        original_head=manifest["git_head"],original_run=44061230103,original_status="FAIL",
        original_zip=ZIP,original_tar=TAR,logical_files=44786,logical_bytes=2581124108,
        unique_objects=2593,all_original_files_and_modes_read=True,
        original_failure_preserved=True,native_or_rust_executions=0)
    report.write_bytes(encoded(result))
    print(encoded(result).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--destination",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args();restore(a.archive.resolve(strict=True),a.destination.absolute(),a.report.absolute())
