"""Read complete independent-proof ZIPs; execute no captured code."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, sys, urllib.request, zipfile

def pin_bytes(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def write(path,value):
    with path.open("x",encoding="utf-8") as stream:
        json.dump(value,stream,sort_keys=True,indent=2,allow_nan=False);stream.write("\n")

def main():
    config=Path(sys.argv[1]);out=Path(sys.argv[2])
    assert not out.exists();out.mkdir(parents=True)
    specs=json.loads(config.read_bytes());all_reports=[]
    for spec in specs:
        archive=out/(str(spec["id"])+".zip")
        with urllib.request.urlopen(spec["url"],timeout=60) as response,archive.open("xb") as stream:
            digest=hashlib.sha256();size=0
            while data:=response.read(1<<20):
                stream.write(data);digest.update(data);size+=len(data)
        assert {"bytes":size,"sha256":digest.hexdigest()}=={k:spec[k] for k in ("bytes","sha256")}
        physical={}
        with zipfile.ZipFile(archive) as zipped:
            assert len(zipped.namelist())==len(set(zipped.namelist()))
            assert zipped.testzip() is None
            for item in zipped.infolist():
                p=PurePosixPath(item.filename.rstrip("/"))
                assert not p.is_absolute() and all(x not in ("",".","..") for x in p.parts)
                mode=item.external_attr>>16
                assert stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR)
                if item.is_dir():continue
                with zipped.open(item) as stream:
                    digest=hashlib.sha256();count=0
                    while data:=stream.read(1<<20):digest.update(data);count+=len(data)
                assert count==item.file_size
                physical[item.filename]={"bytes":count,"sha256":digest.hexdigest(),"zip_mode":mode,"crc32":item.CRC}
            def only(suffix):
                names=[n for n in physical if n==suffix or n.endswith("/"+suffix)]
                assert len(names)==1,(suffix,names)
                return names[0]
            rn=only("READBACK.json");gn=only("READONLY.json");sn=only("SOURCE.json")
            report=json.loads(zipped.read(rn));guard=json.loads(zipped.read(gn))
            assert report["status"]=="COMPLETE_EXISTING_ROLE_ARCHIVES_AND_PURE_READER_PASS"
            assert report["producer_head"]=="d397daea2c098746b47e88efa0cb566c6ef71103"
            assert report["producer_run"]==43979626193
            assert report["readonly"]=={k:physical[gn][k] for k in ("bytes","sha256")}
            assert report["physical_guard_probes"]==len(guard["probes"])==11
            assert guard["before"]==guard["after"] and report["unchanged_entries"]==len(guard["before"])
            assert guard["native_or_rust_executions"]==guard["reader_writes"]==0
            assert report["native_or_rust_reader_executions"]==report["reader_writes"]==0
            for key in ("before","after"):
                actual=hashlib.sha256(json.dumps(guard[key],sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
                assert actual==report[key+"_sha256"]
            assert guard["evidence"]["status"]==report["qualification_status"]
            assert report["full_sdk_qualified"] is False and report["full_async_qualified"] is False
            assert report["production_activated"] is False and report["old_stack_removed"] is False
            source=json.loads(zipped.read(sn));prefix=sn.removesuffix("SOURCE.json")
            assert report["source"]=={k:physical[sn][k] for k in ("bytes","sha256")}
            for name,identity in source["files"].items():
                assert identity=={k:physical[prefix+name][k] for k in ("bytes","sha256")}
            for label,row in report["artifact_inventories"].items():
                candidates=[n for n in physical if n.endswith("/"+label+"/capture/artifact-manifest.json")]
                assert len(candidates)==1,(label,candidates)
                name=candidates[0];assert row["manifest"]=={k:physical[name][k] for k in ("bytes","sha256")}
                inventory=json.loads(zipped.read(name))
                assert inventory["label"]==label and inventory["source_manifest_sha256"]==row["artifact"]["source_manifest_sha256"]
                assert len(inventory["files"])+1==row["members"]
                assert sum(x["bytes"] for x in inventory["files"].values())+physical[name]["bytes"]==row["logical_bytes"]
                assert len(inventory["directories"])==row["directories"]
                source_rows={n.removeprefix("ci-package/"):v for n,v in inventory["files"].items() if n.startswith("ci-package/")}
                assert len(source_rows)==row["source_files"]==2113
                assert source_rows["wire/reference/read_only_guard.py"]["sha256"]=="7c45f0610e28742fe73323fb7c133ee3e04e5e41f4ea77a815b516e059849a1b"
            summary={"artifact":{k:spec[k] for k in ("id","name","bytes","sha256")},
                     "role":report["role"],"full_proof_zip_members":len(physical),
                     "full_proof_zip_logical_bytes":sum(x["bytes"] for x in physical.values()),
                     "complete_captured_archives":report["artifact_inventories"],
                     "readonly_report":report,"native_or_rust_executed":False,
                     "scope":"All proof ZIP bytes read locally; underlying complete capture bytes were read in the pinned independent CI.",
                     "all_proof_members":physical}
            write(out/(str(spec["id"])+".json"),summary);all_reports.append(summary)
            print(json.dumps({"id":spec["id"],"role":report["role"],"members":len(physical),"unchanged_entries":report["unchanged_entries"],"status":"COMPLETE_PROOF_ZIP_READBACK_PASS"}),flush=True)
    final={"schema":"hepta.public111.independent-proof-local-readback.v1","status":"PASS",
           "reports":all_reports,"native_or_rust_executed":False,"captured_readers_executed_locally":False}
    write(out/"COMPLETE.json",final)
if __name__=="__main__":main()
