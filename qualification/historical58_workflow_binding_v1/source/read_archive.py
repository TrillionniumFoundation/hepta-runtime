"""Independent inert reader of every source, stream and complete archive object."""
from pathlib import Path
import argparse, gzip, hashlib, json, stat, sys, tarfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from archive import digest,inventory
from run_ci import identity,git_tree
import read_only_guard as guard

def read(a):
    binding=json.loads((HERE/"BINDING.json").read_bytes())
    assert identity(a.source_manifest_sha256)==a.source_manifest_sha256
    objects={};manifest=None;manifest_pin=None
    with tarfile.open(a.archive,"r|gz") as tar:
        while member:=tar.next():
            name=Path(member.name)
            assert member.isfile() and not name.is_absolute() and ".." not in name.parts
            assert member.mode in (0o600,0o644,0o755)
            with tar.extractfile(member) as stream:
                if member.name=="artifact-manifest.json":
                    assert manifest is None and member.mode==0o644
                    raw=stream.read();assert len(raw)==member.size
                    manifest=json.loads(raw)
                    manifest_pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=member.mode)
                else:
                    assert len(name.parts)==2 and name.parts[0]=="objects"
                    assert member.name not in objects
                    value=dict(bytes=member.size,sha256=hashlib.file_digest(stream,"sha256").hexdigest(),mode=member.mode)
                    assert member.name=="objects/"+value["sha256"]+"-"+format(value["mode"],"03o")
                    objects[member.name]=value
            tar.members.clear()
    assert manifest is not None
    assert manifest["schema"]=="hepta.historical-workflow.complete-deduplicated-archive.v1"
    assert manifest["semantic_reexecutions"]==0 and manifest["whole_runtime_replaced"] is False
    actual={}
    for prefix,root in (("qualification-source",HERE),("evidence",a.work)):
        actual.update({prefix+"/"+name:value for name,value in inventory(root).items()})
    assert set(actual)==set(manifest["files"])
    referenced=set()
    for name,row in manifest["files"].items():
        path=Path(name);assert not path.is_absolute() and ".." not in path.parts
        assert actual[name]=={key:row[key] for key in ("bytes","sha256","mode")}==objects[row["object"]]
        referenced.add(row["object"])
    assert referenced==set(objects)
    receipt=json.loads(a.archive.with_suffix(a.archive.suffix+".json").read_bytes())
    assert {key:receipt[key] for key in ("bytes","sha256","mode")}==digest(a.archive)
    assert receipt["logical_files"]==len(actual)
    assert receipt["logical_bytes"]==sum(row["bytes"] for row in actual.values())
    assert receipt["unique_objects"]==len(objects)
    assert receipt["unique_bytes"]==sum(row["bytes"] for row in objects.values())
    result=json.loads((a.work/"RESULT.json").read_bytes())
    assert result["status"]=="PASS" and result["body_source_files"]==67
    assert result["guard_probes"]==48 and result["physical_source_mutants"]==2
    assert result["current_graph_files"]==390 and result["historical_restore_files"]==120
    assert result["source_manifest_sha256"]==a.source_manifest_sha256
    assert result["original_failure_preserved"]==binding["original_failure"]
    records=json.loads((a.work/"processes/processes.json").read_bytes())
    expected=["base-head","base-tree","candidate-head","candidate-tree","base-materialize","base-admission",
              "candidate-materialize","candidate-admission","workflow-mutant","fixture-mutant"]
    assert [row["name"] for row in records]==expected
    all_probes=0
    for row in records:
        assert row["completed"] and not row["timed_out"] and row["exit_code"]==0
        assert row["timeout_seconds"]==60 and row["elapsed_seconds"]<=60
        assert row["pid"]==row["pgid"] and row["pid"]>0
        for kind in ("stdout","stderr"):
            path=a.work/"processes"/row[kind]["file"]
            value=digest(path)
            assert {key:value[key] for key in ("bytes","sha256")}=={key:row[kind][key] for key in ("bytes","sha256")}
        if row["name"] in ("base-admission","candidate-admission","workflow-mutant","fixture-mutant"):
            proof=json.loads((a.work/"processes"/row["stdout"]["file"]).read_bytes())
            assert proof["before"]==proof["after"] and len(proof["probes"])==12
            assert proof["reader_writes"]==proof["native_or_rust_executions"]==0
            all_probes+=len(proof["probes"])
            if row["name"]=="base-admission":
                assert proof["evidence"]["status"]=="EXPECTED_OLD_REFUSAL"
            elif row["name"]=="candidate-admission":
                assert proof["evidence"]["status"]=="BODY_SOURCE_ADMITTED"
            else:assert proof["evidence"]["status"]=="EXPECTED_SOURCE_REFUSAL"
    assert all_probes==48
    tree_proof=json.loads((a.work/"TREE_PROOF.json").read_bytes())
    for label in ("base","candidate"):
        actual_tree=git_tree((a.work/"processes"/(label+"-tree.stdout")).read_bytes())
        assert actual_tree==tree_proof[label]
        assert (a.work/"processes"/(label+"-head.stdout")).read_text().strip()==binding[label]["commit"]
    changed={name for name in set(tree_proof["base"])|set(tree_proof["candidate"])
             if tree_proof["base"].get(name)!=tree_proof["candidate"].get(name)}
    assert changed==set(tree_proof["changed"])=={row["path"] for row in binding["install"]}
    return dict(schema="hepta.historical-workflow.independent-archive-read.v1",status="PASS",
        source_manifest_sha256=a.source_manifest_sha256,archive=digest(a.archive),
        logical_files=len(actual),logical_bytes=sum(row["bytes"] for row in actual.values()),
        unique_objects=len(objects),unique_bytes=sum(row["bytes"] for row in objects.values()),
        tar_members=len(objects)+1,processes=len(records),retained_guard_probes=all_probes,
        changed_paths=sorted(changed),current_graph_files=390,body_source_files=67,
        historical_restore_files=120,original_failure_preserved=True,
        native_or_rust_executions=0,reader_writes=0,whole_runtime_replaced=False)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();a.work=a.work.resolve(strict=True);a.archive=a.archive.resolve(strict=True)
    identity(a.source_manifest_sha256)
    proof=guard.guarded(lambda:read(a),roots=[HERE,a.work,a.archive.parent],foreign_path=Path("/etc/passwd"))
    print(json.dumps(proof,sort_keys=True,indent=2,allow_nan=False))
if __name__=="__main__":main()
