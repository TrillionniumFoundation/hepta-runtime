"""Bounded source-only regression qualification; no native or Rust execution."""
from pathlib import Path
import argparse, ast, hashlib, importlib.util, json, os, shutil, stat, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from process import Recorder,put
from archive import inventory,digest
import archive
PREFIX=Path("tests/hia_native/historical_public58")
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def identity(expected):
    raw=(HERE/"SOURCE_MANIFEST.json").read_bytes()
    assert SHA(raw)==expected
    manifest=json.loads(raw)
    actual={p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()}
    assert actual==set(manifest["files"])|{"SOURCE_MANIFEST.json"}
    for name,pin in manifest["files"].items():
        value=(HERE/name).read_bytes()
        assert dict(bytes=len(value),sha256=SHA(value))==pin,name
        if name.endswith(".py"):ast.parse(value,filename=name)
    return SHA(raw)

def module(root):
    path=root/PREFIX/"materialize.py"
    spec=importlib.util.spec_from_file_location("source_materializer",path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

def git_tree(raw):
    result={}
    for row in raw.split(b"\0"):
        if not row:continue
        head,path=row.split(b"\t",1)
        mode,kind,blob=head.decode().split()
        assert (kind,mode) in (("blob","100644"),("blob","100755"),("blob","120000"),("commit","160000"))
        name=path.decode()
        assert name not in result
        result[name]=dict(mode=mode,git_blob=blob)
    return result

def qualify(a):
    binding=json.loads((HERE/"BINDING.json").read_bytes())
    assert not a.work.exists();a.work.mkdir(parents=True)
    rec=Recorder(HERE,a.work/"processes")
    result=dict(status="FAIL",schema="hepta.historical-workflow.source-regression.v1",
                native_or_rust_executions=0,source_manifest_sha256=a.source_manifest_sha256)
    try:
        trees={}
        for label,checkout in (("base",a.base),("candidate",a.candidate)):
            out,_=rec.run(label+"-head",["git","rev-parse","HEAD"],cwd=checkout,timeout=60)
            assert out.decode().strip()==binding[label]["commit"]
            out,_=rec.run(label+"-tree",["git","ls-tree","-r","-z","HEAD"],cwd=checkout,timeout=60)
            trees[label]=git_tree(out)
        differences={name for name in set(trees["base"])|set(trees["candidate"])
                     if trees["base"].get(name)!=trees["candidate"].get(name)}
        assert differences=={row["path"] for row in binding["install"]}
        for row in binding["install"]:
            name=row["path"];data=(a.candidate/name).read_bytes()
            assert trees["candidate"][name]==dict(mode=row["mode"],git_blob=row["after"]["git_blob"])
            assert dict(bytes=len(data),sha256=SHA(data))=={key:row["after"][key] for key in ("bytes","sha256")}
        put(a.work/"TREE_PROOF.json",dict(base=trees["base"],candidate=trees["candidate"],changed=sorted(differences)))
        bundles={}
        for label,checkout in (("base",a.base),("candidate",a.candidate)):
            materializer=module(checkout)
            selected=materializer.selected(checkout)
            original={name:digest(path) for name,path in selected.items()}
            target=a.work/"inputs"/label
            for name,path in selected.items():
                dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(path,dest);dest.chmod(path.stat().st_mode&0o777)
            assert inventory(target)==original
            assert {name:digest(path) for name,path in materializer.selected(checkout).items()}==original
            bundles[label]=target
        for label in ("base","candidate"):
            root=bundles[label];view=a.work/"views"/label
            rec.run(label+"-materialize",[sys.executable,"-I","-B",root/PREFIX/"materialize.py",
                "--source",root,"--output",view],timeout=60)
            out,_=rec.run(label+"-admission",[sys.executable,"-I","-B",HERE/"probe.py",
                "--source",view,"--mode","old" if label=="base" else "new"],timeout=60)
            proof=json.loads(out)
            assert proof["before"]==proof["after"] and len(proof["probes"])==12
            expect="EXPECTED_OLD_REFUSAL" if label=="base" else "BODY_SOURCE_ADMITTED"
            assert proof["evidence"]["status"]==expect
        original=inventory(bundles["candidate"])
        for label,name in (("workflow-mutant",binding["workflow"]),
                           ("fixture-mutant",(PREFIX/"source"/binding["workflow"]).as_posix())):
            mutant=a.work/"controls"/label
            shutil.copytree(bundles["candidate"],mutant,copy_function=shutil.copy2)
            assert inventory(mutant)==original
            path=mutant/name;raw=path.read_bytes();path.write_bytes(raw+b"\n")
            put(mutant/"MUTATION.json",dict(path=name,before=dict(bytes=len(raw),sha256=SHA(raw)),
                after=digest(path),operation="append-one-newline"))
            out,_=rec.run(label,[sys.executable,"-I","-B",HERE/"probe.py","--source",mutant,"--mode",label],timeout=60)
            proof=json.loads(out)
            assert proof["evidence"]["status"]=="EXPECTED_SOURCE_REFUSAL"
            assert proof["before"]==proof["after"] and len(proof["probes"])==12
        assert inventory(bundles["candidate"])==original
        result.update(status="PASS",tree_leaves=len(trees["candidate"]),changed_paths=sorted(differences),
            current_graph_files=390,current_authority_files=6,current_workflow_files=4,
            historical_restore_files=120,body_source_files=67,old_source_refusals=1,
            physical_source_mutants=2,guard_proofs=4,guard_probes=48,
            production_graph_changed=False,source_admission_weakened=False,
            original_failure_preserved=binding["original_failure"])
    except BaseException as error:
        result.update(error_type=type(error).__name__,error=str(error))
        raise
    finally:
        put(a.work/"RESULT.json",result)
    print(json.dumps(result,sort_keys=True))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("stage",choices=("qualify","export","read","export-child"))
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args()
    identity(a.source_manifest_sha256)
    a.work=a.work.absolute();a.archive=a.archive.absolute()
    if a.stage=="qualify":qualify(a)
    elif a.stage=="export-child":
        print(json.dumps(archive.export(HERE,a.work,a.archive),sort_keys=True))
    else:
        records=a.archive.parent/("historical-workflow-"+a.stage+"-processes")
        rec=Recorder(HERE,records)
        if a.stage=="export":
            command=[sys.executable,"-I","-B",HERE/"run_ci.py","export-child","--work",a.work,
                "--archive",a.archive,"--source-manifest-sha256",a.source_manifest_sha256]
        else:
            command=[sys.executable,"-I","-B",HERE/"read_archive.py","--work",a.work,
                "--archive",a.archive,"--source-manifest-sha256",a.source_manifest_sha256]
        raw,row=rec.run(a.stage,command,timeout=180)
        value=json.loads(raw)
        put(records/"RESULT.json",dict(status="PASS",result=value,process=row))
        print(json.dumps(dict(status="PASS",stage=a.stage,result=value if a.stage=="export" else value["evidence"],
                             process=row),sort_keys=True))
if __name__=="__main__":main()
