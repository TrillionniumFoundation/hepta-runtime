"""Only read the uploaded complete source/capture; no semantic executable is loaded."""
import argparse,hashlib,io,json,tarfile,tomllib
from pathlib import Path
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pin(x):return dict(bytes=len(x),sha256=hashlib.sha256(x).hexdigest())
def run(root,out):
    semantic=root/"run/semantic";source=root/"source"
    packages=[p for p in tomllib.loads((source/"reference/Cargo.lock").read_text())["package"] if "source" in p]
    missing={};count=0;total=0
    for p in packages:
        name=p["name"]+"-"+p["version"];raw=(semantic/"crates"/(name+".crate")).read_bytes()
        assert pin(raw)["sha256"]==p["checksum"]
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tar:
            for m in tar:
                if m.isdir():continue
                assert m.isfile() and m.name.startswith(name+"/")
                relative=m.name[len(name)+1:];body=tar.extractfile(m).read();assert len(body)==m.size
                vendor=semantic/"vendor"/name/relative
                if not vendor.exists():missing.setdefault(name,{})[relative]=pin(body)
                else:assert vendor.read_bytes()==body
                count+=1;total+=len(body)
    entropy=json.loads((source/"reference/ENTROPY_SOURCE.json").read_bytes())
    tag_members={}
    for row in entropy["members"]:
        rel=row["path"].split("getrandom-0.2.17/",1)[1].removesuffix(".txt")
        declared=(source/row["path"]).read_bytes();actual=(semantic/"vendor/getrandom-0.2.17"/rel).read_bytes()
        tag_members[rel]=dict(declared=pin(declared),actual=pin(actual),equal=declared==actual)
    assert all(r["equal"] for r in tag_members.values())
    (out/"ring-rand.rs.txt").write_bytes((semantic/"vendor/ring-0.17.14/src/rand.rs").read_bytes())
    domain=json.loads((source/"DOMAIN.json").read_bytes());results=[]
    for group in domain["groups"]:
        origin=json.loads((semantic/("original-"+group)/"OBSERVATIONS.json").read_bytes())
        for mode in ("observed","off"):
            folder=semantic/("native-"+mode+"-"+group)
            native=json.loads((folder/"OBSERVATIONS.json").read_bytes());assert len(native)==len(origin)
            for a,b in zip(native,origin):assert (a["case"],a["step"],a["initial_hex"],a["semantic_hex"])==(b["case"],b["step"],b["initial_hex"],b["semantic_hex"])
            report=json.loads((folder/"NATIVE.json").read_bytes())
            results.append(dict(group=group,mode=mode,cases=report["cases"],operations=len(native),
                                counts=report["counts"],outer_calls=report["outer_calls"]))
    samples={}
    for group in ("normal","enosys","eperm","entropy-eio","unlink-eacces"):
        raw=(semantic/("original-"+group+".strace")).read_text()
        # Complete lines only; this is diagnostic context, never used as the implementation.
        samples[group]=[x for x in raw.splitlines() if "getrandom(" in x or "poll(" in x or
                        "linkat(" in x or "unlinkat(" in x][:30]
    result=dict(status="DIAGNOSTIC_SOURCE_AND_FULL_RESULT_READ_PASS",source_members=count,source_bytes=total,
                original_packages=len(packages),vendor_omissions=missing,entropy_tag_matches_locked_crate=tag_members,
                cohorts=results,complete_original_native_operations=2*domain["operation_count"],
                sample_actual_lines=samples,native_or_rust_executions=0,
                strong_semantic_qualification_pending=True,public_handler_qualified=False)
    (out/"RESULT.json").write_bytes(enc(result));print("RESULT_BEGIN");print(enc(result).decode(),end="");print("RESULT_END")
    print("RING_SOURCE_BEGIN");print((out/"ring-rand.rs.txt").read_text(),end="");print("RING_SOURCE_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False);run(a.root,a.output)
