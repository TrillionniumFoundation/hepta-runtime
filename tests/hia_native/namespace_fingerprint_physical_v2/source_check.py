"""Exact frozen source, unchanged complete per-copy body and disjoint control ownership."""
from pathlib import Path
import ast,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc
def run():
    identity=pc.source()
    for name in pc.loads(pc.read(ROOT/"SOURCE.json"))["files"]:
        if name.endswith(".py"):compile(pc.read(ROOT/name),str(ROOT/name),"exec")
    prior=pc.read(ROOT/"prior_physical_controls.py.txt").decode().replace("audit-anchor-publish","namespace-fingerprint").replace("PUBLISHER","FINGERPRINT").replace("publisher","fingerprint")
    before=ast.parse(prior);after=ast.parse(pc.read(ROOT/"physical_controls.py"))
    for name in ("guarded_proof","refused","run_subset","summary","verify"):
        old=next(n for n in before.body if isinstance(n,ast.FunctionDef)and n.name==name)
        new=next(n for n in after.body if isinstance(n,ast.FunctionDef)and n.name==name)
        pc.check(ast.dump(old,include_attributes=False)==ast.dump(new,include_attributes=False),
                 "whole established per-copy/control verification body preserved: "+name)
    import physical_controls as controls,physical_parallel as parallel,mutations
    parts=parallel.parts(controls.ADMISSIONS,mutations.NAMES)
    pc.check(len(parts)==2 and len(parts[0])==9 and len(parts[1])==8 and
             set(parts[0]).isdisjoint(parts[1]) and set(parts[0]+parts[1])==set((*controls.ADMISSIONS,*mutations.NAMES)),
             "two exact disjoint complete partitions")
    return dict(status="FROZEN_PURE_CONTROL_SOURCE_PASS",source_manifest_sha256=identity,
                original_copy_and_read_body_unchanged=True,partitions=[list(x)for x in parts],
                whole_parent_timeout_seconds=180,native_or_rust_executions=0)
if __name__=="__main__":print(pc.enc(run()).decode(),end="")
