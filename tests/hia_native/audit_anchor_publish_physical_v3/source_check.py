"""Pure source closure and exact preservation of the original physical control body."""
from pathlib import Path
import ast,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc

def run():
    identity=pc.source()
    for name in pc.loads(pc.read(ROOT/"SOURCE.json"))["files"]:
        if name.endswith(".py"):compile(pc.read(ROOT/name),str(ROOT/name),"exec")
    before=ast.parse(pc.read(ROOT/"prior_physical_controls.py.txt"))
    after=ast.parse(pc.read(ROOT/"physical_controls.py"))
    old_run=next(n for n in before.body if isinstance(n,ast.FunctionDef) and n.name=="run")
    new_run=next(n for n in after.body if isinstance(n,ast.FunctionDef) and n.name=="run_subset")
    old_loop=next(n for n in old_run.body if isinstance(n,ast.For))
    new_loop=next(n for n in new_run.body if isinstance(n,ast.For))
    pc.check(ast.dump(ast.Module(body=old_loop.body,type_ignores=[]),include_attributes=False)==
             ast.dump(ast.Module(body=new_loop.body,type_ignores=[]),include_attributes=False),
             "complete original per-copy physical control body unchanged")
    for name in ("guarded_proof","refused","summary"):
        old=next(n for n in before.body if isinstance(n,ast.FunctionDef) and n.name==name)
        new=next(n for n in after.body if isinstance(n,ast.FunctionDef) and n.name==name)
        pc.check(ast.dump(old,include_attributes=False)==ast.dump(new,include_attributes=False),
                 "complete original helper unchanged: "+name)
    old_verify=next(n for n in before.body if isinstance(n,ast.FunctionDef) and n.name=="verify")
    new_verify=next(n for n in after.body if isinstance(n,ast.FunctionDef) and n.name=="verify")
    old_loop=next(n for n in old_verify.body if isinstance(n,ast.For))
    new_loop=next(n for n in new_verify.body if isinstance(n,ast.For))
    pc.check(ast.dump(old_loop,include_attributes=False)==ast.dump(new_loop,include_attributes=False),
             "entire complete physical mutation verification loop unchanged")
    import physical_controls as controls,physical_parallel as parallel,mutations
    parts=parallel.parts(controls.ADMISSIONS,mutations.NAMES)
    pc.check(len(parts)==2 and len(parts[0])==9 and len(parts[1])==8 and
             set(parts[0]).isdisjoint(parts[1]) and set(parts[0]+parts[1])==set((*controls.ADMISSIONS,*mutations.NAMES)),
             "two exact disjoint complete partitions")
    return dict(status="FROZEN_PURE_CONTROL_SOURCE_PASS",source_manifest_sha256=identity,
                original_copy_body_unchanged=True,original_mutation_reader_loop_unchanged=True,
                partitions=[list(x) for x in parts],whole_parent_timeout_seconds=180,native_or_rust_executions=0)
if __name__=="__main__":print(pc.enc(run()).decode(),end="")
