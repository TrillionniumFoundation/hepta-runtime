"""Freeze every actual source and domain byte before any application is launched."""
import ast,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,require,pin
from protocol import domain
def verify():
    identity=source();d=domain();p=loads(read(ROOT/"RUN_PLAN.json"));deps=loads(read(ROOT/"DEPENDENCIES.json"))
    require(p["schema"]=="hepta.namespace-versions.actual-plan.v1"and p["groups"]==d["groups"]
        and p["application_seconds"]==60 and p["reader_seconds"]==180 and p["workflow_minutes"]==15
        and p["completed_or_unknown_application_replays"]==0,"entire complete actual execution plan")
    require(deps["native_image"]==dict(bytes=415337,sha256="389a70f890d88b5f0abd828798b6a57cb08064d7e3ec366f01f720e8d1087da7")
        and deps["original_binary"]==dict(bytes=12100008,sha256="3acd7ab13f39b1e8c9e7c2094723848e4fadaff4dfcbbe018f81e026ab739836")
        and deps["application_replays"]==0,"exact fixed compiled original/native application identities")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    for name in("native_child.py","versions_loader.py","capture_native.py"):
        tree=ast.parse(read(ROOT/name))
        require(not any(isinstance(n,ast.Constant)and isinstance(n.value,(str,bytes))and "HNVSAK01"in str(n.value)for n in ast.walk(tree)),
            "actual fixtures cannot manufacture namespace effect ACKs")
    return dict(status="NAMESPACE_VERSIONS_ACTUAL_SOURCE_PASS",source_manifest_sha256=identity,groups=len(d["groups"]),
        source_operations=d["operations"],parallel_calls=d["parallel_calls"],native_application_calls=0,original_application_calls=0)
if __name__=="__main__":print(encoded(verify()).decode(),end="")
