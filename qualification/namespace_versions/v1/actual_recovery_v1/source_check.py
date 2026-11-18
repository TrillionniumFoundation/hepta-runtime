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
    require(deps["native_image"]==dict(bytes=415321,sha256="53217454e0bb1c637bc7decdb698667916af93ac46ac843dea3f0a40ad4c3e05")
        and deps["original_binary"]==dict(bytes=11890224,sha256="1362c9b030d065e4e882a8f8c697501f5aaf90cac77e25e69d3e303f28ebaec8")
        and deps["application_replays"]==0,"exact fixed compiled original/native application identities")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    for name in("native_child.py","versions_loader.py","capture_native.py"):
        tree=ast.parse(read(ROOT/name))
        require(not any(isinstance(n,ast.Constant)and isinstance(n.value,(str,bytes))and "HNVSAK01"in str(n.value)for n in ast.walk(tree)),
            "actual fixtures cannot manufacture namespace effect ACKs")
    return dict(status="NAMESPACE_VERSIONS_ACTUAL_SOURCE_PASS",source_manifest_sha256=identity,groups=len(d["groups"]),
        source_operations=d["operations"],parallel_calls=d["parallel_calls"],native_application_calls=0,original_application_calls=0)
if __name__=="__main__":print(encoded(verify()).decode(),end="")
