"""Admit the complete fixed-eight source successor without native execution."""
import argparse, ast, hashlib, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,require,pin,source
from authoring.author_fixed8 import generate

def check():
    identity=source()
    from source_check import check as original
    require(original()["source_manifest_sha256"]==identity,"all original span and scalar source checks")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    fixed=loads(read(ROOT/"FIXED8.json"))
    before=read(ROOT/"baseline/namespace_watcher.hepta")
    after=read(ROOT/"native/namespace_watcher.hepta")
    require(after==generate(before),"deterministic sole three-function change")
    require(pin(before)=={k:fixed["baseline_owner"][k] for k in ("bytes","sha256")}
        and pin(after)=={k:fixed["owner"][k] for k in ("bytes","sha256")},"both exact owner bytes")
    require(read(ROOT/"native/namespace_watcher.composition.json")==read(ROOT/"FIXED8.json"),"single successor composition identity")
    original_fixed=loads(read(ROOT/"SOURCE_QUALIFIED.json"))
    require(pin(before)=={k:original_fixed["owner"][k] for k in ("bytes","sha256")}
        and pin(read(ROOT/"baseline/namespace_watcher.composition.json"))=={k:original_fixed["composition"][k] for k in ("bytes","sha256")},"original qualified source binding preserved")
    require(pin(read(ROOT/"authoring/namespace_watcher_callable.S.in"))=={k:fixed["unchanged_adapter_template"][k] for k in ("bytes","sha256")},"actual native mechanics unchanged")
    require(pin(read(ROOT/"DOMAIN.json"))=={k:fixed["unchanged_domain"][k] for k in ("bytes","sha256")},"whole unchanged 984-operation domain")
    result=dict(status="FIXED_EIGHT_SOURCE_ONLY_PASS",source_manifest_sha256=identity,
        owner=fixed["owner"],baseline_owner=fixed["baseline_owner"],
        original_spans=original()["original_spans"],unchanged_full_function_asts_pending_symbolic_check=26,
        new_candidate_not_old_image=True,native_or_rust_executions=0,
        watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False)
    return result
if __name__=="__main__":print(encoded(check()).decode(),end="")
