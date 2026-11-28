"""Exact dependency-reader correction; original producer evidence stays immutable."""
from pathlib import Path
import argparse,importlib.util,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import recovery_common as rc

def prepare(original):
    identity=rc.source()
    revision=rc.loads(rc.read(ROOT/"READER_REVISION.json"))
    sys.path.insert(0,str(original))
    import common,reader_cli,read_capture,read_dependencies,reader_controls
    rc.check(common.ROOT==original and common.source()==revision["source_sha256"],"exact original producer source")
    rc.check(rc.pin(rc.read(original/"read_dependencies.py"))=={k:revision["delta"]["before"][k] for k in ("bytes","sha256")},"exact original dependency reader")
    fix=ROOT/"reader_dependency_fix.py"
    rc.check(rc.pin(rc.read(fix))=={k:revision["delta"]["after"][k] for k in ("bytes","sha256")},"exact frozen dependency reader successor")
    spec=importlib.util.spec_from_file_location("anchor_dependency_reader_successor",fix)
    corrected=importlib.util.module_from_spec(spec);spec.loader.exec_module(corrected)
    read_dependencies.dependencies=corrected.dependencies
    rc.check(read_capture.read_dependencies is read_dependencies,"one exact module call edge")
    reader_cli.prepare()
    # Every physical control guards both unchanged producer source and this
    # explicitly separate reader source. No capture/source file is rewritten.
    reader_controls.roots=lambda folder,prepared=None:[folder,common.ROOT,ROOT]
    rc.check(rc.source()==identity,"stable prepared recovery source")
    return identity,reader_cli,read_capture,reader_controls

def verify(original,capture,controls=None):
    identity,reader_cli,read_capture,reader_controls=prepare(original)
    roots=[capture,original,ROOT]+([] if controls is None else [controls])
    def operation():
        rc.check(rc.source()==identity,"all frozen recovery bytes inside guard")
        value=read_capture.verify(capture)
        if controls is not None:value=dict(value,controls=reader_controls.verify(capture,controls,value))
        return dict(original_source_sha256=value["source_manifest_sha256"],recovery_source_sha256=identity,
            original_producer_status="FAIL",complete_evidence=value,native_executions=0,rust_executions=0)
    foreign=str(capture.parent/"not-admitted/CAPTURE.json")
    return reader_cli.read_only_guard.guarded(operation,roots=roots,foreign_path=foreign)

def run_controls(original,capture,output):
    identity,reader_cli,read_capture,reader_controls=prepare(original)
    value=reader_controls.run(capture,output)
    rc.check(rc.source()==identity,"stable complete recovery control source")
    return value

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--phase",choices=("semantic","controls","final"),required=True)
    p.add_argument("--original-source",type=Path,required=True);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--controls",type=Path);p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args();original=a.original_source.resolve(strict=True);capture=a.capture.resolve(strict=True)
    if a.phase=="controls":
        rc.check(a.controls is not None,"explicit controls output")
        result=run_controls(original,capture,a.controls.absolute())
    else:
        rc.check((a.phase=="final")==bool(a.controls),"exact phase controls")
        result=verify(original,capture,None if a.controls is None else a.controls.resolve(strict=True))
    a.receipt.write_bytes(rc.enc(result))
    if a.phase=="controls":summary=result
    else:summary={k:v for k,v in result.items() if k not in ("before","after")}
    print(rc.enc(summary).decode(),end="")
