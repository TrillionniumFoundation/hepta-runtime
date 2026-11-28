"""Own only new-image captured-buffer replay processes; never replay old applications."""
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,require,source
from comparison_commands import commands
from process import Recorder,environment
def run(workspace):
    identity=source();out=workspace/"run";out.mkdir()
    env,binding=environment(os.environ)
    meta=dict(schema="hepta.namespace-watcher.fixed-eight-capture-comparison.v1",
        source_manifest_sha256=identity,source_root=str(ROOT),output_root=str(out),
        workspace_root=str(workspace),prior_root=str(workspace/"prior"),fresh_root=str(workspace/"fresh"),
        python=str(Path(sys.executable).resolve(strict=True)),pid=os.getpid(),parent_pid=os.getppid(),
        pgid=os.getpgrp(),environment=binding,old_native_applications=0,rust_executions=0)
    rows=commands(meta);meta["commands"]=rows;(out/"RUN.json").write_bytes(encoded(meta))
    recorder=Recorder(ROOT,out/"processes",env)
    try:
        for row in rows:
            recorder.run(row["name"],row["argv"],cwd=row["cwd"],timeout=row["timeout"])
            print(row["name"]+" PASS",flush=True)
        guard=loads(read(out/"processes/complete-read.stdout"))
        require(source()==identity,"whole comparison source unchanged")
        gate=dict(status="COMPLETE_CAPTURED_FIXED_EIGHT_COMPARISON_PASS",source_manifest_sha256=identity,
            comparison=guard["evidence"],guard_probes=len(guard["probes"]),processes=recorder.records,
            old_native_applications=0,rust_executions=0,watcher_qualified=False,
            namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
        (out/"GATE.json").write_bytes(encoded(gate))
        print(encoded(gate).decode(),end="")
    finally:
        for row in recorder.records:
            path=out/"processes"/row["stderr"]["file"]
            if path.is_file()and path.stat().st_size:sys.stderr.write(path.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--workspace",type=Path,required=True)
    a=p.parse_args();run(a.workspace.resolve(strict=True))
