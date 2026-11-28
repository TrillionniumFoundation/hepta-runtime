"""Complete source-bound pure semantic reader; execution is never a fallback."""
import argparse,copy,gzip,io,json,os,sys,time,tarfile,tomllib,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from reader_common import read,loads,encoded,pin,require,source
import read_producer,read_pairs,read_trace,read_native,read_outer
import legacy_build
from read_only_guard import guarded
def prepare(bundle):
    source()
    # Load source-only AST/proof dependencies before installing the fixed guard.
    original=read_producer.prepare_source(bundle/"source")
    build=legacy_build.prepare(bundle/"retained")
    gzip.decompress(gzip.compress(b""));json.loads("{}");tomllib.loads("x=1\n")
    with tarfile.open(fileobj=io.BytesIO(gzip.compress(bytes(1024))),mode="r:gz"):pass
    return dict(bundle=bundle,original=original,build=build)
def verify(bundle,prepared):
    identity=source();require(prepared["bundle"]==bundle,"prepared exact relocated capture root")
    admission=legacy_build.verify(bundle/"retained",prepared["build"])
    producer=read_producer.verify(bundle,prepared["original"],admission)
    m=producer["metadata"];groups=[];all_turns=0;all_private=0;full_buffers=0;full_wires=0
    for group in producer["domain"]["groups"]:
        cases=[c for c in producer["domain"]["cases"]if c["group"]==group]
        folder=bundle/"run"/("paired-"+group)
        pair=read_pairs.verify(folder,m,producer["processes"]["paired-"+group],cases,producer["producer"])
        traces=[read_trace.verify(folder/"roles"/name,role,pair["commands"])
            for name,role in zip(read_pairs.ROLES,pair["roles"])]
        outer=[read_outer.verify(trace,pair["commands"],role)for trace,role in zip(traces,pair["roles"])]
        kernel=read_trace.compare(traces,cases)
        native=[read_native.verify(folder/"roles"/name/"capture",pair,i,m,admission,traces[i])
            for i,name in enumerate(read_pairs.ROLES[:2])]
        read_pairs.exact(native[0]["turns"],native[1]["turns"],"all actual HIA/native call counts unchanged without observer")
        require(native[0]["private_owner_calls"]==native[1]["private_owner_calls"],"all private original callback calls retained without observer")
        all_turns+=native[0]["entries"];all_private+=native[0]["private_owner_calls"]
        full_buffers+=sum(n["full_buffer_bytes"]for n in native);full_wires+=pair["summary"]["complete_wire_bytes"]
        groups.append(dict(pair=pair["summary"],kernel=kernel,native=native,outer=outer))
    return dict(status="COMPLETE_WATCHER_SEMANTIC_READ_PASS",source_manifest_sha256=identity,
        producer_source_sha256=producer["source_sha256"],build=admission,producer=producer["summary"],
        cases=58,operations=984,groups=groups,application_processes=39,complete_buffer_bytes=full_buffers,
        complete_wire_bytes=full_wires,native_method_turns_per_role=all_turns,private_owner_calls_per_role=all_private,
        original_module=pin(read(bundle/"source/reference/namespace_version.rs.txt")),
        reader_native_executions=0,reader_rust_executions=0,reader_application_executions=0,
        readonly_physical_controls_pending=True,namespace_version_qualified=False,public_handler_qualified=False,
        whole_runtime_replaced=False)
def run(bundle,output):
    state=prepare(bundle);m=loads(read(bundle/"run/CAPTURE.json"));started=time.monotonic()
    result=guarded(lambda:verify(bundle,state),roots=[bundle,ROOT],
        foreign_path=str(Path(m["producer_root"])/"CAPTURE.json"))
    require(time.monotonic()-started<=180,"unchanged whole pure-reader deadline")
    # Explicit CLI report output is outside the guarded reader and input tree.
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(encoded(result))
    print(encoded(dict(status=result["evidence"]["status"],elapsed_seconds=time.monotonic()-started,
        cases=58,operations=984,guard_probes=len(result["probes"]),files=len(result["before"]),
        complete_buffer_bytes=result["evidence"]["complete_buffer_bytes"],reader_native_or_rust_executions=0)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--bundle",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.bundle.resolve(strict=True),a.output.absolute())
