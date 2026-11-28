"""Complete immutable Watcher engineering capture, no native/original replay."""
import argparse,gzip,math,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import final_common as fc
import read_only_guard as guard

def prepare(restored):
    identity=fc.source();binding=fc.loads(fc.read(ROOT/"PINS.json"))
    archive=restored/"complete";frozen=archive/"source"
    fc.check(fc.pin(fc.read(frozen/"SOURCE.json"))==binding["source_manifests"]["source/SOURCE.json"],
        "exact complete original producer source")
    sys.path.insert(0,str(frozen))
    import common,read_native_probe,read_callable_prepare
    fc.check(common.ROOT==frozen and read_native_probe.ROOT==frozen and
        read_callable_prepare.ROOT==frozen,"only original admitted immutable reader source")
    fc.check(common.source()==binding["source_sha256"],"every original producer source byte")
    gzip.decompress(gzip.compress(b"",mtime=0))
    return identity,binding,archive,common,read_native_probe,read_callable_prepare

def custody(archive,common):
    output=archive/"run";folder=output/"processes"
    rows=common.loads(common.read(folder/"processes.json"))
    names=["source-check","fresh-owner","author-callable","fresh-packer","complete-read","kernel-probe","kernel-read"]
    bounds=[60,900,60,900,180,60,180];exits=[0,0,0,0,0,0,1]
    fc.check(type(rows)is list and [r["name"]for r in rows]==names,"entire original process prefix")
    expected_files={"processes.json"};parent=None;ids=set()
    original_source=rows[0]["cwd"];python=rows[0]["argv"][0]
    old_build=rows[1]["argv"][-1];old_output=str(Path(old_build).parent)
    compiler=rows[1]["argv"][7]
    required=[
        [python,"-I","-B",original_source+"/source_check_callable.py"],
        [python,"-I","-B",original_source+"/build_callable_prepare.py","--phase","owner","--hepta",compiler,"--output",old_output+"/build"],
        [python,"-I","-B",original_source+"/authoring/author_callable.py","--hepta",compiler,"--root",original_source,
            "--owner-image",old_output+"/build/modules/namespace-watcher/module.image.bin","--output",old_output+"/authored"],
        [python,"-I","-B",original_source+"/build_callable_prepare.py","--phase","packer","--hepta",compiler,
            "--output",old_output+"/build","--authored",old_output+"/authored"],
        [python,"-I","-B",original_source+"/read_callable_prepare.py","--build",old_output+"/build","--authored",old_output+"/authored"],
        [python,"-I","-B",original_source+"/native_probe.py","--build",old_output+"/build","--authored",old_output+"/authored","--output",old_output+"/native-probe"],
        [python,"-I","-B",original_source+"/read_native_probe.py","--build",old_output+"/build","--authored",old_output+"/authored","--output",old_output+"/native-probe"]]
    fc.check([r["argv"]for r in rows]==required and all(r["cwd"]==original_source for r in rows),
        "every complete original command, same source and owned build/capture paths")
    for row,name,bound,code in zip(rows,names,bounds,exits):
        fc.check(type(row["timeout_seconds"])is int and row["timeout_seconds"]==bound and
            type(row["exit_code"])is int and row["exit_code"]==code and
            row["timed_out"]is False and row["completed"]is True and row["stdin"]is None and
            type(row["elapsed_seconds"])in(int,float) and math.isfinite(row["elapsed_seconds"]) and
            0<row["elapsed_seconds"]<=bound,"exact original completion and unchanged deadline")
        fc.check(all(type(row[k])is int and row[k]>1 for k in("pid","parent_pid","pgid")) and
            row["pid"]==row["pgid"]!=row["parent_pid"] and row["pid"]not in ids,
            "all actual owned process identities")
        ids.add(row["pid"])
        if parent is None:parent=row["parent_pid"]
        fc.check(row["parent_pid"]==parent,"same actual recorder parent")
        for kind in("stdout","stderr"):
            filename=name+"."+kind;raw=common.read(folder/filename);expected_files.add(filename)
            fc.check(row[kind]==dict(file=filename,**common.pin(raw)),"whole original process stream")
            if kind=="stderr":
                if name=="kernel-read":
                    fc.check(raw.endswith(b"TypeError: Object of type bytes is not JSON serializable\n") and
                        b'read_native_probe.py", line 102' in raw and b'File "/usr/lib/python3.12/json/encoder.py"' in raw,
                        "exact actual report-serialization failure retained")
                else:fc.check(raw==b"","all original producer stderr is empty")
    fc.check(set(common.files(folder))==expected_files,"complete original process stream domain")
    fc.check(common.read(folder/"kernel-read.stdout")==b"","failed JSON reporting emitted no prefix")
    fc.check(common.read(folder/"kernel-probe.stdout")==common.read(output/"native-probe/PROBE.json"),
        "actual native process stdout equals its complete report")
    fc.check(not (output/"GATE.json").exists(),"original failed gate remains absent")
    return rows

def verify(restored):
    identity,binding,archive,common,original,build=prepare(restored)
    def operation():
        fc.check(fc.source()==identity and common.source()==binding["source_sha256"],"both complete source closures inside guard")
        rows=custody(archive,common)
        value=original.verify(archive/"run/build",archive/"run/authored",archive/"run/native-probe")
        fc.check(value["status"]=="COMPLETE_NATIVE_ENGINEERING_READ_PASS","all unchanged original reader checks")
        table=value["libc"]["table"]
        fc.check(type(table)is bytes and len(table)==72 and
            table==struct.pack("<9Q",*(r["pointer"]for r in value["libc"]["bindings"]),0),
            "complete already-verified actual libc table")
        # This is solely a lossless external-report representation. No retained
        # source, original outcome, native frame or actual process is changed.
        value["libc"]=dict(value["libc"],table=dict(**fc.pin(table),hex=table.hex()))
        encoded=fc.enc(value)
        fc.check(fc.loads(encoded)==value,"complete external report JSON round trip")
        build_value=build.verify(archive/"run/build",archive/"run/authored")
        fc.check(common.read(archive/"run/processes/complete-read.stdout")==common.encoded(build_value),
            "actual complete build reader stdout")
        probe=common.loads(common.read(archive/"run/native-probe/PROBE.json"))
        return dict(status="WATCHER_NATIVE_ENGINEERING_READ_RECOVERED",
            source_manifest_sha256=identity,original_source_sha256=binding["source_sha256"],
            original_processes=rows,build=build_value,engineering=value,probe=probe,
            artifact_binding=binding,historical_gate_failure_preserved=True,
            native_or_rust_executions=0,no_kernel_probe_replay=True,
            original_comparison_qualified=False,observer_off_qualified=False,
            complete_watcher_qualified=False,namespace_version_qualified=False,
            archive_store_qualified=False,hot_cache_qualified=False,
            begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    return guard.guarded(operation,roots=[archive,ROOT],foreign_path="/unadmitted-original-producer/source/SOURCE.json")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--restored",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    proof=verify(a.restored.resolve(strict=True));output=a.output.resolve(strict=True)
    (output/"READBACK.json").write_bytes(fc.enc(proof))
    print(fc.enc({k:v for k,v in proof.items()if k not in("before","after")}).decode(),end="")
