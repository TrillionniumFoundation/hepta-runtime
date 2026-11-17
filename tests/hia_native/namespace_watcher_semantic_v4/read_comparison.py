"""Complete read-only captured-buffer join, including immutable uploaded archives."""
import argparse,bz2,copy,encodings.cp437,gzip,io,json,lzma,os,sys,tarfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,pin,read,require,source
from archive_read import verify as verify_archive
from legacy_build import prepare,verify as verify_build
from compare_captured import GROUPS,verify as verify_group
from comparison_commands import commands
from comparison_controls import verify_controls
from read_only_guard import guarded

def verify(workspace,prepared):
    identity=source();out=workspace/"run";fresh=workspace/"fresh";prior=workspace/"prior"
    old_archive=verify_archive(workspace/"inputs/prior.zip",prior,ROOT/"PRIOR-PINS.json")
    new_archive=verify_archive(workspace/"inputs/fresh.zip",fresh,ROOT/"NEW-BUILD-PINS.json")
    build=verify_build(fresh,prepared)
    groups=[verify_group(prior/"complete",fresh/"complete/run/build",out/"groups"/g,g)for g in GROUPS]
    require(sum(r["old_records"]for r in groups)==14196
        and sum(r["old_complete_buffer_bytes"]for r in groups)==6710163328,
        "all eight original complete streams and every original buffer byte retained")
    controls=verify_controls(workspace)
    meta=loads(read(out/"RUN.json"));rows=loads(read(out/"processes/processes.json"))
    require(meta["schema"]=="hepta.namespace-watcher.fixed-eight-capture-comparison.v1"
        and meta["source_manifest_sha256"]==identity and meta["old_native_applications"]==meta["rust_executions"]==0,
        "exact producer source and execution scope")
    expected=commands(meta);require(encoded(meta["commands"])==encoded(expected),"exact full frozen process plan")
    require([r["name"]for r in rows]in([r["name"]for r in expected[:-1]],[r["name"]for r in expected]),
        "all completed actual processes, with only current reader optionally pending")
    seen=set()
    for i,(row,wanted)in enumerate(zip(rows,expected,strict=False)):
        require(row["name"]==wanted["name"] and row["argv"]==wanted["argv"] and row["cwd"]==wanted["cwd"]
            and type(row["timeout_seconds"])is int and row["timeout_seconds"]==wanted["timeout"]
            and type(row["elapsed_seconds"])is float and 0<=row["elapsed_seconds"]<=wanted["timeout"]
            and type(row["pid"])is int and row["pid"]>0 and row["pid"]not in seen
            and row["parent_pid"]==meta["pid"] and row["pgid"]==row["pid"]
            and row["exit_code"]==0 and row["completed"]is True and row["timed_out"]is False
            and row["stdin"]is None,"complete actual bounded process custody")
        seen.add(row["pid"])
        for label in("stdout","stderr"):
            name=row["name"]+"."+label;raw=read(out/"processes"/name)
            require(row[label]==dict(file=name,**pin(raw)),"full actual process stream")
            if label=="stderr":require(raw==b"","no hidden process error")
        stdout=read(out/"processes"/(row["name"]+".stdout"))
        if row["name"]=="build-read":require(stdout==encoded(build),"actual complete build reader stdout")
        elif row["name"].startswith("compare-"):
            group=row["name"][8:];report_raw=read(out/"groups"/group/"RESULT.json");report=loads(report_raw)
            require(stdout==report_raw and report["pid"]==row["pid"] and report["parent_pid"]==meta["pid"]
                and report["pgid"]==row["pgid"] and report["elapsed_seconds"]<=row["elapsed_seconds"],
                "actual new-image child identity and complete stdout")
        elif row["name"]=="reader-controls":
            require(stdout==encoded(controls) and controls["pid"]==row["pid"] and controls["parent_pid"]==meta["pid"]
                and controls["pgid"]==row["pgid"] and controls["elapsed_seconds"]<=row["elapsed_seconds"],"actual four physical control process")
        else:
            saved=loads(stdout)
            require(saved["native_or_rust_executions"]==saved["reader_writes"]==0 and len(saved["probes"])==12
                and saved["before"]==saved["after"] and saved["evidence"]["groups"]==groups,
                "prior guarded reader whole domain and no writes/execution")
    require(source()==identity,"complete source unchanged in full reader")
    return dict(status="FULL_FIXED_EIGHT_CAPTURED_BUFFER_JOIN_PASS",source_manifest_sha256=identity,
        groups=groups,new_hia_calls=sum(r["calls"]for r in groups),
        old_records=14196,old_complete_buffer_bytes=6710163328,
        complete_new_buffer_bytes=sum(r["new_complete_buffer_bytes"]for r in groups),reader_controls=controls,
        original_failure_archive=old_archive,new_build_archive=new_archive,new_build=build,
        reader_native_executions=0,reader_rust_executions=0,reader_writes=0,
        watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False)

def run(workspace):
    # Every parser/import, including compression and qualified source AST proof,
    # is prepared before guard installation; original reader function stays exact.
    prepared=prepare(workspace/"fresh")
    gzip.decompress(gzip.compress(b"preload"));bz2.decompress(bz2.compress(b"preload"))
    lzma.decompress(lzma.compress(b"preload"))
    original=loads(read(workspace/"prior/complete/run/CAPTURE.json"))
    foreign=Path(original["source_root"])/"SOURCE.json"
    roots=(ROOT,workspace/"inputs",workspace/"prior",workspace/"fresh",workspace/"run")
    return guarded(lambda:verify(workspace,prepared),roots=roots,foreign_path=foreign)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--workspace",type=Path,required=True)
    a=p.parse_args();print(encoded(run(a.workspace.resolve(strict=True))).decode(),end="")
