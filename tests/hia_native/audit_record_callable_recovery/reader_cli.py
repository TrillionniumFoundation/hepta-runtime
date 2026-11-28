"""Guarded complete native-pump recovery; verification never writes or executes a semantic owner."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from recovery_common import source,read,loads,encoded,need,BASE_SOURCE
import reader_adapter

def run(phase,original,capture,retained,controls,report):
    identity=source()
    legacy,physical=reader_adapter.install(original)
    prepared=legacy.prepare(retained)
    if phase=="controls":
        result=physical.run(capture,prepared,controls)
        value=dict(schema="hepta.audit-record-callable.recovered-controls.v1",
            reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
            evidence=result,native_or_rust_executions=0,original_failure_preserved=True)
        report.write_bytes(encoded(value))
        summary=dict(status=result["status"],refusals=result["refusals"],admissions=result["admissions"],
            native_or_rust_executions=0,mutation_writes_outside_guards=True,
            reader_adapter_source_sha256=identity)
    else:
        complete=phase in ("final","verify")
        roots=physical.roots(capture,prepared)
        if complete:roots.append(controls)
        value=legacy.read_only_guard.guarded(
            lambda:legacy.operation(capture,prepared,controls if complete else None),
            roots=roots,foreign_path=str(report.parent/"foreign-unadmitted-copy/CAPTURE.json"))
        value["reader_adapter_source_sha256"]=identity
        value["original_source_manifest_sha256"]=BASE_SOURCE
        value["original_failure_preserved"]=True
        if phase=="verify":
            existing=loads(read(report))
            need(existing["reader_adapter_source_sha256"]==identity and
                 existing["original_source_manifest_sha256"]==BASE_SOURCE and
                 existing["original_failure_preserved"] is True and
                 existing["evidence"]==value["evidence"] and existing["before"]==existing["after"] and
                 len(existing["probes"])==12 and
                 existing["native_or_rust_executions"]==existing["reader_writes"]==0,
                 "read-only comparison of full retained final proof, no rewrite")
        else:report.write_bytes(encoded(value))
        summary=dict(status=value["evidence"]["status"],native_or_rust_executions=0,reader_writes=0,
            guard_probes=len(value["probes"]),physical_entries=len(value["before"]),
            reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
            evidence=value["evidence"])
        if phase=="verify":summary["complete_guard"]=value
    need(source()==identity,"unchanged complete source after recovery")
    print(encoded(summary).decode(),end="")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",choices=("semantic","controls","final","verify"),required=True)
    for name in ("original","capture","retained","controls","report"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    run(a.phase,a.original.resolve(strict=True),a.capture.resolve(strict=True),a.retained.resolve(strict=True),
        a.controls.absolute(),a.report.absolute())
