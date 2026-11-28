#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Final complete uploaded result read; do not rerun any retained semantic reader."""
from pathlib import Path
import argparse,os,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,need,pin,unpack,inventories
from common import source_evidence
def no_process(event,args):
    if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
        raise PermissionError("final immutable reader executes no applications or retained readers")
def main():
    p=argparse.ArgumentParser()
    for n in("source","archive","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(no_process);need(not a.output.exists()and not a.stage.exists(),"fresh complete uploaded read")
    a.output.mkdir();a.stage.mkdir();binding=source_evidence(a.source);inputs=decode((a.source/"INPUTS.json").read_bytes())
    root=unpack(a.archive,a.stage/"complete",inputs["completed"]);snapshot=inventories(root)
    previous=root.parent/"recipe-source";need(pin(previous/"SOURCE_MANIFEST.json")==inputs["completed"]["source_manifest"],"exact completed pure source manifest")
    old_source=source_evidence(previous);result=decode((root/"RESULT.json").read_bytes());ready=decode((root/"READY.json").read_bytes())
    need(result["status"]=="INSTALLED_SECOND_RELOCATION_COMPLETE"and result["whole_original_object_equal"]is True and result["whole_native_object_equal"]is True,"whole finished second comparison")
    need(result["new_pure_phase_invocations"]==1 and result["new_hia_applications"]==result["new_rust_applications"]==result["new_compilers"]==0,"only missing pure phase completed")
    need(result["completed_refusals_preserved"]==42 and result["completed_first_relocation_preserved"]is True and result["completed_refusals_replayed"]==result["completed_first_relocation_replayed"]==result["second_standalone_native_phase_replayed"]==0,"all completed controls/readers retained without replay")
    process=decode((root/"CONTINUATION_PROCESS.json").read_bytes())
    need(process["status"]=="COMPLETE"and process["exit_code"]==process["applications"]==0 and process["timeout_seconds"]==180 and process["elapsed_ns"]<=180000000000,"actual bounded original pure phase completion")
    need(process["standalone_native_phase_replayed"]is False and process["operation"]=="unchanged actual test_native_evidence.admit_bundle"and process["finished_ns"]>=process["started_ns"],"actual exact remaining entry and timestamps")
    prior=root/"prior-completed-evidence";baseline=(prior/"BASELINE.json").read_bytes();native=(prior/"NATIVE-BASELINE.json").read_bytes()
    need(pin(root/"EVIDENCE.json")==inputs["original_result"]and pin(root/"NATIVE-EVIDENCE.json")==inputs["native_result"],"whole original immutable final results")
    need(baseline==(root/"EVIDENCE.json").read_bytes()==(prior/"relocation-1/EVIDENCE.json").read_bytes(),"all complete original result bytes equal")
    need(native==(root/"NATIVE-EVIDENCE.json").read_bytes()==(prior/"relocation-1/NATIVE-EVIDENCE.json").read_bytes()==(prior/"relocation-2/NATIVE-EVIDENCE.json").read_bytes(),"all complete native result bytes equal without rerun")
    need(decode(baseline)==decode((root/"EVIDENCE.json").read_bytes())and decode(native)==decode((root/"NATIVE-EVIDENCE.json").read_bytes()),"entire result objects equal")
    first=decode((prior/"relocation-1/PROCESS.json").read_bytes());need(first["exit_code"]==0 and first["timed_out"]is False,"original completed first process remains complete")
    refusals=decode((prior/"REFUSALS.json").read_bytes());need(len(refusals["controls"])==42 and len({r["name"]for r in refusals["controls"]})==42,"all distinct original physical refusals present")
    need(refusals["groups"]==dict(process_contract=8,receipt_semantics=13,observer_state=6,source_and_build=8,files_and_json=5,whole_streams=2),"full original refusal scope")
    bundle=root/"owned-second-relocation";need(pin(bundle/"mapping.json")==inputs["mapping"],"whole unchanged physical relocation mapping")
    rows=decode((root/"EXTRACTED_FILES.json").read_bytes());expected={r["path"]:r for r in rows}
    actual={p.relative_to(bundle).as_posix()for p in [bundle,*bundle.rglob("*")]};actual.discard(".");actual.add("")
    need(actual==set(expected),"all expanded original bundle files and directories")
    logical=files=dirs=0
    for rel,r in expected.items():
        path=bundle/rel;s=path.lstat()
        need((stat.S_ISREG(s.st_mode)if r["kind"]=="file"else stat.S_ISDIR(s.st_mode))and stat.S_IMODE(s.st_mode)==r["mode"]and s.st_mtime_ns==r["mtime_ns"],"exact complete original bundle metadata")
        if r["kind"]=="file":need(pin(path)=={k:r[k]for k in("bytes","sha256")},"all complete original bundle bytes");files+=1;logical+=r["bytes"]
        elif rel:dirs+=1
    need((files,dirs,logical)==(1811,797,571446317),"exact original bundle closure")
    for r in ready["source_files"]:
        path=bundle/r["path"];need(pin(path)=={k:r[k]for k in("bytes","sha256")}and path.read_bytes()==(previous/"retained-sources"/r["path"]).read_bytes(),"every actual retained reader source equals frozen original bytes")
    need(result["source"]==old_source and ready["metadata_binding"]["second_native_phase_complete"]is True and ready["metadata_binding"]["second_full_phase_complete"]is False,"original missing-phase boundary retained")
    need(inventories(root)==snapshot and source_evidence(a.source)==binding,"independent complete read changed no input/source bytes or metadata")
    final=dict(status="INSTALLED_BYTES_42_REFUSALS_AND_TWO_RELOCATIONS_COMPLETE_UPLOADED_PASS",uploaded=inputs["completed"],
        full_files=files,full_directories=dirs,full_bundle_bytes=logical,original_result=inputs["original_result"],native_result=inputs["native_result"],
        completed_refusals=42,completed_first_relocation_replayed=0,second_standalone_native_phase_replayed=0,
        pure_missing_phase_completed_once=True,retained_semantic_readers_executed=0,new_applications=0,new_compilers=0,
        old_failures=result["old_failures"],scope_expanded=False,public_scope="existing installed original 323 attempts plus 9 private fixture/cache controls only",source=binding)
    (a.output/"RESULT.json").write_bytes(canonical(final));print(canonical(final).decode(),end="")
if __name__=="__main__":main()
