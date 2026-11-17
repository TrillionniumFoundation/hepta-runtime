"""Independently read complete uploaded WAIT evidence without target execution."""
from pathlib import Path
import argparse,json,os,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from archive_input import require,pin,doc,put,admitted,files,saved_guard,process,download,flat_archive
import saved_controls
def main():
    p=argparse.ArgumentParser();p.add_argument("--name",required=True);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    out=a.output.absolute();require(not out.exists(),"fresh independent full read");out.mkdir(parents=True)
    identity=next(x for x in doc(HERE/"INPUTS.json")["artifacts"] if x["name"]==a.name)
    admitted(HERE)
    archive=out/"producer.zip";download(archive,identity["artifact"])
    actual_archive=flat_archive(archive,identity,out/"retained")
    put(out/"ARCHIVE_READ.json",actual_archive)
    root=out/"retained";recipe=root/"recipe-source";capture=root/"capture"
    pair=capture/"pair";retained=pair/"retained";actual=retained/"capture"
    source=retained/"recipe-source";native_source=actual/"recipe-extension"
    source_count=admitted(recipe,identity["source_manifest"])
    source_input=next(x for x in doc(recipe/"INPUTS.json")["artifacts"] if x["domain"]==identity["domain"])
    require(doc(pair/"ARCHIVE_READ.json")=={k:source_input[k] for k in ("archive","files","logical_bytes")}|{"status":"COMPLETE_ARCHIVE_BYTES_PASS"},"exact retained inner archive proof")
    require(pin(pair/"producer.zip")==source_input["zip"],"full retained inner producer ZIP")
    capture_count=admitted(source,source_input["capture_source_manifest"])
    native_count=admitted(native_source,source_input["native_source_manifest"])
    require((recipe/"read_capture_fixed.py").read_bytes()==(native_source/"read_capture_fixed.py").read_bytes(),"entire native reader retained")
    # Imports are pinned, complete source reads performed before entering guard.
    os.environ["WAIT_SOURCE"]=str(source)
    sys.path[:0]=[str(recipe),str(native_source),str(source),str(source/"build_reader")]
    import read_lifetime as reader,read_only_guard as guard
    role=identity["role"];control_name="controls" if role=="complete" else "semantic_controls";control_root=capture/control_name
    prepared={}
    controlled=out/"independent-controls"
    if role=="semantic":prepared=saved_controls.prepare_semantic(actual,control_root,controlled)
    else:controlled.mkdir()
    def verify():
        recovery_process=process(capture,"recover",identity["processes"][0])
        control_process=process(capture,control_name,identity["processes"][1])
        expected=identity["expected_reports"]
        require(doc(pair/"RESULT.json")==expected[0] and doc(control_root/"CONTROLS.json")==expected[1] and doc(capture/"RESULT.json")==expected[2],"complete original successful gate receipts")
        require((root/"driver.stderr").read_bytes()==b"","complete original driver stderr")
        inputs=doc(actual/"INPUTS_READY.json")
        require({k:inputs["native"][k] for k in ("bytes","sha256")}==reader.source_contract()["native_fixture"],"complete same production fixture")
        values=[reader.read(actual/side,side,{k:inputs[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
        qualification=reader.compare(*values)
        old=doc(pair/"READ_ONLY.json")
        require(qualification==old["evidence"]==doc(pair/"QUALIFICATION.json"),"entire independently recomputed saved pair evidence")
        proof_files=saved_guard(old,[files(pair,("READ_ONLY.json","QUALIFICATION.json","RESULT.json")),files(source),files(native_source),files(recipe)],recovery_process["pid"])
        controls=saved_controls.controls(actual,control_root,recipe,source,control_process,qualification,reader,prepared,role)
        return {"status":"INDEPENDENT_UPLOADED_SCOPE_WAIT_FULL_READ_PASS","name":identity["name"],"domain":identity["domain"],"role":role,
            "source":"320862f03902153b5c804d1b68142126a9c7a606","producer_source":identity["source"],"producer_run":identity["run"],"producer_job":identity["job"],
            "artifact":identity["artifact"],"complete_files":identity["files"],"complete_logical_bytes":identity["logical_bytes"],
            "source_files":{"reader":source_count,"capture":capture_count,"native":native_count},"original_cases":4,"native_cases":4,
            "recomputed_qualification":qualification,"retained_guarded_files":proof_files,"controls":controls,
            "new_original_executions":0,"new_native_executions":0,"full_runtime":False,"full_sdk":False,"production_installed":False}
    checked=guard.guarded(verify,roots=[root,HERE,controlled],foreign_path=Path("/dev/null"))
    put(out/"READ_ONLY.json",checked);put(out/"QUALIFICATION.json",checked["evidence"])
    retirement=saved_controls.retire(prepared,actual,control_root)
    put(out/"RETIREMENT.json",retirement)
    result={k:checked["evidence"][k] for k in ("status","name","domain","role","source","producer_source","producer_run","producer_job","artifact","complete_files","complete_logical_bytes","original_cases","native_cases","new_original_executions","new_native_executions")}
    result.update(independent_guard_probes=len(checked["probes"]),retained_control_count=len(checked["evidence"]["controls"]),retired_complete_control_copies=len(retirement))
    put(out/"RESULT.json",result);print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
