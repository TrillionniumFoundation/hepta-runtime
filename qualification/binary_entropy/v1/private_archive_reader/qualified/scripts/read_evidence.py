"""Read the complete uploaded private producer, all guards and physical copies."""
from pathlib import Path
from evidence_common import decode,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_build_evidence,read_private,private_controls
def process_table(folder,rows,expected):
    require(decode((folder/"processes.json").read_bytes())==rows,"complete private process inventory")
    require([(r["name"],r["timeout_seconds"])for r in rows]==expected,"exact frozen private process sequence")
    values={}
    for row in rows:
        require(row["pid"]==row["pgid"]and row["parent_pid"]>0 and row["exit_code"]==0
            and row["completed"]is True and row["timed_out"]is False and row["stdin"]is None
            and 0<=row["elapsed_seconds"]<row["timeout_seconds"],"natural bounded complete process")
        for suffix in("stdout","stderr"):
            value=row[suffix]
            require(value["file"]==row["name"]+"."+suffix
                and pin(folder/value["file"])=={k:value[k]for k in("bytes","sha256")},"complete private process stream")
        require(row["stderr"]["bytes"]==0,"hidden private process error")
        values[row["name"]]=decode((folder/row["stdout"]["file"]).read_bytes())
    return values
def argument(row,key):return row["argv"][row["argv"].index("--"+key)+1]
def verify(source,work):
    identity=source_evidence(source);gate=decode((work/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.binary-entropy.private-gate.v1"
        and gate["source"]==identity and gate["compiled_build_reused"]is True and gate["compiler_executions"]==0
        and gate["private_hia_entry_calls"]==216 and gate["private_native_admission_calls"]==24
        and gate["original_application_calls"]==gate["actual_kernel_entropy_applications"]==gate["application_replays"]==0
        and gate["whole_runtime_replaced"]is False,"complete private gate scope")
    rows=gate["processes"]
    values=process_table(work/"processes",rows,[("source-check",60),("build-fetch",60),("build-unpack",180),
        ("build-read",180),("private-capture",60),("full-read",180),("physical-controls",180)])
    expected_source=dict(status="PRIVATE_SOURCE_DOMAIN_PASS",source=identity,domain=pin(source/"PRIVATE_DOMAIN.json"),
        private_hia_entry_calls=216,private_native_admission_calls=24,application_calls=0)
    require(values["source-check"]==gate["source_check"]==decode((work/"INPUT_DOMAIN.json").read_bytes())==expected_source,
        "complete private source admission")
    require(values["build-fetch"]==gate["build_fetch"]and values["build-unpack"]==gate["build_restore"],
        "complete qualified build archive recovery")
    reuse=work/"build-reuse";build_value=read_build_evidence.verify(source,reuse)
    build_guard=decode((work/"BUILD_ADMISSION.json").read_bytes())
    require(values["build-read"]==build_guard and build_guard["evidence"]==gate["build_admission"]==build_value,
        "complete retained build pure result")
    source_origin=rows[0]["cwd"];reuse_origin=argument(rows[1],"work")
    references=saved_guard(build_guard,{source_origin:tree(source),
        reuse_origin+"/original":tree(reuse/"original"),reuse_origin+"/download":tree(reuse/"download")})
    capture=work/"capture";summary=decode((capture/"CAPTURE.json").read_bytes())
    require(summary==values["private-capture"]==gate["private_capture"]
        and summary["process_pid"]==rows[4]["pid"],"one bounded private HIA/native process")
    require((capture/"BUILD.json").read_bytes()==(reuse/"original/restored/run/build/BUILD.json").read_bytes(),
        "actual image map exactly equals admitted build")
    result=read_private.verify(source,capture);primary=decode((work/"READONLY.json").read_bytes())
    require(primary==values["full-read"]and primary["evidence"]==gate["private_result"]==result,
        "all private buffers agree with frozen independent reader")
    references+=saved_guard(primary,{source_origin:tree(source),argument(rows[5],"capture"):tree(capture)})
    controls=decode((work/"controls/CONTROLS.json").read_bytes())
    require(controls==gate["controls"]==values["physical-controls"]and controls["source"]==identity
        and controls["status"]=="FOUR_PRIVATE_REFUSALS_TWO_RELOCATIONS_PASS"and controls["guard_probes"]==66
        and controls["application_executions"]==0 and controls["all_expanded_copies_retained"]is True,
        "all six retained private physical controls")
    require(len(controls["cases"])==6,"exact private physical case count")
    returned=process_table(work/"controls/processes",controls["processes"],[(n,180)for n,_ in private_controls.CASES])
    originals={}
    for label,folder in(("source",source),("capture",capture)):
        originals.update({label+"/"+p:v for p,v in private_controls.files(folder).items()})
    for row,(name,message)in zip(controls["cases"],private_controls.CASES):
        root=work/"controls"/name;working=root/"working";guard=decode((root/"READONLY.json").read_bytes())
        require(row["name"]==name and row["process"]==next(p for p in controls["processes"]if p["name"]==name)
            and row["guard"]==pin(root/"READONLY.json")and returned[name]==guard
            and guard["evidence"]==row["result"],"full private physical guard and process")
        observed=private_controls.files(working)
        require(set(observed)==set(originals)and len(observed)==row["retained_complete_files"],
            "complete private physical-copy file set")
        changes={p:dict(before=originals[p],after=observed[p])for p in observed if observed[p]!=originals[p]}
        require(changes==row["changes"]and len(changes)==(2 if message is not None else 0),
            "all honestly resealed private physical bytes and modes")
        actual=private_controls.verify_copy(working/"source",working/"capture",name)
        require(actual==row["result"],"pure physical refusal/recovery result differs")
        if message is None:
            require(actual==dict(status="COMPLETE_PRIVATE_RELOCATION_PASS",name=name,qualification=result),
                "complete semantic private relocation")
        mapping={source_origin:tree(source),argument(row["process"],"source"):tree(working/"source"),
            argument(row["process"],"capture"):tree(working/"capture")}
        references+=saved_guard(guard,mapping)
    return dict(status="COMPLETE_UPLOADED_ENTROPY_PRIVATE_EVIDENCE_PASS",private=result,upstream_build=build_value,
        retained_guard_full_file_references=references,retained_guards=8,retained_guard_probes=88,
        physical_refusals=4,complete_relocations=2,new_hia_or_original_applications=0,whole_runtime_replaced=False)
