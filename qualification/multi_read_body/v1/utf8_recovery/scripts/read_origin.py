"""Read the first failed UTF-8 producer in full; preserve completed applications."""
from pathlib import Path
from evidence_common import decode,owned,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_build_evidence
def argument(row,name):return row["argv"][row["argv"].index("--"+name)+1]
def reader_change(reader,source):
    reader,source=Path(reader),Path(source)
    own=source_evidence(reader);original=source_evidence(source)
    require((source/"SOURCE_MANIFEST.json").read_bytes()==(reader/"ORIGINAL_SOURCE_MANIFEST.json").read_bytes(),
        "exact complete original source manifest")
    change=decode((reader/"READER_CHANGE.json").read_bytes())
    before=(reader/"reference/read_utf8_before.py").read_bytes();after=(reader/"scripts/read_utf8.py").read_bytes()
    require(before==(source/"scripts/read_utf8.py").read_bytes()
        and pin(reader/"reference/read_utf8_before.py")=={k:change["before"][k] for k in ("bytes","sha256")}
        and pin(reader/"scripts/read_utf8.py")=={k:change["after"][k] for k in ("bytes","sha256")},
        "complete reader before and after source pins")
    value=before.decode()
    for edit in change["edits"]:
        require(value.count(edit["old"])==edit["occurrences"],"exact reader-edit preimage")
        value=value.replace(edit["old"],edit["new"])
    require(value.encode()==after,"only the frozen evidence-reader correction")
    for name in ("evidence_common.py","buffer_store.py","inputs.py","readonly.py","read_main.py",
        "read_build_evidence.py","build_reuse.py","read_uploaded_build.py","process.py","physical_controls.py","common.py"):
        require((reader/"scripts"/name).read_bytes()==(source/"scripts"/name).read_bytes(),"unchanged support source "+name)
    native=(source/"trusted-build/scripts/read_callable_build.py").read_text()
    require("elf.stat().st_mode&0o777==0o500" in native,"actual build-owned executable mode")
    require((reader/"BUILD_REUSE.json").read_bytes()==(source/"BUILD_REUSE.json").read_bytes(),"same unchanged native build")
    return dict(reader_source=own,original_source=original,change=pin(reader/"READER_CHANGE.json"))
def verify(reader,semantic,reuse,group):
    reader,semantic,reuse=Path(reader),Path(semantic),Path(reuse)
    base=semantic/"original/restored";source=base/"source";capture=base/"run"
    identity=reader_change(reader,source)
    binding=decode((reader/"ORIGIN_BINDING.json").read_bytes())["groups"][group]
    require(pin(semantic/"download/complete.zip")=={k:binding["artifact"][k] for k in ("bytes","sha256")}
        and pin(semantic/"original/zip/evidence.tar.gz")=={k:binding["tar"][k] for k in ("bytes","sha256")},
        "complete fixed original ZIP and TAR")
    gate=decode(owned(capture,"GATE.json").read_bytes())
    rows=decode(owned(capture,"processes/processes.json").read_bytes())
    require(gate["status"]=="FAIL" and gate["group"]==group and gate["source"]==identity["original_source"]
        and gate["compiler_or_rust_executions"]==0 and gate["whole_runtime_replaced"] is False
        and gate["error_type"]=="RuntimeError" and gate["message"]=="recorded command failed: full-read"
        and rows==gate["processes"] and [r["name"] for r in rows]==
        ["source-check","build-fetch","build-unpack","build-admission","capture-original","capture-native","full-read"],
        "exact original failed pure-reader stage")
    values={};expected={"processes.json"}
    for index,(row,limit) in enumerate(zip(rows,(60,60,180,180,180,180,180))):
        require(row["pid"]==row["pgid"] and row["pid"]>0 and row["parent_pid"]>0
            and row["exit_code"]==(1 if index==6 else 0) and row["timed_out"] is False and row["completed"] is True
            and row["timeout_seconds"]==limit and 0<=row["elapsed_seconds"]<limit and row["stdin"] is None,
            "original complete natural process status")
        for suffix in ("stdout","stderr"):
            part=row[suffix];name=row["name"]+"."+suffix;expected.add(name)
            require(part["file"]==name and pin(owned(capture,"processes/"+name))=={k:part[k] for k in ("bytes","sha256")},
                "complete original retained process streams")
        stdout=(capture/"processes"/row["stdout"]["file"]).read_bytes()
        stderr=(capture/"processes"/row["stderr"]["file"]).read_bytes()
        if index==6:
            require(stdout==b"" and b"ValueError: retained native ELF bytes\n" in stderr,
                "preserved original mode-admission failure")
        else:
            require(stderr==b"","no hidden producer failure before the reader")
            values[row["name"]]=decode(stdout)
    require({p.name for p in (capture/"processes").iterdir()}==expected,"complete original process set")
    domain=decode(owned(capture,"INPUT_DOMAIN.json").read_bytes())
    require(values["source-check"]==domain and domain["status"]=="MULTI_UTF8_SOURCE_AND_INPUT_ONLY_PASS"
        and domain["source"]==identity["original_source"] and domain["original_inputs"]==76414
        and domain["native_inputs"]==76662 and domain["private_controls"]==248
        and domain["original_decode_calls"]==domain["native_or_rust_calls"]==0,"complete input-only original source admission")
    counts={};reports={}
    for role in ("original","native"):
        report=decode(owned(capture,"application/"+role+"/CAPTURE.json").read_bytes())
        require(report["status"]=="PASS" and report["source"]==identity["original_source"]
            and report["group"]==group and report["role"]==role,"completed original/native captures retained")
        expected=dict(status="PASS",role=role,group=group,cases=report["cases"],
            original_decode_calls=report["original_decode_calls"],native_utf8_calls=report["native_utf8_calls"],
            body_or_parent_application_calls=0)
        require(values["capture-"+role]==expected,"full actual capture completion")
        reports[role]=expected;counts[role]=report["cases"]
    require(gate["completed"]==decode(owned(capture,"COMPLETED.json").read_bytes())
        ==[dict(role=role,report=reports[role]) for role in ("original","native")],"both completed roles survived reader failure")
    built=read_build_evidence.verify(source,reuse)
    admission=decode(owned(capture,"BUILD_ADMISSION.json").read_bytes())
    require(admission==values["build-admission"] and admission["evidence"]==built,"complete original native build admission")
    original_work=Path(argument(rows[3],"work"));original_source=argument(rows[3],"source")
    guarded_files=saved_guard(admission,{original_source:tree(source),
        str(original_work/"original"):tree(reuse/"original"),str(original_work/"download"):tree(reuse/"download")})
    require(values["build-fetch"]["status"]==values["build-unpack"]["status"]=="PASS","actual upstream archive recovery")
    require({p.name for p in capture.iterdir() if p.is_file()}==
        {"ENVIRONMENT.json","INPUT_DOMAIN.json","BUILD_ADMISSION.json","COMPLETED.json","GATE.json"}
        and {p.name for p in capture.iterdir() if p.is_dir()}=={"application","processes"},"original failure tree retained intact")
    decode(owned(capture,"ENVIRONMENT.json").read_bytes())
    return dict(status="ORIGINAL_COMPLETE_UTF8_CAPTURE_AND_MODE_FAILURE_PRESERVED",group=group,source=identity,
        completed_original_decodes=counts["original"],completed_native_calls=counts["native"],
        original_failed_process="full-read",original_failure_preserved=True,build=built,
        original_admission_full_guard_file_references=guarded_files,new_original_or_native_applications=0)
