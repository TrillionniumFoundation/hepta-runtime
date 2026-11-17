"""Pure full-byte admission of the unique read67/pool and formatter34 successor."""
from pathlib import Path
from callable_common import decode,owned,pin,require
def check_edits(root,row):
    before=owned(root,row["before_path"]).read_bytes()
    after=owned(root,row["path"]).read_bytes()
    require(pin(root/row["before_path"])=={k:row["before"][k] for k in ("bytes","sha256")}
        and pin(root/row["path"])==row["after"],"complete rebind before/after pins")
    value=before.decode()
    for edit in row["edits"]:
        require(value.count(edit["old"])==edit["occurrences"],"exact dependency-rebind preimage")
        value=value.replace(edit["old"],edit["new"])
    require(value.encode()==after,"only the frozen dependency-rebind edits")
def verify(root):
    root=Path(root);proof=decode(owned(root,"REBIND_PROOF.json").read_bytes())
    require(proof["previous_production"]=="8a1ab5839ed3b5699916c7c1b8e113aade1d9417"
        and proof["read67_production"]=="6ba1cbe2d46cc82416596f838b738df70478de7a"
        and proof["read67_final"]=="8bb4e020fc8a728ec7b06e8ffa510052d5e8fa64"
        and proof["formatter34_production"]=="2464624eee505339adfd6b6297a7f7eb00672bd8"
        and proof["formatter34_final"]=="96a3ecccb3b054a9bf0059659040d4bb9e38e4a9",
        "fixed previously qualified production owners")
    require(len(proof["production_edits"])==len(proof["fixture_edits"])==1,"one production and one private fixture owner")
    for row in proof["production_edits"]+proof["fixture_edits"]:check_edits(root,row)
    body=proof["body40_unchanged"]
    require(body["path"]=="native/file_info_at.hepta" and pin(root/body["path"])==
        {k:body[k] for k in ("bytes","sha256")},"complete info40 HIA retained")
    read=decode(owned(root,"reference/read67_final_handoff.json").read_bytes())["production"]
    require(read["commit"]==proof["read67_production"] and read["body_functions"]==67
        and read["body_instructions"]==4063 and read["unchanged_functions_exact_ir"]==66,
        "final read67 qualification binding")
    for name in ("body","composition","native_boundary","shared_pool"):
        row=read[name];require(pin(owned(root,row["path"]))=={k:row[k] for k in ("bytes","sha256")},
            "all exact read67 and single process-pool production bytes")
    manifest=decode(owned(root,"reference/read67_build_source_manifest.json").read_bytes())
    require(pin(root/"reference/read67_build_source_manifest.json")["sha256"]==read["source_manifest_sha256"]
        and len(manifest["files"])==52,"complete original read67 build source identity")
    formatter=decode(owned(root,"reference/formatter34_final_handoff.json").read_bytes())
    install=decode(owned(root,"reference/formatter34_install_rows.json").read_bytes())
    require(formatter["status"]=="COMPLETE_LITERAL_ERROR_PRIVATE_PRIMITIVE_QUALIFIED"
        and formatter["production"]["commit"]==install["production_commit"]==proof["formatter34_production"]
        and install["functions"]==34 and install["retained_previous_function_bodies"]==32,
        "final sole formatter34 qualification binding")
    for row in install["files"]:
        require(pin(owned(root,row["destination"]))=={k:row[k] for k in ("bytes","sha256")},
            "complete final formatter source, platform data and ABI")
    require(not (root/"native/structured_error.hepta").exists() and not (root/"native/binary_error.hepta").exists(),
        "no obsolete production formatter remains")
    bridge=owned(root,"asm/file_info_at_callable.S").read_text()
    require(bridge.count("mov rdx, [r12+376]\n    call binary_read_body_create")==1,
        "validated process-wide pool passed to fingerprint child")
    require(proof["application_executions"]==0 and proof["qualification_pending"] is True,
        "source author cannot imply new composed-application qualification")
    return dict(status="EXACT_INFO40_READ67_POOL_FORMATTER34_REBIND_SOURCE_PASS",info_functions=40,
        read_functions=67,formatter_functions=34,one_shared_pool=True,actual_composition_qualified=False,
        native_application_calls=0)
