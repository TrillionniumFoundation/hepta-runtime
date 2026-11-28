"""Pure reversible admission of the single pool and final diagnostic owner."""
from pathlib import Path
from callable_common import decode,owned,pin,require
def conditional(text,flag):
    out=[];active=True;stack=[]
    for line in text.splitlines(keepends=True):
        stripped=line.strip()
        if stripped==".if HBRH_OBSERVE":
            stack.append((active,flag));active=active and bool(flag)
        elif stripped==".else":
            require(stack,"unmatched conditional");parent,value=stack[-1];active=parent and not value
        elif stripped==".endif":
            require(stack,"unmatched conditional end");parent,value=stack.pop();active=parent
        elif active:out.append(line)
    require(not stack,"unterminated observer block");return "".join(out)
def verify(root):
    root=Path(root);proof=decode(owned(root,"REBIND_PROOF.json").read_bytes())
    require(proof["previous_production"]=="6fadcb3e85ce80607e22c18fe650c0a0acd71587"
        and proof["read67_production"]=="6ba1cbe2d46cc82416596f838b738df70478de7a"
        and proof["read67_final"]=="8bb4e020fc8a728ec7b06e8ffa510052d5e8fa64"
        and proof["formatter34_production"]=="2464624eee505339adfd6b6297a7f7eb00672bd8"
        and proof["formatter34_final"]=="96a3ecccb3b054a9bf0059659040d4bb9e38e4a9","fixed final owner pins")
    before=owned(root,proof["before"]["path"]).read_bytes();after=owned(root,proof["after"]["path"]).read_bytes()
    require(pin(root/proof["before"]["path"])=={k:proof["before"][k] for k in ("bytes","sha256")}
        and pin(root/proof["after"]["path"])=={k:proof["after"][k] for k in ("bytes","sha256")},
        "complete stdio bridge preimage and successor")
    text=before.decode();production=before.decode();production_changes=0
    for edit in proof["edits"]:
        require(text.count(edit["old"])==edit["occurrences"],"exact stdio bridge edit preimage")
        text=text.replace(edit["old"],edit["new"])
        if edit["scope"].startswith("production-"):
            require(production.count(edit["old"])==edit["occurrences"],"production-only edit preimage")
            production=production.replace(edit["old"],edit["new"]);production_changes+=1
    require(text.encode()==after and production_changes==2,"only full frozen bridge changes")
    require(conditional(production,0)==conditional(after.decode(),0)
        and ".Lbrh_lifecycle_" not in conditional(after.decode(),0),"all lifecycle observers absent from production")
    require(after.count(b"call hia_process_orphans_create")==1
        and b"mov rdx, [r15+112]\n    call binary_read_body_create" in after,"one process pool supplied to create")
    bindings=decode(owned(root,"SOURCE_BINDINGS.json").read_bytes())
    for name,row in bindings["exact_unchanged_preimages"].items():
        require(pin(owned(root,name))==row,"whole final qualified owner source")
    read=decode(owned(root,"reference/read67_final_handoff.json").read_bytes())["production"]
    require(read["commit"]==proof["read67_production"] and read["body_functions"]==67,"final read67")
    for key in ("body","composition","native_boundary","shared_pool"):
        row=read[key];require(pin(owned(root,row["path"]))=={k:row[k] for k in ("bytes","sha256")},
            "one exact qualified read body and shared pool")
    install=decode(owned(root,"reference/formatter34_install_rows.json").read_bytes())
    require(install["production_commit"]==proof["formatter34_production"] and install["functions"]==34,
        "sole final 34-function formatter")
    for row in install["files"]:
        require(pin(owned(root,row["destination"]))=={k:row[k] for k in ("bytes","sha256")},"full final diagnostic source")
    require(not(root/"native/binary_error.hepta").exists() and not(root/"native/structured_error.hepta").exists(),
        "obsolete formatter absent from production source")
    require(proof["application_executions"]==0 and proof["new_composition_qualification_pending"] is True,
        "source admission does not assert new runtime qualification")
    return dict(status="STDIO_READ67_POOL_FORMATTER34_SOURCE_PASS",production_edits=2,
        one_process_pool=True,observer_absent_from_production=True,native_application_calls=0)
