#!/usr/bin/env python3
"""Independent R2 source-only mocks: never import or execute harness top level/runtime/SSH."""
import ast, base64, collections, hashlib, json, os, pathlib, stat, tempfile
SOURCE = pathlib.Path("/home/qian-qi/hepta-runtime-v9-ledger-rollback-drafts-20261013/tests/dc_functional_v9_rollback_ledger_host_acceptance.py")
BASELINE = pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013/tests/dc_functional_v8_rollback_host_acceptance.py")
EXPECTED = "2c1c473cc1be005559d71dd75023dbaff0b6d3baf25f10afcb2f9caca4a8f4aa"
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED
tree = ast.parse(SOURCE.read_text())
assert next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="HARNESS_ACCEPTANCE_ENABLED" for t in n.targets)) is False
def extracted(name, ns):
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),"<R2-source-only-"+name+">","exec"),ns)
    return ns[name]
with tempfile.TemporaryDirectory(prefix="hepta-v9-ledger-r2-reviewer-mock-") as tmp:
    paths=[pathlib.Path(tmp)/n for n in ["counter","healthcounter","gate","observed","intent","child"]]
    wrapper = extracted("health_ledger_wrapper", {})(*paths,"mock-nonce","mock-fixed-host")
    generated=ast.parse(wrapper)
    publish_node=next(n for n in generated.body if isinstance(n,ast.FunctionDef) and n.name=="publish")
    pns={"os":os,"json":json}
    exec(compile(ast.Module(body=[publish_node],type_ignores=[]),"<R2-publish-only>","exec"),pns)
    dest=pathlib.Path(tmp)/"atomic.json";value={"nonce_sha256":"x"*64,"wrapper":{"pid":123,"start_ticks":456}}
    link0,fsync0=os.link,os.fsync;visible=[];sync_kinds=[]
    def link(src,target,**kw):
        assert not pathlib.Path(target).exists()
        assert json.loads(pathlib.Path(src).read_text())==value
        link0(src,target,**kw)
        assert json.loads(pathlib.Path(target).read_text())==value
        visible.append("complete_document_at_first_visibility")
    def fsync(fd):
        sync_kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return fsync0(fd)
    os.link,os.fsync=link,fsync
    try:pns["publish"](dest,value)
    finally:os.link,os.fsync=link0,fsync0
    assert dest.stat().st_nlink==1 and stat.S_IMODE(dest.stat().st_mode)==0o600
    print(json.dumps({"check":"atomic_complete_visibility","passed":True,"observations":visible,"sync_kinds":sync_kinds,"directory_fsync_present":"directory" in sync_kinds}))
    before=dest.read_bytes()
    try:pns["publish"](dest,{"different":True})
    except FileExistsError:pass
    else:raise AssertionError("publication overwrote existing destination")
    assert dest.read_bytes()==before
    print(json.dumps({"check":"existing_destination_refused_without_overwrite","passed":True}))
    rns={"base64":base64,"hashlib":hashlib,"json":json,"ledger_request_identity":lambda raw:None,"ledger_retention_ack":lambda raw,kind:None,"ledger_result_text":lambda raw:raw}
    reconstruct=extracted("ledger_reconstruct",rns)
    request_id="a"*64;native={"resultType":"complete","_meta":{"io.hepta.runtime/request-v8":{"request_id":request_id}},"pad":""}
    minimal=json.dumps(native,separators=(",",":")).encode();native["pad"]="x"*(65536-len(minimal))
    payload=json.dumps(native,separators=(",",":")).encode();assert len(payload)==65536
    class Pages:
        def __init__(self,mutate=False):self.calls=0;self.mutate=mutate
        def raw_call(self,tool,args):
            self.calls+=1;assert tool=="request_result" and args["limit"]==16384
            offset=args["offset"];end=min(offset+16384,len(payload))
            return {"request_id":request_id,"offset":offset,"automatic_retry":False,"delivery_proven":False,"immutable_snapshot":True,"format":"serialized_native_CallToolResult_with_request_identity_before_retention_ack_and_transport_normalization","result_sha256":hashlib.sha256(payload).hexdigest(),"total_bytes":len(payload),"data_base64":base64.b64encode(payload[offset:end]).decode(),"next_offset":end+(1 if self.mutate else 0),"eof":end==len(payload)}
    good=Pages();data,summary=reconstruct(good,request_id,native)
    assert data==payload and good.calls==4
    try:reconstruct(Pages(True),request_id,native)
    except AssertionError:pass
    else:raise AssertionError("invalid page progression accepted")
    print(json.dumps({"check":"four_page_max_and_invalid_progression","passed":True,"maximum_payload_bytes":len(payload),"calls":good.calls}))
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main")
workflow=next(n for n in main.body if isinstance(n,ast.Try) and n.lineno>800)
cursors=[n.lineno for n in ast.walk(workflow) if isinstance(n,ast.Assert) and "owner_cursor" in ast.unparse(n)]
admissions=[n.lineno for n in ast.walk(workflow) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {"ledger_capture","ledger_begin_interrupted_async"}]
assert max(cursors)<min(admissions)
budget={"capture_forward":15,"async_start_including_inner_ticket":3,"forward_four_page_lookups":12,"async_status_reuse_cancel":3,"capture_second":15,"second_four_page_lookups":12,"revocation_calls":4,"restored_four_page_lookups":12,"old_v4_archive_and_pty_observations_conservatively_counted":4}
assert sum(budget.values())==80 and sum(budget.values())<128
print(json.dumps({"check":"cursor_order_and_new_id_retention_budget","passed":True,"last_original_cursor_assertion":max(cursors),"first_ledger_admission":min(admissions),"r2_conservative_footer_admission_upper_bound":80,"quota":128,"bound_components":budget}))
baseline=ast.parse(BASELINE.read_text())
new=collections.Counter(ast.dump(n).replace("v8","v9").replace("V8","V9") for n in ast.walk(tree) if isinstance(n,ast.Assert))
old_asserts=[n for n in ast.walk(baseline) if isinstance(n,ast.Assert)]
for node in old_asserts:
    key=ast.dump(node).replace("v8","v9").replace("V8","V9")
    assert new[key],"original assertion missing at "+str(node.lineno)
    new[key]-=1
old_checks=sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="passed" for n in ast.walk(baseline))
new_checks=sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="passed" for n in ast.walk(tree))
assert len(old_asserts)==89 and old_checks==11 and new_checks==17
print(json.dumps({"check":"all_original_assertions_and_checks_preserved","passed":True,"original_assertions":89,"original_checks":11,"total_checks":17}))
old={"pid":123,"uid":1000,"boot_id":"mock-boot","start_ticks":10,"state":"R"}
for label,current,expect in [
    ("same_incarnation_running",dict(old),False),
    ("same_incarnation_zombie",dict(old,state="Z"),True),
]:
    ns={"owned_local_identity":lambda pid,c=current:c}
    assert extracted("original_local_process_gone",ns)(old)==expect
ns={"owned_local_identity":lambda pid:dict(old,uid=1001)}
try:extracted("original_local_process_gone",ns)(old)
except AssertionError:pass
else:raise AssertionError("same-incarnation changed UID accepted as gone")
print(json.dumps({"check":"identity_guard_mock","passed":True,"same_incarnation_uid_change_currently_refused":True,"zombie_acceptance_is_only_not_executing_not_reaped":True}))
print(json.dumps({"review_scope":"source_only_ast_and_own_private_file_mocks","runtime_executed":False,"ssh_executed":False,"services_changed":False,"acceptance_qualified":False,"pending_fix":"directory_fsync_and_strict_reaping_or_explicit_HOLD"}))
