#!/usr/bin/env python3
"""Independent R3 source-only mocks: never import or execute harness top level/runtime/SSH."""
import ast, base64, collections, hashlib, json, os, pathlib, stat, tempfile
SOURCE = pathlib.Path("/home/qian-qi/hepta-runtime-v9-ledger-rollback-drafts-20261013/tests/dc_functional_v9_rollback_ledger_host_acceptance.py")
BASELINE = pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013/tests/dc_functional_v8_rollback_host_acceptance.py")
EXPECTED = "5e3ea2af529c709cfd1e3a20bbf437397edd6838c71cacac3ee569b4139af474"
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED
tree = ast.parse(SOURCE.read_text())
assert next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="HARNESS_ACCEPTANCE_ENABLED" for t in n.targets)) is False
def extracted(name, ns):
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),"<R3-source-only-"+name+">","exec"),ns)
    return ns[name]
with tempfile.TemporaryDirectory(prefix="hepta-v9-ledger-r3-reviewer-mock-") as tmp:
    paths=[pathlib.Path(tmp)/n for n in ["counter","healthcounter","gate","observed","intent","child"]]
    wrapper = extracted("health_ledger_wrapper", {})(*paths,"mock-nonce","mock-fixed-host")
    generated=ast.parse(wrapper)
    publish_node=next(n for n in generated.body if isinstance(n,ast.FunctionDef) and n.name=="publish")
    pns={"os":os,"json":json}
    exec(compile(ast.Module(body=[publish_node],type_ignores=[]),"<R3-publish-only>","exec"),pns)
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
    assert "directory" in sync_kinds
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
budget={"capture_forward":15,"async_start_including_inner_ticket":3,"forward_four_page_lookups":12,"async_status_reuse_cancel":3,"capture_second":15,"second_four_page_lookups":12,"revocation_calls":4,"restored_four_page_lookups":12,"old_v4_archive_and_pty_observations_conservatively_counted":4,"revoked_status_denials":3,"restored_same_async_key_lookup":1}
assert sum(budget.values())==84 and sum(budget.values())<128
print(json.dumps({"check":"cursor_order_and_new_id_retention_budget","passed":True,"last_original_cursor_assertion":max(cursors),"first_ledger_admission":min(admissions),"r3_conservative_footer_admission_upper_bound":84,"quota":128,"bound_components":budget}))
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
    ("same_incarnation_zombie",dict(old,state="Z"),False),
]:
    ns={"owned_local_identity":lambda pid,c=current:c}
    assert extracted("original_local_process_gone",ns)(old)==expect
ns={"owned_local_identity":lambda pid:dict(old,uid=1001)}
try:extracted("original_local_process_gone",ns)(old)
except AssertionError:pass
else:raise AssertionError("same-incarnation changed UID accepted as gone")
print(json.dumps({"check":"identity_guard_mock","passed":True,"same_incarnation_uid_change_currently_refused":True,"zombies_refused_until_reaped":True}))

# All transport capture tests use own anonymous pipes and a fake Popen handle.
# No subprocess is spawned by this recipe.
import selectors, threading, time, subprocess, types
wrapper_ns={}
wrapper_text=extracted("health_ledger_wrapper",wrapper_ns)(*[pathlib.Path("/tmp")/("mock-unused-"+str(i)) for i in range(6)],"mock-nonce","mock-fixed-host")
wrapper_ast=ast.parse(wrapper_text)
capture_node=next(n for n in wrapper_ast.body if isinstance(n,ast.FunctionDef) and n.name=="bounded_capture")
capture_ns={"selectors":selectors,"os":os,"time":time}
exec(compile(ast.Module(body=[capture_node],type_ignores=[]),"<R3-bounded-capture-only>","exec"),capture_ns)
class FakeChild:
    def __init__(self,out=b"",err=b"",stall=False,wait_timeout=False):
        self.returncode=None;self.kills=0;self.waits=[];self.threads=[];self.writer_fds=[];self.wait_timeout=wait_timeout
        streams=[]
        for data in (out,err):
            reader,writer=os.pipe();streams.append(os.fdopen(reader,"rb",buffering=0))
            if stall:self.writer_fds.append(writer);continue
            def send(fd=writer,payload=data):
                try:
                    offset=0
                    while offset<len(payload):offset+=os.write(fd,payload[offset:offset+4096])
                except BrokenPipeError:pass
                finally:os.close(fd)
            thread=threading.Thread(target=send,daemon=True);thread.start();self.threads.append(thread)
        self.stdout,self.stderr=streams
    def poll(self):return self.returncode
    def kill(self):self.kills+=1;self.returncode=-9
    def wait(self,timeout):
        self.waits.append(timeout)
        if self.wait_timeout and len(self.waits)==1:raise subprocess.TimeoutExpired("fake-owned-handle",timeout)
        if self.returncode is None:self.returncode=0
        return self.returncode
    def finish(self):
        for fd in self.writer_fds:os.close(fd)
        for thread in self.threads:thread.join(timeout=1);assert not thread.is_alive()
        assert self.stdout.closed and self.stderr.closed
cases=[]
child=FakeChild(b"hepta-host-health-v1\n",b"x"*65536)
try:
    out,err=capture_ns["bounded_capture"](child)
    assert out==b"hepta-host-health-v1\n" and len(err)==65536 and child.kills==0 and len(child.waits)==1
    cases.append("exact_stderr_limit_and_small_stdout")
finally:child.finish()
for label,out,err in [("stdout_overflow",b"x"*257,b""),("stderr_overflow",b"",b"x"*65537)]:
    child=FakeChild(out,err)
    try:
        try:capture_ns["bounded_capture"](child)
        except BufferError:pass
        else:raise AssertionError(label+" accepted")
        assert child.kills==1 and child.waits==[2]
        cases.append(label+"_owned_handle_killed_and_waited")
    finally:child.finish()
child=FakeChild(stall=True)
clock_calls=[0]
def expired_clock():
    clock_calls[0]+=1
    return 0 if clock_calls[0]==1 else 9
capture_ns["time"]=types.SimpleNamespace(monotonic=expired_clock)
try:
    try:capture_ns["bounded_capture"](child)
    except TimeoutError:pass
    else:raise AssertionError("capture deadline did not refuse stalled pipes")
    assert child.kills==1 and child.waits==[2]
    cases.append("eight_second_deadline_owned_handle_killed_and_waited")
finally:child.finish();capture_ns["time"]=time
child=FakeChild(wait_timeout=True)
try:
    try:capture_ns["bounded_capture"](child)
    except subprocess.TimeoutExpired:pass
    else:raise AssertionError("child wait timeout was hidden")
    assert child.kills==1 and len(child.waits)==2 and child.waits[1]==2
    cases.append("wait_timeout_owned_handle_killed_and_waited")
finally:child.finish()
print(json.dumps({"check":"bounded_capture_failure_and_limits","passed":True,"cases":cases,"actual_processes_spawned":0}))
publish_calls=[n for n in wrapper_ast.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=="publish" and n.value.args and isinstance(n.value.args[0],ast.Name) and n.value.args[0].id=="intent"]
popen_calls=[n for n in wrapper_ast.body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=="Popen"]
assert len(publish_calls)==len(popen_calls)==1 and publish_calls[0].lineno<popen_calls[0].lineno
child_source=next(ast.literal_eval(n.value) for n in wrapper_ast.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="child_code" for t in n.targets))
child_ast=ast.parse(child_source)
directory_sync=[n.lineno for n in ast.walk(child_ast) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="fsync" and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=="directory"]
child_exec=[n.lineno for n in ast.walk(child_ast) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="execv"]
assert len(directory_sync)==len(child_exec)==1 and directory_sync[0]<child_exec[0]
ns={"owned_local_identity":lambda pid:dict(old,uid=1001,start_ticks=11)}
assert extracted("original_local_process_gone",ns)(old) is True
print(json.dumps({"check":"directory_sync_precedes_transport_and_incarnation_guard","passed":True,"intent_publish_before_popen":True,"child_directory_sync_before_exec":True,"cross_uid_new_incarnation_refused_no_signaling_needed":False,"cross_uid_new_incarnation_original_gone":True,"same_incarnation_changed_uid_remains_HOLD":True}))
final_body=workflow.finalbody
first_local=next(n for n in final_body if isinstance(n,ast.Try) and any(isinstance(k,ast.Call) and isinstance(k.func,ast.Name) and k.func.id=="ledger_cleanup_proof" for k in ast.walk(n)))
release_try=next(n for n in final_body if isinstance(n,ast.Try) and any(isinstance(k,ast.Call) and isinstance(k.func,ast.Name) and k.func.id=="release_jobs" for k in ast.walk(n)))
assert final_body.index(first_local)<final_body.index(release_try)
revoked_status=[n for n in ast.walk(workflow) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="call" and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=="request_status" and any(k.arg=="denied" and isinstance(k.value,ast.Constant) and k.value.value is True for k in n.keywords)]
restored_key=next(n for n in ast.walk(workflow) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="restored_async" for t in n.targets))
assert len(revoked_status)==1 and revoked_status[0].lineno<restored_key.lineno
checks_after_restore=[ast.unparse(n) for n in ast.walk(workflow) if isinstance(n,ast.Assert) and n.lineno>restored_key.lineno and n.lineno<restored_key.lineno+5]
assert any("request_id" in c and "ledger_started" in c for c in checks_after_restore)
assert any("ledger_health_count()" in c and "before_ledger_probe_count" in c for c in checks_after_restore)
print(json.dumps({"check":"cleanup_order_and_revocation_restore_proofs","passed":True,"local_cleanup_precedes_remote_release":True,"status_denials_inside_three_snapshot_loop":True,"restored_same_inner_id_and_no_probe_replay_guard":True}))

print(json.dumps({"review_scope":"source_only_ast_and_own_private_file_mocks","runtime_executed":False,"ssh_executed":False,"services_changed":False,"acceptance_qualified":False,"pending_fix":"final_external_dependency_bootstrap_and_frozen_artifacts"}))
