"""Only actual public bytes and fixed fixture commands; no expected tool implementation."""
from pathlib import Path
import argparse,json,os,signal,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import wait_domain,wait_process,body_fixture
from capture_common import OwnedFixture,file_pin,capture_tool,check_tool
def dump(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def snapshot(owner,work,vault):
    return {"complete_metadata":owner.snapshot([os.fsencode(work).hex()]),"filesystem":body_fixture.tree_snapshot(work,vault)}
def capture(binary,output,work,name,side):
    need=lambda ok,text:(_ for _ in ()).throw(ValueError(text)) if not ok else None
    need(os.environ.get("GITHUB_ACTIONS")=="true" and side in ("original","native"),"actual application execution restricted to CI")
    binary=Path(binary).resolve(strict=True);output=Path(output).absolute();work=Path(work).absolute()
    output.mkdir(parents=True,exist_ok=False);owner=OwnedFixture(work.parent,create=True)
    plan=wait_domain.domain(name,work);dump(output/"DOMAIN.json",plan)
    selected=capture_tool(binary,output,"runtime");check_tool(selected)
    config=work.parent/"config.json"
    value={"controller_workspace_roots":[str(work)],"state_dir":str(work.parent/"admin-state"),"hosts":{"fixture":{"ssh_target":"wait.invalid","remote_state_dir":"/actual-wait-fixture-state"}}}
    config.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
    dump(output/"CONFIG.json",{"actual_bytes":file_pin(config),"value":value,"original_constructor_seam":True,"native_startup_validation_unchanged":True,"external_connection_requested":False})
    report={"schema":"hepta.runtime.actual-extract-contention-capture.v1","status":"RUNNING","side":side,"domain":name,"fixture":str(work),"binary":selected,"cases":[],"lane_seconds":180,"per_exchange_seconds":60,"original_old_domains_replayed":False}
    dump(output/"CAPTURE.json",report)
    prior=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),"no inherited lane timer")
    def expired(signum,frame):
        signal.setitimer(signal.ITIMER_REAL,0);raise TimeoutError("actual contention lane exceeds unchanged180s")
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,180)
    old_mask=os.umask(0o022);started=time.monotonic()
    try:
        for number,item in enumerate(plan["cases"]):
            check_tool(selected);work.mkdir(mode=0o700)
            case=output/("%03d"%number);case.mkdir();vault=case/"blobs";vault.mkdir()
            actions=[]
            for file in item["files"]:
                actions.extend([{"kind":"write","path_hex":os.fsencode(work/file["path"]).hex(),"data_hex":file["bytes_hex"]},{"kind":"chmod","path_hex":os.fsencode(work/file["path"]).hex(),"mode":file["mode"]}])
            setup=owner.actions(actions)
            row={"index":number,"name":item["name"],"input":item,"setup":setup,"initial":snapshot(owner,work,vault),"steps":[],"status":"RUNNING"}
            dump(case/"CASE.json",row);child=None;failed=True
            try:
                child=wait_process.Process(case/"process",binary,work,config,side)
                for index,step in enumerate(item["steps"]):
                    result={"index":index,"kind":step["kind"],"label":step["label"]};observe=False
                    kind=step["kind"]
                    if kind=="wire":
                        result["exchange"]=child.send(bytes.fromhex(step["wire_hex"]),label=step["label"],until=step["correlation_id"])
                        need(not child.eof["stdout"] and result["exchange"]["accepted_input"]["bytes"]==len(bytes.fromhex(step["wire_hex"])),"actual public connection remains live during declared request domain")
                        if step["correlation_id"] is not None:
                            need(result["exchange"]["matched_correlation"],"actual declared public barrier")
                            observe=True
                    elif kind=="control":
                        result["observation"]=child.command_control(step["operation"],step["slot"],bytes.fromhex(step["payload_hex"]),step["label"])
                        observe=step["operation"] in (1,3,4)
                    elif kind=="wait-lock":
                        result["readiness"]=child.wait_lock(step["key_hex"],step["strong"],step["label"]);observe=True
                    elif kind=="write":
                        result["action"]=owner.actions([{"kind":"write","path_hex":os.fsencode(step["path"]).hex(),"data_hex":step["bytes_hex"]}]);observe=True
                    elif kind=="control-close":
                        child.close_control();result["control_closed"]=True
                    else:raise ValueError("unknown frozen step")
                    if observe:result["snapshot"]=snapshot(owner,work,vault)
                    row["steps"].append(result);dump(case/"CASE.json",row)
                failed=False
            except BaseException as error:
                row.update(status="FAIL",failure={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()});raise
            finally:
                try:
                    if child is not None:row["process"]=child.finish(failed=failed)
                except BaseException as error:
                    failed=True;row.update(status="FAIL",finalization_failure={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()});raise
                finally:
                    row["final"]=snapshot(owner,work,vault);row["cleanup"]=owner.remove_tree(os.fsencode(work))
                    if not failed:row["status"]="ACTUAL_PROCESS_EOF_AND_RUNTIME_DROP_CAPTURED"
                    dump(case/"CASE.json",row)
            report["cases"].append({"index":number,"name":item["name"],"case":file_pin(case/"CASE.json")});dump(output/"CAPTURE.json",report)
        report["status"]="COMPLETE_ACTUAL_CONTENTION_DOMAIN_CAPTURED"
    except BaseException as error:
        report.update(status="FAIL",failure={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()});raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior);os.umask(old_mask)
        report["elapsed_seconds"]=time.monotonic()-started
        administrative=[p for p in sorted(work.parent.iterdir()) if p!=work]
        report["administrative_complete_metadata"]=owner.snapshot([os.fsencode(p).hex() for p in administrative])
        report["administrative_cleanup"]=[]
        for p in administrative:report["administrative_cleanup"].extend(owner.remove_tree(os.fsencode(p)))
        need(not list(work.parent.iterdir()),"fresh owned lane root fully accounted");work.parent.rmdir()
        dump(output/"CAPTURE.json",report)
    need(report["elapsed_seconds"]<180,"actual lane time budget")
    return report
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("binary","output","work"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--domain",required=True);p.add_argument("--side",choices=("original","native"),required=True)
    a=p.parse_args();r=capture(a.binary,a.output,a.work,a.domain,a.side)
    print(json.dumps({k:r[k] for k in ("status","side","domain","elapsed_seconds")},sort_keys=True))
