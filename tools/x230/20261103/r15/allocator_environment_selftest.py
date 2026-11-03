#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Local Python-child environment tests and synthetic analyzer schema checks; no benchmark."""
import argparse,copy,datetime,hashlib,json,os,socket,sys,tempfile
from pathlib import Path
from unittest import mock
import allocator_environment as allocator
import allocator_environment_audit as audit
import run_cancel_responsiveness as cancel
import run_native_observation as native
import run_isolated_tests as isolated
import analyze_cancel_responsiveness as analyze_cancel
import analyze_native_observation as analyze_native
import verify_cancel_recovery as verify_recovery
def need(value,reason):
    if not value: raise RuntimeError(reason)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def synthetic_observation(startup,environment,agent):
    return {"schema":audit.LIVE_SCHEMA,"status":"verified","pid":startup["pid"],"birth_ticks":startup["birth_ticks"],
            "phase":"after-native-initialize","requested":environment,"observed":environment,
            "environment_sha256":audit.digest(environment),"ssh_auth_sock_present":agent,
            "held_ssh_agent_preserved":agent,"source":"same-PID/start-ticks /proc/PID/environ","full_environment_retained":False}
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    report={"schema":"hepta-r15-allocator-environment-selftest/v1","success":False,
            "started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"cases":[],
            "formal_benchmarks_run":0,"rust_tests_run":0,"compilation_started":False,
            "remote_operations":0,"production_environment_changes":0,
            "synthetic_fixture_scope":"Analyzer configuration-schema acceptance only; altered in-memory copies are not measurement evidence.",
            "fixture_sha256":{}}
    try:
        original=dict(os.environ)
        with tempfile.TemporaryDirectory(prefix="hepta-r15-allocator-env-selftest-") as temporary:
            root=Path(temporary)
            stub=root/"mcp_stub"
            stub.write_text("#!/usr/bin/python3\nimport json,sys\nfor line in sys.stdin:\n message=json.loads(line)\n if 'id' in message:\n  result={'protocolVersion':'2025-03-26','serverInfo':{'name':'local-python-env-stub','version':'1'},'capabilities':{}}\n  print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}),flush=True)\n")
            stub.chmod(0o700)
            socket_path=root/"agent-fixture"
            held=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            held.bind(str(socket_path))
            try:
                pollution={"MALLOC_ARENA_MAX":"99","MALLOC_TRIM_THRESHOLD_":"123","MALLOC_CHECK_":"3",
                           "GLIBC_TUNABLES":"glibc.malloc.arena_max=99","SSH_AUTH_SOCK":str(socket_path)}
                with mock.patch.dict(os.environ,pollution):
                    dirty=dict(os.environ)
                    for index,maximum in enumerate((None,1,2,4)):
                        selected=allocator.configured(maximum)
                        clean=allocator.child_environment(dirty,selected)
                        need(allocator.allocator_values(clean)==selected,"parent allocator pollution survived")
                        need(clean["SSH_AUTH_SOCK"]==str(socket_path) and dirty==dict(os.environ),"held agent or parent changed")
                        directory=root/f"cancel-{index}"
                        directory.mkdir()
                        controller=cancel.Controller(stub,root/"unused-config",root,directory,1,allocator_values=selected)
                        try:
                            audit.validate_observation(controller.startup["allocator_environment"],selected,
                                                       controller.child.pid,controller.birth,False)
                            need(controller.startup["server_info"]["name"]=="local-python-env-stub","fake MCP response stream contaminated")
                        finally:
                            shutdown=controller.close()
                        need(shutdown["exit_code"]==0 and shutdown["unmatched"]==0 and shutdown["reader_error"] is None,"cancel stub did not close cleanly")
                        directory=root/f"native-{index}"
                        directory.mkdir()
                        controller=native.bench.Controller(stub,root/"unused-config",root/"unused-profile",directory,1,allocator_values=selected)
                        try:
                            audit.validate_observation(controller.startup["allocator_environment"],selected,
                                                       controller.child.pid,controller.birth,True)
                            need(controller.startup["server_info"]["name"]=="local-python-env-stub","native MCP response stream contaminated")
                        finally:
                            shutdown=controller.close()
                        need(shutdown["exit_code"]==0 and shutdown["unmatched_responses"]==0 and shutdown["reader_error"] is None,"native stub did not close cleanly")
                        output=root/f"isolated-{index}"
                        output.mkdir()
                        program="import json,os,time; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('MALLOC_') or k=='GLIBC_TUNABLES'}),flush=True); time.sleep(0.1)"
                        result,text=isolated.command([sys.executable,"-c",program],output,"environment",10,True,allocator_values=selected)
                        need(result["exit_code"]==0 and json.loads(text)==selected,"direct isolated child environment differs")
                        audit.validate_observation(result["allocator_observation"],selected,result["pid"],agent_required=True)
                        report["cases"].append({"case":"child-environment-"+("default" if maximum is None else str(maximum)),
                                                "passed":True,"configuration":selected,"controller_paths_checked":["cancel","native"],
                                                "isolated_direct_child_checked":True,"mcp_stdout_clean":True})
                    need(dict(os.environ)==dirty,"environment constructor modified parent")
            finally:
                held.close()
            need(dict(os.environ)==original,"temporary test pollution was not restored")
        fixtures={
          "cancel":Path("/home/qian/hepta-runtime-optimization-20261103-r14/cancel-r13-r14-01/report.json"),
          "native":Path("/home/qian/hepta-runtime-optimization-20261103-r14/native-r11-r14-01/report.json"),
          "recovery":Path("/home/qian/hepta-runtime-optimization-20261103-r12/r14-candidate-cancel-recovery-01/report.json")}
        for kind,path in fixtures.items():
            raw=path.read_bytes()
            report["fixture_sha256"][str(path)]=hashlib.sha256(raw).hexdigest()
            value=json.loads(raw)
            selected=allocator.configured(1)
            if kind in {"cancel","native"}:
                candidate=value["binary_sha256"]["B"]
                value["binary_sha256"]={"A":candidate,"B":candidate}
                value["allocator_configuration"]=allocator.run_metadata({"A":{},"B":selected},value["binary_sha256"])
                for row in value["rounds"]:
                    arm=row["arm"] if kind=="cancel" else row["version"]
                    env={} if arm=="A" else selected
                    for key in (("startup",) if kind=="cancel" else ("startup","restart_startup")):
                        row[key]["allocator_environment"]=synthetic_observation(row[key],env,kind=="native")
                if kind=="cancel":
                    result=analyze_cancel.analyze(value,"0"*64)
                else:
                    result=analyze_native.analyze(json.dumps(value).encode())
                proof=result["allocator_environment_verification"]
                need(proof["same_binary_configuration_comparison"] is True,"same binary/configuration comparison rejected")
                bad=copy.deepcopy(value)
                row=next(x for x in bad["rounds"] if x.get("arm",x.get("version"))=="B")
                row["startup"]["allocator_environment"]["observed"]={}
                rejected=False
                try:
                    if kind=="cancel": analyze_cancel.analyze(bad,"0"*64)
                    else: analyze_native.analyze(json.dumps(bad).encode())
                except ValueError:
                    rejected=True
                need(rejected,"analyzer accepted stripped candidate allocator environment")
                report["cases"].append({"case":kind+"-same-binary-analyzer","passed":True,"same_binary_accepted":True,
                                        "stripped_candidate_rejected":True,"fixture":"synthetic in-memory schema case only"})
            else:
                value["allocator_configuration"]=allocator.run_metadata({"candidate":selected},{"candidate":value["candidate_sha256"]})
                for key in ("first_startup","after_crash_startup","after_cancel_startup"):
                    value[key]["allocator_environment"]=synthetic_observation(value[key],selected,True)
                result=verify_recovery.verify(json.dumps(value).encode())
                need(result["allocator_environment_verification"]["controllers_with_live_environment"]==3,"recovery verifier missed restart environment")
                report["cases"].append({"case":"recovery-three-controller-schema","passed":True,
                                        "fixture":"synthetic in-memory schema case only"})
        report["success"]=True
    except BaseException as error:
        report["error"]={"type":type(error).__name__,"reason":str(error)[:2000]}
    report["finished_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["selftest_sha256"]=sha(__file__)
    report["environment_helper_sha256"]=allocator.source_sha256()
    with args.output.open("x") as stream: json.dump(report,stream,indent=2);stream.write("\n")
    print(json.dumps({"success":report["success"],"report":str(args.output),"sha256":sha(args.output),
                      "cases":report["cases"],"error":report.get("error")}),flush=True)
    return 0 if report["success"] else 1
if __name__=="__main__":
    raise SystemExit(main())
