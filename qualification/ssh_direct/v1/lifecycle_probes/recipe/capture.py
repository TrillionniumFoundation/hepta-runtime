#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One new application per frozen case/side, with bounded capture and no retry."""
from pathlib import Path
import argparse,os,platform,shutil,signal,subprocess,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,need,unpack,case_bytes,inventories
from common import source_evidence
def main():
    p=argparse.ArgumentParser()
    for n in("source","native_zip","original_zip","output","stage"):p.add_argument("--"+n.replace("_","-"),type=Path,required=True)
    p.add_argument("--role",choices=("native","original"),required=True);a=p.parse_args()
    need(os.environ.get("GITHUB_ACTIONS")=="true","CI-only application capture")
    source=a.source.resolve();binding=source_evidence(source);inputs=decode((source/"INPUTS.json").read_bytes());domain=decode((source/"domain.json").read_bytes())
    need(not a.output.exists()and not a.stage.exists(),"fresh complete capture/staging");a.output.mkdir(parents=True);a.stage.mkdir()
    native=unpack(a.native_zip,a.stage/"native",inputs["native"]);original=unpack(a.original_zip,a.stage/"original",inputs["original"])
    for side in(native,original):need(pin(side/"recipe-source/SOURCE_MANIFEST.json")==inputs["source_manifest"],"actual compiled source manifest")
    nb=decode((native/"BUILD.json").read_bytes());ob=decode((original/"REFERENCE.json").read_bytes())
    need(nb["applications_executed"]==0 and ob["applications_executed"]==0,"0-app build predecessors")
    for row in inputs["generated_hia"]:need(pin(native/row["path"])=={k:row[k]for k in("bytes","sha256")},"all exact generated HIA sources")
    child=native/"fixtures/child-fixture";native_app=native/"fixtures/native-harness";original_app=original/ob["test_executable_path"]
    need(pin(child)==nb["fixtures"]["child-fixture"]and pin(native_app)==nb["fixtures"]["native-harness"]and pin(original_app)==ob["executable"],"exact compiled application bytes")
    retained=a.output/"build-inputs";retained.mkdir()
    for role,z in (("native",a.native_zip),("original",a.original_zip)):
        dst=retained/(role+".zip");shutil.copyfile(z,dst);need(pin(dst)==inputs[role]["zip"],"complete retained uploaded predecessor")
    installed=a.output/"binaries";installed.mkdir();owned={}
    for role,old in dict(child=child,native=native_app,original=original_app).items():
        dst=installed/role;shutil.copyfile(old,dst);os.chmod(dst,0o500)
        need(pin(dst)==pin(old),"exact invoked binary installation");owned[role]=dst.resolve()
    child,native_app,original_app=(owned[k]for k in("child","native","original"))
    (a.output/"HOST.json").write_bytes(canonical(dict(uname=list(platform.uname()),boot_id=Path("/proc/sys/kernel/random/boot_id").read_text(),
        clock_ticks=os.sysconf("SC_CLK_TCK"),page_size=os.sysconf("SC_PAGE_SIZE"),kernel_release=Path("/proc/sys/kernel/osrelease").read_text())))
    strace=Path(shutil.which("strace")or"");need(strace.is_file(),"existing real strace tool required")
    tool=a.output/"strace.executable";shutil.copyfile(strace.resolve(),tool);os.chmod(tool,0o500)
    tools=dict(strace=dict(original_path=str(strace),captured_file=tool.name,**pin(tool)))
    binaries={k:dict(path=str(v),**pin(v))for k,v in dict(child=child,native=native_app,original=original_app).items()}
    (a.output/"PREDECESSOR.json").write_bytes(canonical(dict(inputs=inputs,binaries=binaries,tools=tools,source=binding)))
    shutil.copytree(source,a.output/"recipe-source")
    cases={c["id"]:c for c in domain["cases"]};selected=inputs["application_scope"]["case_ids"]
    need(selected==domain["probe_case_ids"],"only frozen new initial probes")
    (a.output/"PLAN.json").write_bytes(canonical(dict(role=a.role,case_ids=selected,retries=False,application_limit_seconds=60)))
    ledger=[]
    for ident in selected:
        c=cases[ident];root=a.output/("case-"+str(ident));root.mkdir();casefile=root/"CASE.bin";casefile.write_bytes(case_bytes(c))
        actual=root/"actual";actual.mkdir();prefix=root/"kernel"
        app=[str(native_app),str(casefile.resolve()),str(actual.resolve()),str(child)]if a.role=="native"else[
            str(original_app),"--exact",ob["selector"],"--test-threads=1","--nocapture"]
        command=[str(tool.resolve()),"-ff","-ttt","-T","-xx","-yy","-v","-s","16777216","-o",str(prefix.resolve()),"--",*app]
        env=dict(PATH="/usr/bin:/bin",LC_ALL="C.UTF-8",LANG="C.UTF-8",TZ="UTC",RUST_BACKTRACE="1",
            HSS_CASE=str(casefile.resolve()),HSS_OUTPUT=str(actual.resolve()),HSS_CHILD=str(child))
        row=dict(case_id=ident,role=a.role,command=command,application_argv=app,cwd=str(root.resolve()),environment=env,
            application_timeout_seconds=60,input=pin(casefile),status="STARTING",started_ns=time.time_ns(),timed_out=False,cleanup=[])
        (root/"PROCESS.json").write_bytes(canonical(row));began=time.monotonic_ns();proc=None
        try:
            with(root/"stdout.bin").open("xb")as out,(root/"stderr.bin").open("xb")as err:
                proc=subprocess.Popen(command,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
                row.update(pid=proc.pid,pgid=proc.pid,status="RUNNING");(root/"PROCESS.json").write_bytes(canonical(row))
                try:proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    row["timed_out"]=True
                    try:os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    proc.wait();row["cleanup"].append("owned capture process group killed and waited")
                row["exit_code"]=proc.returncode
        except BaseException as error:
            row["capture_exception"]=type(error).__name__+": "+str(error)
            raise
        finally:
            if proc is not None and proc.poll()is None:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait();row["cleanup"].append("owned process cleanup after capture exception")
            row.update(elapsed_ns=time.monotonic_ns()-began,finished_ns=time.time_ns())
            row["status"]="COMPLETE"if not row["timed_out"]and row.get("exit_code")==0 else"FAILED_OR_UNKNOWN"
            row["streams"]={n:pin(root/(n+".bin"))for n in("stdout","stderr")if(root/(n+".bin")).exists()}
            row["kernel_files"]={p.name:pin(p)for p in sorted(root.glob("kernel.*"))}
            (root/"PROCESS.json").write_bytes(canonical(row));ledger.append(row)
            (a.output/"LEDGER.json").write_bytes(canonical(dict(role=a.role,applications_started=len(ledger),applications=ledger)))
        need(row["status"]=="COMPLETE","completed/UNKNOWN application preserved; no retry or remaining app launched")
        need(casefile.read_bytes()==case_bytes(c),"input changed during capture")
    need(source_evidence(source)==binding,"capture source changed")
    (a.output/"CAPTURE.json").write_bytes(canonical(dict(status="FROZEN_SSH_LIFECYCLE_CAPTURE_COMPLETE",role=a.role,cases=selected,
        applications_executed=len(ledger),completed_replayed=0,unknown_replayed=0,pure_qualification_pending=True,public_ssh=False)))
    print(canonical(dict(status="FROZEN_SSH_LIFECYCLE_CAPTURE_COMPLETE",role=a.role,cases=selected,applications=len(ledger))).decode(),end="")
if __name__=="__main__":main()
