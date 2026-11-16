"""Observe the unchanged target list handler through the actual current stdio SDK."""
from pathlib import Path
import argparse,os,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c

def run(package,binary,output):
    c.need(os.environ.get("GITHUB_ACTIONS")=="true","original SDK replay is CI-only")
    c.source_check(package)
    sys.path.insert(0,str(package/"public"))
    import public_domain as d
    observer=c.source_module("configured_native_observer_definitions",
        package/"public/capture_public_configured.py")
    transport=c.source_module("configured_original_public_transport",
        package/"graph/tests/hia_native/runtime_mcp_public_capture.py")
    fixture=c.source_module("configured_original_fixture",
        package/"source/retained/pipeline/policy_base/reference/capture.py")
    output.mkdir(parents=True,exist_ok=False)
    c.put(output/"DOMAIN.json",d.domain());binary_pin=c.pin(c.regular(binary))
    c.put(output/"binary-before.json",binary_pin)
    start=time.monotonic_ns();processes=[];observed=[];active=None
    try:
        for profile_index,flags in enumerate(d.FLAGS):
            folder=output/f"profile-{profile_index}";folder.mkdir(mode=0o700)
            owned=folder/"fixture";owned.mkdir(mode=0o700)
            previous_umask=os.umask(0o077)
            try:
                if flags:
                    marker=b"raise SystemExit('catalog configuration fixture; never dispatched')\n"
                    config=fixture.fixture(owned,flags>>1,d.HIA_CATALOG_SHA256,c.pin(marker))
                    cwd=config.parent
                else:
                    config=None;cwd=owned/"workspace";cwd.mkdir(mode=0o700)
            finally:os.umask(previous_umask)
            c.put(folder/"fixture-before.json",observer.snapshot(owned))
            active=transport.Public(folder/"process",binary,cwd,config)
            identity={"pid":active.process.pid,"parent_pid":os.getpid(),"pgid":os.getpgid(active.process.pid),
                "binary":binary_pin,"profile_index":profile_index,"flags":flags}
            c.put(folder/"process-identity.json",identity)
            initialize,initialized=d.initialization(profile_index)
            response=active.exchange(initialize)[0]
            c.put(folder/"initialize.input.bin",initialize);c.put(folder/"initialize.output.bin",response)
            c.need(active.exchange(initialized,expected=0)==[],"initialized notification output")
            c.put(folder/"initialized.input.bin",initialized)
            for case in [row for row in d.rows() if row["profile_index"]==profile_index]:
                raw=active.exchange(case["wire"])[0]
                c.put(folder/f'request-{case["sequence"]:03d}.bin',case["wire"])
                c.put(folder/f'response-{case["sequence"]:03d}.bin',raw)
                observed.append({key:value for key,value in case.items() if key!="wire"}|
                    {"input":c.pin(case["wire"]),"output":c.pin(raw)})
            receipt=active.close();active=None
            observations=c.regular(cwd/"catalog-observations.jsonl")
            c.put(folder/"handler-observations.jsonl",observations)
            c.need(len(observations.splitlines())==18,"complete actual handler observations")
            c.put(folder/"fixture-after.json",observer.snapshot(owned))
            processes.append({"profile_index":profile_index,"flags":flags,"process":receipt,"identity":identity})
        elapsed=time.monotonic_ns()-start
        c.need(len(observed)==216 and len(processes)==9 and elapsed<=180_000_000_000,
            "complete original public domain within original deadline")
        c.need(c.pin(c.regular(binary))==binary_pin,"original public executable changed")
        result={"schema":"hepta.runtime.configured-catalog-public-original.v1","status":"ACTUAL_ORIGINAL_CAPTURE",
            "package":c.pin(c.regular(package/"PACKAGE.json")),"pid":os.getpid(),"parent_pid":os.getppid(),
            "pgid":os.getpgrp(),"original_deadline_seconds":180,"binary":binary_pin,"binary_origin":str(binary),
            "observed":observed,"processes":processes,"elapsed_ns":elapsed,"actual_list_handler_calls":162,
            "sdk_unsupported_version_errors":54,"tool_body_executions":0,
            **{key:False for key in c.FALSE_FLAGS}}
        c.put(output/"result.json",result)
        print(c.encoded({key:value for key,value in result.items() if key not in ("observed","processes")}).decode())
        return result
    except BaseException as exc:
        c.put(output/"FAILURE.json",{"type":type(exc).__name__,"message":str(exc),"traceback":traceback.format_exc(),
            "completed_exchanges":len(observed),"completed_profiles":len(processes),
            "elapsed_ns":time.monotonic_ns()-start})
        raise
    finally:
        if active is not None:
            try:active.close(failed=True)
            finally:c.put(folder/"fixture-after-failure.json",observer.snapshot(owned))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("package","binary","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    run(a.package.resolve(strict=True),a.binary.resolve(strict=True),a.output.absolute())
