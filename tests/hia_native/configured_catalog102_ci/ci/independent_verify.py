"""Own one independent, bounded, read-only verification process and retain every byte."""
from pathlib import Path
import argparse,os,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c

def run(package,capture,output,foreign):
    c.source_check(package)
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row=c.record_process(output/"processes","readonly",
        [sys.executable,"-I","-B",str(package/"ci/run_recipe.py"),"--phase","verify",
            "--package",str(package),"--output",str(capture),"--foreign-path",str(foreign)],package,180)
    raw=c.regular(output/"processes/readonly.stdout");proof=c.parse(raw)
    c.need(c.regular(output/"processes/readonly.stderr")==b"" and proof["before"]==proof["after"]
        and len(proof["probes"])==12 and proof["reader_writes"]==proof["native_or_rust_executions"]==0,
        "actual independent full read-only verification")
    c.need(proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"],
        "actual independent verifier process")
    destination=capture/"independent-readback";destination.mkdir()
    for path in sorted((output/"processes").iterdir()):
        c.put(destination/path.name,c.regular(path))
    c.put(destination/"ADMISSION.json",{"status":"INDEPENDENT_CONFIGURED_READONLY_PASS",
        "package":c.pin(c.regular(package/"PACKAGE.json")),"process":row,"report":c.pin(raw),
        "complete_entries":len(proof["before"]),"readonly_probes":12,"native_executions":0,
        "rust_executions":0,"explicit_retention_after_guard":True})
    print(c.encoded(c.read_json(destination/"ADMISSION.json")).decode())

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("package","capture","output","foreign-path"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.package.resolve(strict=True),a.capture.resolve(strict=True),a.output.absolute(),a.foreign_path.absolute())
