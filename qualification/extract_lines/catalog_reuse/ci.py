"""CI-only inert retained-catalog recovery; fixed per-process deadlines."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
sys.dont_write_bytecode=True
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-sha256",required=True)
    a=p.parse_args();root=Path(__file__).resolve().parent
    raw=(root/"SOURCE.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest()==a.source_sha256
    for name,pin in json.loads(raw)["files"].items():
        path=a.runtime/name;assert path.resolve(strict=True)==path
        data=path.read_bytes()
        assert pin=={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},name
    sys.path.insert(0,str(a.runtime/"authoring/public_extract"))
    from ci_source import process,dump
    a.output.mkdir(parents=True,exist_ok=False)
    status={"schema":"hepta.runtime.extract-catalog-reuse-ci.v1","status":"RUNNING",
        "source_sha256":a.source_sha256,"native_reexecutions":0,"rust_executions":0,"processes":[]}
    try:
        status["processes"].append(process(a.output,"download-complete-archive",
            [sys.executable,"-I","-B",root/"download.py","--output",a.output/"archive"],180))
        status["processes"].append(process(a.output,"complete-readonly-and-select",
            [sys.executable,"-I","-B",root/"read_reuse.py","--capture",a.output/"archive",
             "--reader-source",a.runtime/"authoring/public_extract/catalog_reader",
             "--output",a.output/"evidence"],180))
        status.update(status="RETAINED_CATALOG_READONLY_PASS")
    except BaseException as exc:
        status.update(status="FAIL",error=repr(exc));raise
    finally:dump(a.output/"CATALOG_REUSE_CI.json",status)
    print(json.dumps(status,sort_keys=True))
if __name__=="__main__":main()
