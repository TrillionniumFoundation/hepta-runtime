"""Read all frozen diagnostic source bytes and compile Python syntax only."""
from pathlib import Path
import argparse
import hashlib
import json
import stat

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--source",type=Path,required=True);p.add_argument("--sha256",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);manifest=(source/"SOURCE.json").read_bytes()
    assert hashlib.sha256(manifest).hexdigest()==a.sha256
    expected=json.loads(manifest)["files"];seen={};count=0
    for q in sorted(source.rglob("*")):
        mode=q.lstat().st_mode;assert not stat.S_ISLNK(mode)
        if stat.S_ISDIR(mode):continue
        assert stat.S_ISREG(mode)
        name=q.relative_to(source).as_posix()
        if name=="SOURCE.json":continue
        b=q.read_bytes();seen[name]={"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
        if name.endswith(".py"):compile(b,name,"exec");count+=1
    assert seen==expected
    print(json.dumps({"status":"COMPLETE_SOURCE_AND_SYNTAX_PASS","files":len(seen)+1,"python":count,"source_manifest_sha256":a.sha256,"hia_or_rust_executions":0},sort_keys=True))

if __name__=="__main__":main()
