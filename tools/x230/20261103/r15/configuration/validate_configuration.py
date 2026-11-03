#!/usr/bin/env python3
"""Validate the opt-in launcher and actual glibc precedence; no Rust workload."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path("/home/qian/hepta-runtime-optimization-20261103-r15/configuration")
WRAPPER = ROOT / "hepta-runtime-x230-glibc.sh"
BASE = {"PATH": "/usr/bin:/bin", "LANG": "C"}
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save_new(name, value):
    data=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
    with (ROOT/name).open("xb") as stream:
        stream.write(data)
    return {"path":str(ROOT/name),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def main():
    for name in ("wrapper-validation.json","loader-precedence.json"):
        if (ROOT/name).exists(): raise FileExistsError("never overwrite "+name)
    result={"schema":"hepta-r15-wrapper-validation/v1","success":False,
            "started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "wrapper_sha256":sha(WRAPPER),"policy_sha256":sha(ROOT/"allocator-policy.json"),
            "validator_sha256":sha(__file__),"rust_runtime_launched":False,"cases":[]}
    try:
        syntax=subprocess.run(["/bin/sh","-n",str(WRAPPER)],capture_output=True,text=True,env=BASE,timeout=5)
        assert syntax.returncode==0 and not syntax.stdout and not syntax.stderr
        WRAPPER.chmod(0o755)
        code=("import json,os,sys; print(json.dumps({'pid':os.getpid(),'argv':sys.argv[1:],"
              "'allocator':{k:v for k,v in os.environ.items() if k.startswith('MALLOC_') or k=='GLIBC_TUNABLES'},"
              "'sentinel':os.environ.get('PROFILE_SENTINEL')},sort_keys=True))")
        cases=[
          ("default",{},{"MALLOC_ARENA_MAX":"1"}),
          ("explicit",{"MALLOC_ARENA_MAX":"4"},{"MALLOC_ARENA_MAX":"4"}),
          ("explicit-empty",{"MALLOC_ARENA_MAX":""},{"MALLOC_ARENA_MAX":""}),
          ("explicit-invalid",{"MALLOC_ARENA_MAX":"caller-value"},{"MALLOC_ARENA_MAX":"caller-value"}),
          ("tunables-empty",{"GLIBC_TUNABLES":""},{"GLIBC_TUNABLES":"","MALLOC_ARENA_MAX":"1"}),
          ("unrelated-tunable",{"GLIBC_TUNABLES":"glibc.malloc.trim_threshold=131072"},{"GLIBC_TUNABLES":"glibc.malloc.trim_threshold=131072","MALLOC_ARENA_MAX":"1"}),
          ("tunable-arena",{"GLIBC_TUNABLES":"glibc.malloc.arena_max=2"},{"GLIBC_TUNABLES":"glibc.malloc.arena_max=2"}),
          ("tunable-empty-arena",{"GLIBC_TUNABLES":"glibc.malloc.arena_max="},{"GLIBC_TUNABLES":"glibc.malloc.arena_max="}),
          ("both-explicit",{"MALLOC_ARENA_MAX":"4","GLIBC_TUNABLES":"glibc.malloc.arena_max=1"},{"MALLOC_ARENA_MAX":"4","GLIBC_TUNABLES":"glibc.malloc.arena_max=1"}),
          ("tunable-middle",{"GLIBC_TUNABLES":"glibc.malloc.trim_threshold=131072:glibc.malloc.arena_max=4:glibc.malloc.top_pad=131072"},{"GLIBC_TUNABLES":"glibc.malloc.trim_threshold=131072:glibc.malloc.arena_max=4:glibc.malloc.top_pad=131072"}),
          ("tunable-last",{"GLIBC_TUNABLES":"glibc.malloc.top_pad=131072:glibc.malloc.arena_max=2"},{"GLIBC_TUNABLES":"glibc.malloc.top_pad=131072:glibc.malloc.arena_max=2"}),
          ("similar-key",{"GLIBC_TUNABLES":"glibc.malloc.arena_maximum=4"},{"GLIBC_TUNABLES":"glibc.malloc.arena_maximum=4","MALLOC_ARENA_MAX":"1"}),
        ]
        arguments=["mcp","space preserved","*","literal-dollar-$","literal-backtick-"+chr(96),"--runtime-config","/tmp/not-opened.json"]
        for name,extra,expected in cases:
            env={**BASE,"PROFILE_SENTINEL":"preserved",**extra}
            child=subprocess.Popen([str(WRAPPER),sys.executable,"-c",code,*arguments],
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
            out,err=child.communicate(timeout=10)
            assert child.returncode==0 and err==""
            actual=json.loads(out)
            assert out.count("\n")==1 and actual["pid"]==child.pid
            assert actual["argv"]==arguments and actual["sentinel"]=="preserved"
            # ld.so may sanitize malformed or unknown GLIBC_TUNABLES entries before
            # Python starts. Check raw preservation separately using valid entries;
            # default injection behavior is still observable in MALLOC_ARENA_MAX.
            assert actual["allocator"].get("MALLOC_ARENA_MAX")==expected.get("MALLOC_ARENA_MAX")
            if name not in ("tunable-empty-arena","similar-key"):
                assert actual["allocator"]==expected
            result["cases"].append({"name":name,"passed":True,"supplied":extra,
                                    "observed":actual["allocator"],"pid_preserved":True,
                                    "argv_preserved":True,"stdout_only_child_json":True})
        for name,args,code_expected in (
            ("missing-arguments",[],64),
            ("relative-executable",["relative"],64),
            ("missing-executable",["/nonexistent/hepta-r15-wrapper-fixture"],66)):
            p=subprocess.run([str(WRAPPER),*args],env=BASE,capture_output=True,text=True,timeout=5)
            assert p.returncode==code_expected and p.stdout=="" and p.stderr
            result["cases"].append({"name":name,"passed":True,"exit_code":p.returncode,"stdout_empty":True,"stderr":p.stderr})
        loader=Path("/lib64/ld-linux-x86-64.so.2").resolve(strict=True)
        observations=[]
        for extra,expected in (
            ({"MALLOC_ARENA_MAX":"2"},2),
            ({"MALLOC_ARENA_MAX":"1","GLIBC_TUNABLES":"glibc.malloc.arena_max=4"},4),
            ({"MALLOC_ARENA_MAX":"4","GLIBC_TUNABLES":"glibc.malloc.arena_max=1"},1)):
            p=subprocess.run([str(loader),"--list-tunables"],env={**BASE,**extra},
                             capture_output=True,text=True,timeout=5)
            assert p.returncode==0 and p.stderr==""
            lines=[line for line in p.stdout.splitlines() if line.startswith("glibc.malloc.arena_max:")]
            assert len(lines)==1
            match=re.match(r"glibc\.malloc\.arena_max:\s*(\S+)",lines[0])
            value=int(match[1],0)
            assert value==expected
            observations.append({"supplied_allocator_environment":extra,"effective_arena_max":value,
                                 "observed_line":lines[0],"stdout":p.stdout,"stderr":p.stderr,
                                 "exit_code":p.returncode,"stdout_sha256":hashlib.sha256(p.stdout.encode()).hexdigest()})
        precedence={"schema":"hepta-r15-glibc-loader-precedence/v1","success":True,
            "glibc":os.confstr("CS_GNU_LIBC_VERSION"),"loader":str(loader),
            "loader_sha256":sha(loader),"observations":observations,
            "conclusion":"On this X230 glibc, explicit glibc.malloc.arena_max supersedes MALLOC_ARENA_MAX.",
            "scope":"Three short fresh loader invocations, not runtime performance measurements."}
        result["loader_precedence"]=save_new("loader-precedence.json",precedence)
        result["success"]=True
    except BaseException as error:
        result["error"]={"type":type(error).__name__,"message":str(error)}
        raise
    finally:
        result["finished_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
        receipt=save_new("wrapper-validation.json",result)
        print(json.dumps({"validation":receipt,"success":result["success"],"cases":len(result["cases"]),
                          "loader_precedence":result.get("loader_precedence")}))

if __name__=="__main__": main()
