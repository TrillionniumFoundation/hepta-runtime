#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare the actual native exec boundary with this host's Rust Command."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
OPTIONS=None
OBSERVATIONS=[]
NATIVE_SOURCE=r"""#include <stdio.h>
extern char **environ;
extern long ssh_public_execvp(const char *,char *const *,char *const *);
int main(int argc,char **argv){
    if(argc<2)return 90;
    long error=ssh_public_execvp(argv[1],argv+1,environ);
    fprintf(stderr,"ERRNO=%ld\n",-error);
    return 111;
}
"""
RUST_SOURCE=r"""use std::os::unix::process::CommandExt;
use std::process::Command;
fn main() {
    let args:Vec<_>=std::env::args_os().collect();
    if args.len()<2 { std::process::exit(90); }
    let error=Command::new(&args[1]).args(&args[2..]).exec();
    eprintln!("ERRNO={}",error.raw_os_error().unwrap_or(0));
    std::process::exit(111);
}
"""
PROGRAM=b"#!/bin/sh\nprintf 'RUN:<%s>:<%s>:<%s>\\n' \"$1\" \"$2\" \"$MARK\"\nexit 29\n"
SHELL=b"printf 'SHELL:<%s>:<%s>:<%s>\\n' \"$1\" \"$2\" \"$MARK\"\nexit 27\n"
def pin(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def run_record(folder,label,argv,env,cwd):
    started=time.monotonic()
    with (folder/(label+".stdout")).open("xb") as out,(folder/(label+".stderr")).open("xb") as err:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,cwd=cwd,env=env,timeout=10)
    record=dict(returncode=result.returncode,elapsed_seconds=time.monotonic()-started,
                stdout=pin(folder/(label+".stdout")),stderr=pin(folder/(label+".stderr")))
    (folder/(label+".json")).write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
    return result.returncode,(folder/(label+".stdout")).read_bytes(),(folder/(label+".stderr")).read_bytes()
class ExecPathTests(unittest.TestCase):
    def compare(self,name,program,path,cwd,args=(b"alpha",b"two words"),extra=None):
        folder=OPTIONS.output/"cases"/name;folder.mkdir()
        env={b"MARK":b"actual environment",b"LC_ALL":b"C"}
        if path is not None:env[b"PATH"]=os.fsencode(path)
        if extra:env.update(extra)
        old=run_record(folder,"rust",[os.fsencode(OPTIONS.rust),program,*args],env,cwd)
        new=run_record(folder,"native",[os.fsencode(OPTIONS.native),program,*args],env,cwd)
        OBSERVATIONS.append(dict(case=name,equal=new==old,returncode=new[0],
                                 stdout_bytes=len(new[1]),stderr_bytes=len(new[2])))
        self.assertEqual(new,old,name)
        return new
    def test_path_and_environment(self):
        root=OPTIONS.output/"path";root.mkdir()
        good=root/"directory with spaces";good.mkdir()
        (good/"ssh").write_bytes(PROGRAM);(good/"ssh").chmod(0o700)
        missing=root/"missing"
        regular=root/"regular";regular.write_bytes(b"not a directory")
        denied=root/"denied";denied.mkdir()
        (denied/"ssh").write_bytes(PROGRAM);(denied/"ssh").chmod(0o600)
        (root/"ssh").write_bytes(PROGRAM);(root/"ssh").chmod(0o700)
        for label,path in (
            ("single",good),("missing-first",str(missing)+":"+str(good)),
            ("not-directory-first",str(regular)+":"+str(good)),
            ("permission-first",str(denied)+":"+str(good)),
            ("empty", ""),("empty-first",":"+str(missing)),
            ("empty-last",str(missing)+":"),
            ("long-component","x"*5000+":"+str(good)),
        ):
            self.compare(label,b"ssh",path,root)
        self.compare("unset-default",b"printf",None,root,args=(b"%s",b"default-path"))
        self.compare("raw-argument",b"ssh",good,root,args=(b"\xff",b"second"),extra={b"RAW_ENV":b"\xfe"})
        rawdir=os.fsencode(root)+b"/raw-\xff";os.mkdir(rawdir)
        fd=os.open(rawdir+b"/ssh",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)
        try:os.write(fd,PROGRAM)
        finally:os.close(fd)
        self.compare("raw-path",b"ssh",rawdir,root)
    def test_exact_errors_and_interpreter_fallback(self):
        root=OPTIONS.output/"errors";root.mkdir()
        good=root/"scripts";good.mkdir()
        (good/"ssh").write_bytes(SHELL);(good/"ssh").chmod(0o700)
        self.compare("relative-no-shebang",b"ssh",good,root)
        self.compare("absolute-no-shebang",os.fsencode(good/"ssh"),b"",root)
        missing=root/"missing"
        self.compare("no-entry",b"ssh",missing,root)
        self.compare("empty-program",b"",good,root,args=())
        self.compare("name-too-long",b"x"*300,good,root)
        self.compare("only-long-component",b"ssh",b"x"*5000,root)
        denied=root/"denied";denied.mkdir()
        (denied/"ssh").write_bytes(PROGRAM);(denied/"ssh").chmod(0o600)
        self.compare("only-denied",b"ssh",denied,root)
        self.compare("denied-and-missing",b"ssh",str(denied)+":"+str(missing),root)
        (root/"regular").write_bytes(b"not directory")
        self.compare("only-not-directory",b"ssh",root/"regular",root)

def main():
    global OPTIONS
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    OPTIONS=parser.parse_args();OPTIONS.output.mkdir(parents=True,exist_ok=False)
    (OPTIONS.output/"cases").mkdir()
    compiler=shutil.which("rustc")
    if compiler is None:
        candidate=Path.home()/".cargo/bin/rustc"
        if candidate.is_file():compiler=str(candidate)
    if compiler is None:raise RuntimeError("actual Rust compiler unavailable")
    c=OPTIONS.output/"native.c";r=OPTIONS.output/"original.rs"
    c.write_text(NATIVE_SOURCE);r.write_text(RUST_SOURCE)
    OPTIONS.native=OPTIONS.output/"native";OPTIONS.rust=OPTIONS.output/"original"
    env=dict(os.environ)
    for key in list(env):
        if key.startswith("PYTHON"):env.pop(key)
    toolchain=subprocess.run([compiler,"-vV"],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
    (OPTIONS.output/"rustc-version.stdout").write_bytes(toolchain.stdout)
    run_record(OPTIONS.output,"compile-native",["/usr/bin/cc","-O2","-no-pie",str(c),str(OPTIONS.library),"-o",str(OPTIONS.native)],env,OPTIONS.output)
    run_record(OPTIONS.output,"compile-rust",[compiler,"--edition=2021","-C","opt-level=2",str(r),"-o",str(OPTIONS.rust)],env,OPTIONS.output)
    started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ExecPathTests))
    report=dict(schema="hepta.runtime.public-ssh-exec-path-tests.v1",
        status="PASS" if result.wasSuccessful() else "FAIL",tests_run=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
        expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        python_isolated=sys.flags.isolated,python_optimize=sys.flags.optimize,
        library=pin(OPTIONS.library),native=pin(OPTIONS.native),rust=pin(OPTIONS.rust),
        elapsed_seconds=time.monotonic()-started,comparisons=OBSERVATIONS,
        public_route_qualified=False)
    (OPTIONS.output/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=="__main__":
    main()
